"""Políticas de confianza, solicitudes de presentación y verificación (doc 02 §3.2, ADR-0007)."""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, select, update
from sqlalchemy.orm import Session

from .. import audit
from ..authz.service import Principal
from ..db import models
from ..organizations.keys import SignerBackend
from ..platform import ids
from ..platform.config import Settings
from ..platform.db import rls_bypass
from ..platform.errors import AppError, Conflict, NotFound
from ..usage import service as usage
from ..vc.jws import JwsFormatError, peek
from ..vc.sdjwt import SdJwtError, parse
from ..vc.verifier import PresentationContext, TrustPolicy, VerificationReport, verify_presentation
from .resolvers import KeyResolver, StatusFetcher, hosted_org_public_id

PRESENTATION_REQUEST_TTL = timedelta(minutes=10)
MAX_PRESENTATION_BYTES = 64 * 1024


class RequestExpired(AppError):
    status_code = 409
    code = "presentation_request_expired"


# ---------------------------------------------------------------------------
# Políticas de confianza
# ---------------------------------------------------------------------------
def create_policy(
    session: Session, principal: Principal, data: dict[str, Any]
) -> models.TrustPolicy:
    exists = session.scalar(
        select(models.TrustPolicy)
        .where(models.TrustPolicy.organization_id == principal.organization_id)
        .where(models.TrustPolicy.name == data["name"])
    )
    if exists is not None:
        raise Conflict("A policy with that name already exists")
    policy = models.TrustPolicy(id=ids.uuid7(), organization_id=principal.organization_id, **data)
    session.add(policy)
    session.flush()
    audit.record(
        session,
        organization_id=principal.organization_id,
        actor=principal.audit_actor,
        action="trust_policy.created",
        target_type="trust_policy",
        target_id=policy.id,
    )
    return policy


def list_policies(session: Session, principal: Principal) -> list[models.TrustPolicy]:
    return list(
        session.scalars(
            select(models.TrustPolicy)
            .where(models.TrustPolicy.organization_id == principal.organization_id)
            .order_by(models.TrustPolicy.created_at)
        ).all()
    )


def get_policy(session: Session, principal: Principal, policy_id: uuid.UUID) -> models.TrustPolicy:
    policy = session.get(models.TrustPolicy, policy_id)
    if policy is None or policy.organization_id != principal.organization_id:
        raise NotFound("Trust policy not found")
    return policy


def list_trusted_issuers(
    session: Session, policy: models.TrustPolicy
) -> list[models.TrustedIssuer]:
    return list(
        session.scalars(
            select(models.TrustedIssuer)
            .where(models.TrustedIssuer.trust_policy_id == policy.id)
            .order_by(models.TrustedIssuer.created_at)
        ).all()
    )


def add_trusted_issuer(
    session: Session,
    principal: Principal,
    settings: Settings,
    policy_id: uuid.UUID,
    *,
    issuer: str,
    note: str | None,
) -> models.TrustedIssuer:
    policy = get_policy(session, principal, policy_id)
    issuer = issuer.rstrip("/")
    if not issuer.startswith("https://") and hosted_org_public_id(settings, issuer) is None:
        raise AppError("issuer must be an https URL or a hosted issuer")
    if any(t.issuer == issuer for t in list_trusted_issuers(session, policy)):
        raise Conflict("Issuer already trusted by this policy")
    hosted_org_id = None
    org_public_id = hosted_org_public_id(settings, issuer)
    if org_public_id is not None:
        with rls_bypass(session):  # el public_id de un emisor alojado es público
            hosted_org_id = session.scalar(
                select(models.Organization.id).where(models.Organization.public_id == org_public_id)
            )
        if hosted_org_id is None:
            raise NotFound("Hosted issuer not found")
    trusted = models.TrustedIssuer(
        id=ids.uuid7(),
        organization_id=principal.organization_id,
        trust_policy_id=policy.id,
        issuer=issuer,
        hosted_org_id=hosted_org_id,
        note=note,
    )
    session.add(trusted)
    session.flush()
    audit.record(
        session,
        organization_id=principal.organization_id,
        actor=principal.audit_actor,
        action="trusted_issuer.added",
        target_type="trust_policy",
        target_id=policy.id,
        metadata={"issuer": issuer},
    )
    return trusted


def remove_trusted_issuer(
    session: Session, principal: Principal, policy_id: uuid.UUID, trusted_id: uuid.UUID
) -> None:
    policy = get_policy(session, principal, policy_id)
    trusted = session.get(models.TrustedIssuer, trusted_id)
    if trusted is None or trusted.trust_policy_id != policy.id:
        raise NotFound("Trusted issuer not found")
    session.delete(trusted)
    audit.record(
        session,
        organization_id=principal.organization_id,
        actor=principal.audit_actor,
        action="trusted_issuer.removed",
        target_type="trust_policy",
        target_id=policy.id,
        metadata={"issuer": trusted.issuer},
    )


def dev_http_origin(settings: Settings) -> str | None:
    """Origen propio con http aceptado sólo fuera de entornos desplegados."""
    if settings.env.is_deployed or not settings.public_base.startswith("http://"):
        return None
    return settings.public_base


def core_policy(
    session: Session, policy: models.TrustPolicy, settings: Settings | None = None
) -> TrustPolicy:
    return TrustPolicy(
        trusted_issuers=frozenset(t.issuer for t in list_trusted_issuers(session, policy)),
        accepted_vcts=frozenset(policy.accepted_vcts) if policy.accepted_vcts else None,
        required_claims=frozenset(policy.required_claims),
        require_holder_binding=policy.require_holder_binding,
        require_status=policy.require_status,
        max_status_age_seconds=policy.max_status_age_seconds,
        clock_skew_seconds=policy.clock_skew_seconds,
        max_kb_age_seconds=policy.max_kb_age_seconds,
        dev_http_origin=dev_http_origin(settings) if settings is not None else None,
    )


# ---------------------------------------------------------------------------
# Solicitudes de presentación
# ---------------------------------------------------------------------------
def verifier_aud(settings: Settings, org_public_id: str) -> str:
    return f"{settings.public_base}/verifiers/{org_public_id}"


def create_presentation_request(
    session: Session,
    principal: Principal,
    settings: Settings,
    policy_id: uuid.UUID,
    now: datetime | None = None,
) -> tuple[models.PresentationRequest, str]:
    now = now or datetime.now(UTC)
    policy = get_policy(session, principal, policy_id)
    org = session.get_one(models.Organization, principal.organization_id)
    nonce = ids.new_secret()
    request = models.PresentationRequest(
        id=ids.uuid7(),
        organization_id=principal.organization_id,
        trust_policy_id=policy.id,
        nonce_hash=ids.sha256(nonce),
        aud=verifier_aud(settings, org.public_id),
        expires_at=now + PRESENTATION_REQUEST_TTL,
        created_at=now,  # mismo reloj que expires_at (now() de PostgreSQL = inicio de transacción)
    )
    session.add(request)
    session.flush()
    return request, nonce


def _consume_request(session: Session, request_id: uuid.UUID, now: datetime) -> bool:
    result = session.execute(
        update(models.PresentationRequest)
        .where(models.PresentationRequest.id == request_id)
        .where(models.PresentationRequest.consumed_at.is_(None))
        .where(models.PresentationRequest.expires_at > now)
        .values(consumed_at=now)
    )
    return bool(cast(CursorResult[Any], result).rowcount)


def _kb_nonce(presentation: str) -> str | None:
    """Nonce del KB-JWT **sin verificar** (sólo para localizar la solicitud)."""
    try:
        parsed = parse(presentation)
        if parsed.kb_jwt is None:
            return None
        nonce = peek(parsed.kb_jwt).payload.get("nonce")
    except (SdJwtError, JwsFormatError, ValueError):
        return None
    return nonce if isinstance(nonce, str) else None


# ---------------------------------------------------------------------------
# Verificación
# ---------------------------------------------------------------------------
def request_context(
    session: Session,
    request: models.PresentationRequest,
    presentation: str,
    now: datetime,
    *,
    expected_aud: str | None = None,
) -> PresentationContext:
    """Contexto de una solicitud (``aud`` + nonce de un uso) para el verificador del núcleo.

    Sólo se guarda el hash del nonce: se toma el que trae el KB-JWT y, si coincide con el
    hash, se usa como valor esperado (la firma del KB-JWT lo autentica después)."""
    presented = _kb_nonce(presentation)
    expected = presented if presented and ids.sha256(presented) == request.nonce_hash else ""
    request_id = request.id

    def consume(nonce: str) -> bool:  # el nonce ya está fijado por la solicitud
        return _consume_request(session, request_id, now)

    return PresentationContext(expected_aud or request.aud, expected, consume)


def run_verification(
    session: Session,
    settings: Settings,
    backend: SignerBackend,
    *,
    organization_id: uuid.UUID,
    policy: models.TrustPolicy,
    presentation: str,
    context: PresentationContext | None,
    request: models.PresentationRequest | None,
    api_client_id: uuid.UUID | None,
) -> tuple[VerificationReport, models.VerificationRecord]:
    if len(presentation.encode()) > MAX_PRESENTATION_BYTES:
        raise AppError("presentation too large")
    report = verify_presentation(
        presentation,
        policy=core_policy(session, policy, settings),
        key_resolver=KeyResolver(session, settings),
        status_fetcher=StatusFetcher(session, settings, backend),
        now=int(time.time()),
        context=context,
    )

    credential_ref: uuid.UUID | None = None
    if report.status_reference is not None:
        prefix = f"{settings.public_base}/status-lists/"
        if report.status_reference.uri.startswith(prefix):
            # Sólo credenciales de la propia organización: filtro explícito, no sólo RLS
            # (las rutas públicas de OID4VP operan con acceso de sistema).
            credential_ref = session.scalar(
                select(models.Issuance.id)
                .join(models.StatusList, models.StatusList.id == models.Issuance.status_list_id)
                .where(models.StatusList.public_id == report.status_reference.uri[len(prefix) :])
                .where(models.Issuance.status_idx == report.status_reference.idx)
                .where(models.Issuance.organization_id == organization_id)
            )
    record = models.VerificationRecord(
        id=ids.uuid7(),
        organization_id=organization_id,
        presentation_request_id=request.id if request is not None else None,
        result=report.result.value,
        checks=[c.as_dict() for c in report.checks],  # códigos, nunca valores de claims
        issuer=report.issuer,
        vct=report.vct,
        credential_ref=credential_ref,
    )
    session.add(record)
    usage.record(session, organization_id, "verification.performed", api_client_id=api_client_id)
    return report, record


def verify(
    session: Session,
    principal: Principal,
    settings: Settings,
    backend: SignerBackend,
    *,
    presentation: str,
    presentation_request_id: uuid.UUID | None,
    policy_id: uuid.UUID | None,
    now: datetime | None = None,
) -> tuple[VerificationReport, models.VerificationRecord]:
    now = now or datetime.now(UTC)
    context: PresentationContext | None = None
    request: models.PresentationRequest | None = None
    if presentation_request_id is not None:
        request = session.get(models.PresentationRequest, presentation_request_id)
        if request is None or request.organization_id != principal.organization_id:
            raise NotFound("Presentation request not found")
        if request.expires_at <= now:
            raise RequestExpired("Presentation request has expired")
        policy = get_policy(session, principal, request.trust_policy_id)
        context = request_context(session, request, presentation, now)
    elif policy_id is not None:
        policy = get_policy(session, principal, policy_id)
    else:
        raise AppError("presentation_request_id or policy_id is required")
    return run_verification(
        session,
        settings,
        backend,
        organization_id=principal.organization_id,
        policy=policy,
        presentation=presentation,
        context=context,
        request=request,
        api_client_id=principal.actor_id if principal.actor_type == "api_client" else None,
    )


def list_records(
    session: Session, principal: Principal, *, limit: int
) -> list[models.VerificationRecord]:
    return list(
        session.scalars(
            select(models.VerificationRecord)
            .where(models.VerificationRecord.organization_id == principal.organization_id)
            .order_by(models.VerificationRecord.created_at.desc())
            .limit(limit)
        ).all()
    )
