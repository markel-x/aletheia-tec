"""Entrega como pase de Apple Wallet y verificación pública de su QR (ADR-0016)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import models
from ..issuance import service as issuance
from ..issuance.service import OidError
from ..organizations.keys import SignerBackend
from ..platform.config import Settings
from ..platform.crypto import DataEncryptor
from ..platform.errors import NotFound
from ..vc.jws import JwsFormatError, peek
from ..vc.sdjwt import SdJwtError, parse
from ..vc.verifier import Check, Outcome, Result, TrustPolicy, verify_presentation
from ..verification.resolvers import KeyResolver, StatusFetcher, hosted_org_public_id
from ..verification.service import dev_http_origin
from .builder import build_pkpass, pass_json
from .google import GoogleWallet, generic_object
from .signing import PassSigner

MAX_TOKEN_BYTES = 8 * 1024
_TECHNICAL = {"iss", "iat", "nbf", "exp", "vct", "status", "cnf", "_sd", "_sd_alg"}


def claim_url(settings: Settings, offer_id: bytes) -> str:
    return f"{settings.public_base}/claim/{offer_id.hex()}"


def verify_url(settings: Settings, token: str) -> str:
    # En el fragmento: el navegador no lo envía al servidor ni queda en registros.
    return f"{settings.public_base}/v#{token}"


def _offer(session: Session, offer_id: bytes, *, lock: bool = False) -> models.Issuance:
    stmt = select(models.Issuance).where(models.Issuance.offer_id == offer_id)
    if lock:
        stmt = stmt.with_for_update()
    found = session.scalar(stmt)
    if found is None:
        raise NotFound("Offer not found")
    return found


def claim_info(
    session: Session,
    settings: Settings,
    offer_id: bytes,
    signer: PassSigner | None,
    google: GoogleWallet | None = None,
) -> dict[str, Any]:
    offer = _offer(session, offer_id)
    if offer.state != "offered" or offer.offer_expires_at <= datetime.now(UTC):
        raise NotFound("Offer not found")
    org = session.get_one(models.Organization, offer.organization_id)
    profile = session.get(models.IssuerProfile, org.id)
    version = session.get_one(models.TemplateVersion, offer.template_version_id)
    template = session.get_one(models.CredentialTemplate, version.template_id)
    return {
        "issuer_name": profile.display_name if profile else org.name,
        "credential_name": template.name,
        "expires_at": offer.offer_expires_at.isoformat(),
        "offer_uri": issuance.credential_offer_uri(settings, offer_id),
        "apple_pass": signer is not None,
        "apple_pass_trusted": bool(signer and signer.trusted_by_apple),
        "google_pass": google is not None,
        "language": org.default_language,
        "attempts_left": max(0, settings.tx_code_max_attempts - offer.tx_code_attempts),
    }


@dataclass(frozen=True)
class _Redeemed:
    serial: str
    signed: issuance.SignedCredential
    organization_name: str
    issued_at: datetime
    expires_at: datetime


def _redeem(
    session: Session,
    settings: Settings,
    backend: SignerBackend,
    encryptor: DataEncryptor,
    *,
    offer_id: bytes,
    tx_code: str | None,
    delivery: str,
    now: datetime,
) -> _Redeemed:
    """Canjea la oferta con su ``tx_code`` y firma la credencial sin vinculación al titular."""
    offer = _offer(session, offer_id, lock=True)
    issuance.check_offer_code(session, settings, offer, tx_code, now)
    already = session.scalar(
        select(models.Oid4vciAccessToken.token_hash).where(
            models.Oid4vciAccessToken.issuance_id == offer.id
        )
    )
    if already is not None:  # un wallet OID4VCI ya canjeó el código: no se entrega dos veces
        raise OidError("invalid_grant", "offer already redeemed by a wallet")
    signed = issuance.sign_and_close(
        session,
        settings,
        backend,
        encryptor,
        issuance=offer,
        holder_jwk=None,
        delivery=delivery,
        now=now,
    )
    if offer.issued_at is None or offer.expires_at is None:  # sign_and_close los fija
        raise OidError("credential_request_denied", "issuance incomplete", 500)
    profile = session.get(models.IssuerProfile, signed.organization.id)
    return _Redeemed(
        serial=offer.public_id,
        signed=signed,
        organization_name=profile.display_name if profile else signed.organization.name,
        issued_at=offer.issued_at,
        expires_at=offer.expires_at,
    )


def redeem_for_pass(
    session: Session,
    settings: Settings,
    backend: SignerBackend,
    encryptor: DataEncryptor,
    signer: PassSigner,
    *,
    offer_id: bytes,
    tx_code: str | None,
    now: datetime | None = None,
) -> tuple[bytes, str]:
    """Canjea la oferta con su ``tx_code`` y devuelve ``(pkpass, número de serie)``."""
    r = _redeem(
        session,
        settings,
        backend,
        encryptor,
        offer_id=offer_id,
        tx_code=tx_code,
        delivery="apple_pass",
        now=now or datetime.now(UTC),
    )
    document = pass_json(
        pass_type_identifier=settings.pass_type_identifier,
        team_identifier=settings.pass_team_identifier,
        serial_number=r.serial,
        organization_name=r.organization_name,
        credential_name=r.signed.template.name,
        claims=r.signed.claims,
        issued_at=r.issued_at,
        expires_at=r.expires_at,
        verify_url=verify_url(settings, r.signed.serialized),
    )
    return build_pkpass(document, signer), r.serial


def redeem_for_google_pass(
    session: Session,
    settings: Settings,
    backend: SignerBackend,
    encryptor: DataEncryptor,
    wallet: GoogleWallet,
    *,
    offer_id: bytes,
    tx_code: str | None,
    now: datetime | None = None,
) -> str:
    """Canjea la oferta, publica el pase en Google Wallet y devuelve el enlace para guardarlo.

    La llamada a Google ocurre dentro de la transacción: si falla, la emisión no se confirma
    y la oferta sigue disponible (el intento de código sí queda contado)."""
    r = _redeem(
        session,
        settings,
        backend,
        encryptor,
        offer_id=offer_id,
        tx_code=tx_code,
        delivery="google_pass",
        now=now or datetime.now(UTC),
    )
    document = generic_object(
        wallet,
        serial_number=r.serial,
        organization_name=r.organization_name,
        credential_name=r.signed.template.name,
        claims=r.signed.claims,
        issued_at=r.issued_at,
        expires_at=r.expires_at,
        verify_url=verify_url(settings, r.signed.serialized),
        logo_url=f"{settings.public_base}/wallet/logo.png",
    )
    return wallet.publish(document)


# ---------------------------------------------------------------------------
# Verificación pública del QR del pase
# ---------------------------------------------------------------------------
def verify_pass_token(
    session: Session, settings: Settings, backend: SignerBackend, token: str
) -> dict[str, Any]:
    if not token or len(token.encode()) > MAX_TOKEN_BYTES:
        return _invalid("malformed", "token ausente o demasiado grande")
    try:
        payload = peek(parse(token).issuer_jwt).payload
    except (SdJwtError, JwsFormatError, ValueError):
        return _invalid("malformed", "no es una credencial SD-JWT VC")
    if parse(token).kb_jwt is not None or "cnf" in payload:
        # Una credencial vinculada a un titular sólo vale presentada con su prueba de posesión.
        return _invalid("holder_bound_credential", "debe presentarse desde el wallet del titular")
    iss = payload.get("iss")
    org: models.Organization | None = None
    org_public_id = hosted_org_public_id(settings, iss) if isinstance(iss, str) else None
    if org_public_id is not None:
        org = session.scalar(
            select(models.Organization)
            .where(models.Organization.public_id == org_public_id)
            .where(models.Organization.status == "active")
        )
    # Sólo emisores alojados en esta instancia: la página la publica Aletheia.
    trusted = frozenset({iss}) if org is not None and isinstance(iss, str) else frozenset()
    report = verify_presentation(
        token,
        policy=TrustPolicy(
            trusted_issuers=trusted,
            require_holder_binding=False,
            require_status=True,
            dev_http_origin=dev_http_origin(settings),
        ),
        key_resolver=KeyResolver(session, settings),
        status_fetcher=StatusFetcher(session, settings, backend),
        now=int(time.time()),
        context=None,
    )
    profile = session.get(models.IssuerProfile, org.id) if org is not None else None
    credential_name = None
    vct = report.vct or ""
    if org is not None and "/types/" in vct:
        template = session.scalar(
            select(models.CredentialTemplate)
            .where(models.CredentialTemplate.organization_id == org.id)
            .where(models.CredentialTemplate.slug == vct.rsplit("/types/", 1)[1])
        )
        credential_name = template.name if template else None
    claims = {k: v for k, v in (report.disclosed_claims or {}).items() if k not in _TECHNICAL}
    return {
        "result": report.result.value,
        "reason": report.reason,
        "checks": [c.as_dict() for c in report.checks],
        "issuer": report.issuer,
        "issuer_name": (profile.display_name if profile else None),
        "credential_name": credential_name,
        "claims": claims if report.result is Result.VALID else None,
        "issued_at": payload.get("iat"),
        "expires_at": payload.get("exp"),
        "checked_at": int(time.time()),
        "language": org.default_language if org is not None else None,
    }


def _invalid(code: str, detail: str) -> dict[str, Any]:
    return {
        "result": Result.INVALID.value,
        "reason": code,
        "checks": [Check("format", Outcome.FAIL, code, detail).as_dict()],
        "issuer": None,
        "issuer_name": None,
        "credential_name": None,
        "claims": None,
        "issued_at": None,
        "expires_at": None,
        "checked_at": int(time.time()),
        "language": None,
    }
