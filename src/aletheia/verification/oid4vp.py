"""OID4VP 1.0: Aletheia como verificador para wallets estándar (ADR-0014).

Perfil implementado (flujo entre dispositivos):

- Solicitud **por valor** en ``openid4vp://?…`` (QR): ``response_type=vp_token``,
  ``response_mode=direct_post``, ``client_id=redirect_uri:<response_uri>``,
  ``nonce``, ``state``, ``dcql_query`` y ``client_metadata``. Con el prefijo
  ``redirect_uri:`` la solicitud no se firma (OID4VP 1.0 §5.9.3).
- Consulta **DCQL** con una credencial ``dc+sd-jwt``: ``vct_values`` y rutas de
  claims derivadas de la política de confianza (o indicadas al crear la sesión).
- El wallet envía ``vp_token`` (objeto JSON ``{id: [presentación]}``) y ``state``
  por ``POST`` a ``response_uri``; el KB-JWT debe tener ``aud = client_id`` y el
  ``nonce`` de la solicitud.
- El verificador (backend autenticado) consulta el resultado por id. El resultado
  con los claims divulgados se guarda **cifrado** y se borra a los 10 minutos.

Fuera de alcance: solicitudes firmadas (``x509_san_dns``/``x509_hash``, exigidas
por HAIP), ``request_uri``, respuesta cifrada (``direct_post.jwt``), flujo en el
mismo dispositivo con ``redirect_uri`` de vuelta, varias credenciales por consulta.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import urlencode

import segno
from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..api.deps import BackendDep, EncryptorDep, SessionDep, SystemSessionDep, require
from ..api.routing import TransactionalRoute
from ..authz.permissions import Permission
from ..authz.service import Principal, network_prefix
from ..db import models
from ..organizations.keys import SignerBackend
from ..platform import ids, ratelimit
from ..platform.config import Settings
from ..platform.crypto import DataEncryptor, DecryptionError, Envelope
from ..platform.errors import AppError, NotFound
from ..vc.verifier import Check, Outcome, Result, VerificationReport
from . import service

log = logging.getLogger(__name__)

CREDENTIAL_QUERY_ID = "credential"
RESULT_TTL = timedelta(minutes=10)
RESPONSE_RATE_LIMIT = 120
RESPONSE_RATE_WINDOW = timedelta(minutes=15)
MAX_VP_TOKEN_BYTES = 70 * 1024
NO_STORE = {"Cache-Control": "no-store"}


class InvalidDcql(AppError):
    status_code = 422
    code = "invalid_dcql"


def response_uri(settings: Settings) -> str:
    return f"{settings.public_base}/oid4vp/response"


def client_id(settings: Settings) -> str:
    return f"redirect_uri:{response_uri(settings)}"


def client_metadata() -> dict[str, Any]:
    return {
        "vp_formats_supported": {
            "dc+sd-jwt": {"sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"]}
        }
    }


def build_dcql(vct_values: list[str], claim_paths: list[list[str]]) -> dict[str, Any]:
    if not vct_values:
        raise InvalidDcql("At least one vct is required (policy accepted_vcts or vct_values)")
    for path in claim_paths:
        if not path or not all(isinstance(p, str) and p for p in path):
            raise InvalidDcql("Claim paths must be non-empty lists of names")
    credential: dict[str, Any] = {
        "id": CREDENTIAL_QUERY_ID,
        "format": "dc+sd-jwt",
        "meta": {"vct_values": vct_values},
    }
    if claim_paths:
        credential["claims"] = [{"path": p} for p in claim_paths]
    return {"credentials": [credential]}


# ---------------------------------------------------------------------------
# Servicio
# ---------------------------------------------------------------------------
def create_session(
    session: Session,
    principal: Principal,
    settings: Settings,
    *,
    policy_id: uuid.UUID,
    vct_values: list[str] | None,
    claim_paths: list[list[str]] | None,
    now: datetime | None = None,
) -> tuple[models.Oid4vpSession, str]:
    """Crea la sesión y devuelve también el enlace ``openid4vp://`` (se muestra una vez)."""
    now = now or datetime.now(UTC)
    policy = service.get_policy(session, principal, policy_id)
    request, nonce = service.create_presentation_request(
        session, principal, settings, policy.id, now
    )
    request.aud = client_id(settings)  # el KB-JWT de OID4VP lleva aud = client_id
    paths = claim_paths if claim_paths is not None else [[c] for c in policy.required_claims]
    dcql = build_dcql(vct_values or list(policy.accepted_vcts), paths)
    state = ids.new_secret()
    oid4vp = models.Oid4vpSession(
        id=ids.uuid7(),
        organization_id=principal.organization_id,
        presentation_request_id=request.id,
        state_hash=ids.sha256(state),
        client_id=client_id(settings),
        response_uri=response_uri(settings),
        dcql_query=dcql,
        created_at=now,
    )
    session.add(oid4vp)
    session.flush()
    params = {
        "client_id": oid4vp.client_id,
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "response_uri": oid4vp.response_uri,
        "nonce": nonce,
        "state": state,
        "dcql_query": json.dumps(dcql, separators=(",", ":")),
        "client_metadata": json.dumps(client_metadata(), separators=(",", ":")),
    }
    return oid4vp, "openid4vp://?" + urlencode(params)


def _result_context(oid4vp: models.Oid4vpSession) -> dict[str, str]:
    return {"organization_id": str(oid4vp.organization_id), "oid4vp_session_id": str(oid4vp.id)}


def _walk(claims: dict[str, Any] | None, path: list[str]) -> bool:
    node: Any = claims
    for part in path:
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    return True


def _apply_dcql(report: VerificationReport, dcql: dict[str, Any]) -> VerificationReport:
    """Además de la política: todos los claims pedidos por DCQL deben estar divulgados."""
    requested = [c["path"] for c in dcql["credentials"][0].get("claims", [])]
    missing = [p for p in requested if not _walk(report.disclosed_claims, p)]
    if report.result is not Result.VALID:
        return report
    if missing:
        report.checks.append(
            Check("dcql", Outcome.FAIL, "requested_claim_missing", ".".join(missing[0]))
        )
        report.result = Result.INVALID  # reason = primer check fallido → requested_claim_missing
        report.disclosed_claims = None
    else:
        report.checks.append(Check("dcql", Outcome.PASS, "ok"))
    return report


def handle_response(
    session: Session,
    settings: Settings,
    backend: SignerBackend,
    encryptor: DataEncryptor,
    *,
    state: str,
    vp_token: str | None,
    error: str | None,
    now: datetime | None = None,
) -> None:
    now = now or datetime.now(UTC)
    oid4vp = session.scalar(
        select(models.Oid4vpSession)
        .where(models.Oid4vpSession.state_hash == ids.sha256(state))
        .with_for_update()
    )
    if oid4vp is None or oid4vp.status != "pending":
        raise service_error("invalid_request", "unknown or already answered state")
    request = session.get_one(models.PresentationRequest, oid4vp.presentation_request_id)
    if request.expires_at <= now:
        raise service_error("invalid_request", "request expired")

    if error is not None:
        oid4vp.status = "failed"
        oid4vp.error = error[:64]
        oid4vp.completed_at = now
        return

    presentation = _single_presentation(vp_token)
    policy = session.get_one(models.TrustPolicy, request.trust_policy_id)
    context = service.request_context(session, request, presentation, now)
    report, record = service.run_verification(
        session,
        settings,
        backend,
        organization_id=oid4vp.organization_id,
        policy=policy,
        presentation=presentation,
        context=context,
        request=request,
        api_client_id=None,
    )
    report = _apply_dcql(report, oid4vp.dcql_query)
    record.result = report.result.value
    record.checks = [c.as_dict() for c in report.checks]
    session.flush()  # sin relationship(): el registro debe existir antes de referenciarlo

    result = {
        "result": report.result.value,
        "reason": report.reason,
        "checks": record.checks,
        "issuer": report.issuer,
        "vct": report.vct,
        "kid": report.kid,
        "holder_binding_verified": report.holder_binding_verified,
        "disclosed_claims": report.disclosed_claims,
        "credential_id": str(record.credential_ref) if record.credential_ref else None,
    }
    envelope = encryptor.encrypt(
        json.dumps(result, ensure_ascii=False).encode(), _result_context(oid4vp)
    )
    oid4vp.status = "completed"
    oid4vp.completed_at = now
    oid4vp.verification_record_id = record.id
    oid4vp.result_ciphertext = envelope.ciphertext
    oid4vp.result_encrypted_key = envelope.encrypted_data_key
    oid4vp.result_key_ref = envelope.key_ref


class ProtocolError(Exception):
    def __init__(self, code: str, description: str) -> None:
        super().__init__(description)
        self.code = code
        self.description = description


def service_error(code: str, description: str) -> ProtocolError:
    return ProtocolError(code, description)


def _single_presentation(vp_token: str | None) -> str:
    if not vp_token:
        raise service_error("invalid_request", "vp_token is required")
    if len(vp_token.encode()) > MAX_VP_TOKEN_BYTES:
        raise service_error("invalid_request", "vp_token too large")
    try:
        parsed = json.loads(vp_token)
    except ValueError:
        raise service_error("invalid_request", "vp_token must be a JSON object") from None
    if not isinstance(parsed, dict) or set(parsed) != {CREDENTIAL_QUERY_ID}:
        raise service_error("invalid_request", f"vp_token must answer '{CREDENTIAL_QUERY_ID}'")
    presentations = parsed[CREDENTIAL_QUERY_ID]
    if not isinstance(presentations, list) or len(presentations) != 1:
        raise service_error("invalid_request", "exactly one presentation is expected")
    if not isinstance(presentations[0], str):
        raise service_error("invalid_request", "presentation must be a string")
    return presentations[0]


def get_session(
    session: Session, principal: Principal, session_id: uuid.UUID
) -> models.Oid4vpSession:
    oid4vp = session.get(models.Oid4vpSession, session_id)
    if oid4vp is None or oid4vp.organization_id != principal.organization_id:
        raise NotFound("OID4VP session not found")
    return oid4vp


def read_result(
    oid4vp: models.Oid4vpSession, encryptor: DataEncryptor, now: datetime | None = None
) -> dict[str, Any] | None:
    now = now or datetime.now(UTC)
    if oid4vp.result_ciphertext is None or oid4vp.result_encrypted_key is None:
        return None
    if oid4vp.completed_at is None or oid4vp.completed_at + RESULT_TTL <= now:
        return None
    try:
        plaintext = encryptor.decrypt(
            Envelope(
                oid4vp.result_ciphertext, oid4vp.result_encrypted_key, oid4vp.result_key_ref or ""
            ),
            _result_context(oid4vp),
        )
    except DecryptionError:
        log.error(
            "oid4vp result could not be decrypted", extra={"oid4vp_session_id": str(oid4vp.id)}
        )
        return None
    result: dict[str, Any] = json.loads(plaintext)
    return result


# ---------------------------------------------------------------------------
# API autenticada (verificador)
# ---------------------------------------------------------------------------
router = APIRouter(route_class=TransactionalRoute, prefix="/v1", tags=["oid4vp"])
public_router = APIRouter(route_class=TransactionalRoute, tags=["oid4vp"])


class Oid4vpCreate(BaseModel):
    trust_policy_id: uuid.UUID
    vct_values: list[str] | None = Field(default=None, max_length=20)
    claims: list[list[str]] | None = Field(
        default=None,
        max_length=50,
        description="Rutas de claims a pedir; por defecto, los requeridos por la política",
    )


class Oid4vpCreated(BaseModel):
    id: uuid.UUID
    status: str
    request_uri: str = Field(description="openid4vp://… para QR o enlace (contiene nonce y state)")
    qr_svg: str
    client_id: str
    dcql_query: dict[str, Any]
    expires_at: datetime


class Oid4vpStatus(BaseModel):
    id: uuid.UUID
    status: str
    error: str | None
    expires_at: datetime
    completed_at: datetime | None
    verification_id: uuid.UUID | None
    result: dict[str, Any] | None = Field(
        description="Resultado con claims divulgados; disponible 10 min tras la respuesta"
    )


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


@router.post("/oid4vp/requests", response_model=Oid4vpCreated, status_code=status.HTTP_201_CREATED)
def create_request(
    body: Oid4vpCreate,
    principal: Annotated[Principal, Depends(require(Permission.VERIFICATIONS_CREATE))],
    session: SessionDep,
    request: Request,
) -> Oid4vpCreated:
    oid4vp, uri = create_session(
        session,
        principal,
        _settings(request),
        policy_id=body.trust_policy_id,
        vct_values=body.vct_values,
        claim_paths=body.claims,
    )
    pr = session.get_one(models.PresentationRequest, oid4vp.presentation_request_id)
    return Oid4vpCreated(
        id=oid4vp.id,
        status=oid4vp.status,
        request_uri=uri,
        qr_svg=segno.make(uri, error="l").svg_data_uri(scale=3, border=2),
        client_id=oid4vp.client_id,
        dcql_query=oid4vp.dcql_query,
        expires_at=pr.expires_at,
    )


@router.get("/oid4vp/requests/{session_id}", response_model=Oid4vpStatus)
def get_request(
    session_id: uuid.UUID,
    principal: Annotated[Principal, Depends(require(Permission.VERIFICATIONS_CREATE))],
    session: SessionDep,
    encryptor: EncryptorDep,
) -> Oid4vpStatus:
    oid4vp = get_session(session, principal, session_id)
    pr = session.get_one(models.PresentationRequest, oid4vp.presentation_request_id)
    return Oid4vpStatus(
        id=oid4vp.id,
        status=oid4vp.status,
        error=oid4vp.error,
        expires_at=pr.expires_at,
        completed_at=oid4vp.completed_at,
        verification_id=oid4vp.verification_record_id,
        result=read_result(oid4vp, encryptor),
    )


# ---------------------------------------------------------------------------
# Endpoint del wallet (direct_post)
# ---------------------------------------------------------------------------
@public_router.post("/oid4vp/response")
def wallet_response(
    request: Request,
    session: SystemSessionDep,
    backend: BackendDep,
    encryptor: EncryptorDep,
    state: Annotated[str, Form(max_length=128)],
    vp_token: Annotated[str | None, Form()] = None,
    error: Annotated[str | None, Form(max_length=64)] = None,
) -> JSONResponse:
    try:
        prefix = network_prefix(request.client.host if request.client else None)
        if prefix:
            try:
                ratelimit.hit(
                    session,
                    f"oid4vp:response:{prefix}",
                    limit=RESPONSE_RATE_LIMIT,
                    window=RESPONSE_RATE_WINDOW,
                )
            except ratelimit.RateLimited as exc:
                raise service_error("slow_down", "too many responses") from exc
        handle_response(
            session,
            _settings(request),
            backend,
            encryptor,
            state=state,
            vp_token=vp_token,
            error=error,
        )
    except ProtocolError as exc:
        session.rollback()
        return JSONResponse(
            {"error": exc.code, "error_description": exc.description},
            status_code=429 if exc.code == "slow_down" else 400,
            headers=NO_STORE,
        )
    # Flujo entre dispositivos: sin redirect_uri de vuelta.
    return JSONResponse({}, headers=NO_STORE)
