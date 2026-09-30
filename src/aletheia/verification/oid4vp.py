"""OID4VP 1.0: Aletheia como verificador para wallets estándar (ADR-0014, ADR-0015).

Flujo entre dispositivos. Tres identificadores de cliente:

- ``redirect_uri:<response_uri>``: solicitud **por valor** en ``openid4vp://?…``,
  sin firma (OID4VP 1.0 §5.9.3).
- ``x509_hash:<b64url(SHA-256(DER hoja))>`` y ``x509_san_dns:<host>``: solicitud
  **firmada** (JWT ``oauth-authz-req+jwt`` con ``x5c``) servida por referencia en
  ``request_uri``; el enlace sólo lleva ``client_id`` y ``request_uri``.

Dos modos de respuesta:

- ``direct_post``: formulario con ``vp_token`` y ``state``.
- ``direct_post.jwt``: formulario con ``response`` = JWE (``ECDH-ES`` + ``A128GCM``/
  ``A256GCM``) hacia una clave efímera por sesión publicada en
  ``client_metadata.jwks``. La sesión exige el modo con el que se creó.

La consulta es DCQL con una credencial ``dc+sd-jwt``. El KB-JWT debe llevar
``aud = client_id`` y el ``nonce`` de la solicitud. El resultado (con claims) se
guarda cifrado y se borra a los 10 minutos; ``request_object`` y la clave de
respuesta, al completar o a los 15 minutos.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from urllib.parse import urlencode, urlsplit

import segno
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import APIRouter, Depends, Form, Request, Response, status
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
from ..platform.jwe import JweError, decrypt_compact
from ..vc.encoding import EncodingError, b64url_decode
from ..vc.jws import sign_compact
from ..vc.keys import public_jwk_from_key
from ..vc.verifier import Check, Outcome, Result, VerificationReport
from . import service
from .identity import VerifierIdentity

log = logging.getLogger(__name__)

CREDENTIAL_QUERY_ID = "credential"
RESULT_TTL = timedelta(minutes=10)
RESPONSE_RATE_LIMIT = 120
RESPONSE_RATE_WINDOW = timedelta(minutes=15)
MAX_VP_TOKEN_BYTES = 70 * 1024
NO_STORE = {"Cache-Control": "no-store"}
REQUEST_OBJECT_TYP = "oauth-authz-req+jwt"
REQUEST_OBJECT_MEDIA_TYPE = "application/oauth-authz-req+jwt"
# Sin metadatos del wallet (descubrimiento estático), OID4VP 1.0 §5.8.
STATIC_WALLET_AUDIENCE = "https://self-issued.me/v2"
ENC_VALUES = ["A128GCM", "A256GCM"]

ClientIdScheme = Literal["redirect_uri", "x509_hash", "x509_san_dns"]


class InvalidDcql(AppError):
    status_code = 422
    code = "invalid_dcql"


class VerifierIdentityUnavailable(AppError):
    status_code = 422
    code = "verifier_identity_unavailable"


def response_uri(settings: Settings) -> str:
    return f"{settings.public_base}/oid4vp/response"


def request_uri(settings: Settings, ref: str) -> str:
    return f"{settings.public_base}/oid4vp/request/{ref}"


def client_id_for(
    scheme: ClientIdScheme, settings: Settings, identity: VerifierIdentity | None
) -> str:
    if scheme == "redirect_uri":
        return f"redirect_uri:{response_uri(settings)}"
    if identity is None:
        raise VerifierIdentityUnavailable("No verifier certificate is configured")
    if scheme == "x509_hash":
        return f"x509_hash:{identity.x509_hash}"
    host = urlsplit(settings.public_base).hostname or ""
    if host not in identity.dns_names():
        raise VerifierIdentityUnavailable(
            "x509_san_dns requires a DNS host covered by the certificate SAN",
            details={"host": host, "san_dns": identity.dns_names()},
        )
    return f"x509_san_dns:{host}"


def client_metadata(response_jwk: dict[str, Any] | None = None) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "vp_formats_supported": {
            "dc+sd-jwt": {"sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"]}
        }
    }
    if response_jwk is not None:
        meta["jwks"] = {"keys": [response_jwk]}
        meta["encrypted_response_enc_values_supported"] = ENC_VALUES
    return meta


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


def _key_context(oid4vp_id: uuid.UUID, organization_id: uuid.UUID) -> dict[str, str]:
    return {
        "organization_id": str(organization_id),
        "oid4vp_session_id": str(oid4vp_id),
        "purpose": "oid4vp-response-key",
    }


def _result_context(oid4vp: models.Oid4vpSession) -> dict[str, str]:
    return {"organization_id": str(oid4vp.organization_id), "oid4vp_session_id": str(oid4vp.id)}


# ---------------------------------------------------------------------------
# Creación de la sesión
# ---------------------------------------------------------------------------
def create_session(
    session: Session,
    principal: Principal,
    settings: Settings,
    encryptor: DataEncryptor,
    identity: VerifierIdentity | None,
    *,
    policy_id: uuid.UUID,
    vct_values: list[str] | None,
    claim_paths: list[list[str]] | None,
    client_id_scheme: ClientIdScheme = "redirect_uri",
    encrypt_response: bool = False,
    now: datetime | None = None,
) -> tuple[models.Oid4vpSession, str]:
    """Crea la sesión y devuelve el enlace ``openid4vp://`` (se muestra una vez)."""
    now = now or datetime.now(UTC)
    client_id = client_id_for(client_id_scheme, settings, identity)
    policy = service.get_policy(session, principal, policy_id)
    request, nonce = service.create_presentation_request(
        session, principal, settings, policy.id, now
    )
    request.aud = client_id  # el KB-JWT de OID4VP lleva aud = client_id
    paths = claim_paths if claim_paths is not None else [[c] for c in policy.required_claims]
    dcql = build_dcql(vct_values or list(policy.accepted_vcts), paths)
    state = ids.new_secret()
    oid4vp_id = ids.uuid7()
    oid4vp = models.Oid4vpSession(
        id=oid4vp_id,
        organization_id=principal.organization_id,
        presentation_request_id=request.id,
        state_hash=ids.sha256(state),
        client_id=client_id,
        response_uri=response_uri(settings),
        dcql_query=dcql,
        client_id_scheme=client_id_scheme,
        response_mode="direct_post.jwt" if encrypt_response else "direct_post",
        created_at=now,
    )

    response_jwk: dict[str, Any] | None = None
    if encrypt_response:
        key = ec.generate_private_key(ec.SECP256R1())
        kid = ids.new_secret()
        response_jwk = {
            **public_jwk_from_key(key.public_key()),
            "kid": kid,
            "use": "enc",
            "alg": "ECDH-ES",
        }
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        envelope = encryptor.encrypt(pem, _key_context(oid4vp_id, principal.organization_id))
        oid4vp.response_kid = kid
        oid4vp.response_key_ciphertext = envelope.ciphertext
        oid4vp.response_key_encrypted_key = envelope.encrypted_data_key
        oid4vp.response_key_ref = envelope.key_ref

    params: dict[str, Any] = {
        "client_id": client_id,
        "response_type": "vp_token",
        "response_mode": oid4vp.response_mode,
        "response_uri": oid4vp.response_uri,
        "nonce": nonce,
        "state": state,
        "dcql_query": dcql,
        "client_metadata": client_metadata(response_jwk),
    }
    if client_id_scheme == "redirect_uri":
        link_params = {
            k: json.dumps(v, separators=(",", ":")) if isinstance(v, dict) else v
            for k, v in params.items()
        }
        link = "openid4vp://?" + urlencode(link_params)
    else:
        if identity is None:  # client_id_for ya lo exige; se repite para el verificador de tipos
            raise VerifierIdentityUnavailable("No verifier certificate is configured")
        ref = ids.new_secret()
        header = {"alg": "ES256", "typ": REQUEST_OBJECT_TYP, "x5c": identity.x5c}
        claims = {
            **params,
            "aud": STATIC_WALLET_AUDIENCE,
            "iat": int(now.timestamp()),
            "exp": int(request.expires_at.timestamp()),
        }
        oid4vp.request_ref = ref
        oid4vp.request_object = sign_compact(header, claims, identity.signer)
        link = "openid4vp://?" + urlencode(
            {"client_id": client_id, "request_uri": request_uri(settings, ref)}
        )
    session.add(oid4vp)
    session.flush()
    return oid4vp, link


def request_object(session: Session, ref: str, now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    oid4vp = session.scalar(
        select(models.Oid4vpSession).where(models.Oid4vpSession.request_ref == ref)
    )
    if oid4vp is None or oid4vp.request_object is None or oid4vp.status != "pending":
        raise NotFound("Request not found")
    request = session.get_one(models.PresentationRequest, oid4vp.presentation_request_id)
    if request.expires_at <= now:
        raise NotFound("Request not found")
    if oid4vp.request_fetched_at is None:
        oid4vp.request_fetched_at = now
    return oid4vp.request_object


# ---------------------------------------------------------------------------
# Respuesta del wallet
# ---------------------------------------------------------------------------
class ProtocolError(Exception):
    def __init__(self, code: str, description: str) -> None:
        super().__init__(description)
        self.code = code
        self.description = description


def service_error(code: str, description: str) -> ProtocolError:
    return ProtocolError(code, description)


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


def _single_presentation(vp_token: Any) -> str:
    if vp_token is None or vp_token == "":
        raise service_error("invalid_request", "vp_token is required")
    if isinstance(vp_token, str):
        if len(vp_token.encode()) > MAX_VP_TOKEN_BYTES:
            raise service_error("invalid_request", "vp_token too large")
        try:
            vp_token = json.loads(vp_token)
        except ValueError:
            raise service_error("invalid_request", "vp_token must be a JSON object") from None
    if not isinstance(vp_token, dict) or set(vp_token) != {CREDENTIAL_QUERY_ID}:
        raise service_error("invalid_request", f"vp_token must answer '{CREDENTIAL_QUERY_ID}'")
    presentations = vp_token[CREDENTIAL_QUERY_ID]
    if not isinstance(presentations, list) or len(presentations) != 1:
        raise service_error("invalid_request", "exactly one presentation is expected")
    if not isinstance(presentations[0], str):
        raise service_error("invalid_request", "presentation must be a string")
    return presentations[0]


def _session_by_state(session: Session, state: Any) -> models.Oid4vpSession:
    if not isinstance(state, str) or not state or len(state) > 128:
        raise service_error("invalid_request", "state is required")
    oid4vp = session.scalar(
        select(models.Oid4vpSession)
        .where(models.Oid4vpSession.state_hash == ids.sha256(state))
        .with_for_update()
    )
    if oid4vp is None or oid4vp.status != "pending":
        raise service_error("invalid_request", "unknown or already answered state")
    return oid4vp


def _decrypt_response(
    session: Session, encryptor: DataEncryptor, jwe: str
) -> tuple[models.Oid4vpSession, dict[str, Any]]:
    try:
        header = json.loads(b64url_decode(jwe.split(".", 1)[0]))
    except (ValueError, EncodingError):
        raise service_error("invalid_request", "response is not a JWE") from None
    kid = header.get("kid") if isinstance(header, dict) else None
    if not isinstance(kid, str):
        raise service_error("invalid_request", "JWE kid is required")
    oid4vp = session.scalar(
        select(models.Oid4vpSession)
        .where(models.Oid4vpSession.response_kid == kid)
        .with_for_update()
    )
    if (
        oid4vp is None
        or oid4vp.status != "pending"
        or oid4vp.response_key_ciphertext is None
        or oid4vp.response_key_encrypted_key is None
    ):
        raise service_error("invalid_request", "unknown or already answered response key")
    try:
        pem = encryptor.decrypt(
            Envelope(
                oid4vp.response_key_ciphertext,
                oid4vp.response_key_encrypted_key,
                oid4vp.response_key_ref or "",
            ),
            _key_context(oid4vp.id, oid4vp.organization_id),
        )
    except DecryptionError:
        log.error("oid4vp response key unavailable", extra={"oid4vp_session_id": str(oid4vp.id)})
        raise service_error("server_error", "response key unavailable") from None
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise service_error("server_error", "response key unavailable")
    try:
        decrypted = decrypt_compact(jwe, key)
    except JweError as exc:
        raise service_error("invalid_request", f"response could not be decrypted: {exc}") from exc
    try:
        payload = json.loads(decrypted.plaintext)
    except ValueError:
        raise service_error("invalid_request", "decrypted response is not JSON") from None
    if not isinstance(payload, dict):
        raise service_error("invalid_request", "decrypted response is not an object")
    # El state del contenido cifrado debe corresponder a la misma sesión que la clave.
    if not ids.constant_time_equal(ids.sha256(str(payload.get("state", ""))), oid4vp.state_hash):
        raise service_error("invalid_request", "state does not match the encrypted response")
    return oid4vp, payload


def handle_response(
    session: Session,
    settings: Settings,
    backend: SignerBackend,
    encryptor: DataEncryptor,
    *,
    form: dict[str, str | None],
    now: datetime | None = None,
) -> None:
    now = now or datetime.now(UTC)
    if form.get("response"):
        oid4vp, payload = _decrypt_response(session, encryptor, form["response"] or "")
        vp_token: Any = payload.get("vp_token")
        error = payload.get("error")
    else:
        oid4vp = _session_by_state(session, form.get("state"))
        if oid4vp.response_mode != "direct_post":
            # Sin esto, un atacante podría eludir el cifrado pedido enviando en claro.
            raise service_error("invalid_request", "this request requires an encrypted response")
        vp_token, error = form.get("vp_token"), form.get("error")
    if oid4vp.response_mode == "direct_post.jwt" and not form.get("response"):
        raise service_error("invalid_request", "this request requires an encrypted response")

    request = session.get_one(models.PresentationRequest, oid4vp.presentation_request_id)
    if request.expires_at <= now:
        raise service_error("invalid_request", "request expired")

    if error is not None:
        _finish(oid4vp, now, status_="failed", error=str(error)[:64])
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
        "client_id_scheme": oid4vp.client_id_scheme,
        "response_mode": oid4vp.response_mode,
    }
    envelope = encryptor.encrypt(
        json.dumps(result, ensure_ascii=False).encode(), _result_context(oid4vp)
    )
    oid4vp.verification_record_id = record.id
    oid4vp.result_ciphertext = envelope.ciphertext
    oid4vp.result_encrypted_key = envelope.encrypted_data_key
    oid4vp.result_key_ref = envelope.key_ref
    _finish(oid4vp, now, status_="completed")


def _finish(
    oid4vp: models.Oid4vpSession, now: datetime, *, status_: str, error: str | None = None
) -> None:
    oid4vp.status = status_
    oid4vp.error = error
    oid4vp.completed_at = now
    # Ya no se necesitan: la solicitud firmada (lleva nonce y state) y la clave de respuesta.
    oid4vp.request_object = None
    oid4vp.response_key_ciphertext = None
    oid4vp.response_key_encrypted_key = None
    oid4vp.response_key_ref = None


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
    client_id_scheme: ClientIdScheme = Field(
        default="x509_hash",
        description=(
            "x509_hash / x509_san_dns: solicitud firmada por referencia; "
            "redirect_uri: sin firmar, por valor"
        ),
    )
    encrypt_response: bool = Field(default=True, description="direct_post.jwt (JWE ECDH-ES)")


class Oid4vpCreated(BaseModel):
    id: uuid.UUID
    status: str
    request_uri: str = Field(description="openid4vp://… para QR o enlace")
    qr_svg: str
    client_id: str
    client_id_scheme: str
    response_mode: str
    dcql_query: dict[str, Any]
    expires_at: datetime


class Oid4vpStatus(BaseModel):
    id: uuid.UUID
    status: str
    error: str | None
    client_id_scheme: str
    response_mode: str
    request_fetched: bool
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
    encryptor: EncryptorDep,
    request: Request,
) -> Oid4vpCreated:
    oid4vp, uri = create_session(
        session,
        principal,
        _settings(request),
        encryptor,
        request.app.state.verifier_identity,
        policy_id=body.trust_policy_id,
        vct_values=body.vct_values,
        claim_paths=body.claims,
        client_id_scheme=body.client_id_scheme,
        encrypt_response=body.encrypt_response,
    )
    pr = session.get_one(models.PresentationRequest, oid4vp.presentation_request_id)
    return Oid4vpCreated(
        id=oid4vp.id,
        status=oid4vp.status,
        request_uri=uri,
        qr_svg=segno.make(uri, error="l").svg_data_uri(scale=3, border=2),
        client_id=oid4vp.client_id,
        client_id_scheme=oid4vp.client_id_scheme,
        response_mode=oid4vp.response_mode,
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
        client_id_scheme=oid4vp.client_id_scheme,
        response_mode=oid4vp.response_mode,
        request_fetched=oid4vp.request_fetched_at is not None,
        expires_at=pr.expires_at,
        completed_at=oid4vp.completed_at,
        verification_id=oid4vp.verification_record_id,
        result=read_result(oid4vp, encryptor),
    )


# ---------------------------------------------------------------------------
# Endpoints del wallet
# ---------------------------------------------------------------------------
@public_router.get("/oid4vp/request/{ref}", response_class=Response)
def get_request_object(ref: str, session: SystemSessionDep) -> Response:
    return Response(
        content=request_object(session, ref),
        media_type=REQUEST_OBJECT_MEDIA_TYPE,
        headers=NO_STORE,
    )


@public_router.post("/oid4vp/response")
def wallet_response(
    request: Request,
    session: SystemSessionDep,
    backend: BackendDep,
    encryptor: EncryptorDep,
    state: Annotated[str | None, Form(max_length=128)] = None,
    vp_token: Annotated[str | None, Form()] = None,
    error: Annotated[str | None, Form(max_length=64)] = None,
    response: Annotated[str | None, Form(max_length=128 * 1024)] = None,
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
            form={"state": state, "vp_token": vp_token, "error": error, "response": response},
        )
    except ProtocolError as exc:
        session.rollback()
        code = {"slow_down": 429, "server_error": 500}.get(exc.code, 400)
        return JSONResponse(
            {"error": exc.code, "error_description": exc.description},
            status_code=code,
            headers=NO_STORE,
        )
    # Flujo entre dispositivos: sin redirect_uri de vuelta.
    return JSONResponse({}, headers=NO_STORE)
