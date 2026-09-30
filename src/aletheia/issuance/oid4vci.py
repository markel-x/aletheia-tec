"""Endpoints OID4VCI 1.0 (flujo pre-autorizado) y metadatos del emisor.

Los errores siguen el formato OAuth (``{"error": ..., "error_description": ...}``)
porque los consumen wallets, no integradores de la API ``/v1``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Form, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..api.deps import BackendDep, EncryptorDep, SessionDep
from ..api.routing import TransactionalRoute
from ..authz.service import network_prefix
from ..db import models
from ..organizations.service import issuer_url, published_jwks
from ..platform import ratelimit
from ..platform.config import Settings
from ..platform.errors import NotFound
from ..vc import OID4VCI_PROOF_TYP
from ..vc.jws import JwsFormatError, JwsSignatureError, peek, verify_compact
from . import service, templates
from .service import OidError

router = APIRouter(route_class=TransactionalRoute, tags=["oid4vci"])

PRE_AUTHORIZED_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
PROOF_MAX_AGE = 300
TOKEN_RATE_LIMIT = 60
TOKEN_RATE_WINDOW = timedelta(minutes=15)
NO_STORE = {"Cache-Control": "no-store"}


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def _oid_error(exc: OidError) -> JSONResponse:
    return JSONResponse(
        {"error": exc.code, "error_description": exc.description},
        status_code=exc.http_status,
        headers=NO_STORE,
    )


# ---------------------------------------------------------------------------
# Metadatos
# ---------------------------------------------------------------------------
@router.get("/.well-known/openid-credential-issuer/issuers/{org_public_id}")
def credential_issuer_metadata(
    org_public_id: str, request: Request, session: SessionDep
) -> dict[str, Any]:
    settings = _settings(request)
    published_jwks(session, org_public_id)  # 404 si el emisor no existe o está deshabilitado
    organization = session.scalar(
        select(models.Organization).where(models.Organization.public_id == org_public_id)
    )
    if organization is None:
        raise NotFound("Issuer not found")
    issuer = issuer_url(settings, org_public_id)
    configurations: dict[str, Any] = {}
    for template, version in templates.published_templates(session, organization.id):
        configurations[template.slug] = {
            "format": "dc+sd-jwt",
            "vct": templates.vct_for(settings, org_public_id, template.slug),
            "scope": template.slug,
            "cryptographic_binding_methods_supported": ["jwk"],
            "credential_signing_alg_values_supported": ["ES256"],
            "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}},
            "display": version.display.get("display", [{"name": template.name}]),
            "claims": version.display.get("claims", []),
        }
    return {
        "credential_issuer": issuer,
        "authorization_servers": [issuer],
        "credential_endpoint": f"{settings.public_base}/oid4vci/credential",
        "nonce_endpoint": f"{settings.public_base}/oid4vci/nonce",
        "credential_configurations_supported": configurations,
    }


@router.get("/.well-known/oauth-authorization-server/issuers/{org_public_id}")
def authorization_server_metadata(
    org_public_id: str, request: Request, session: SessionDep
) -> dict[str, Any]:
    settings = _settings(request)
    published_jwks(session, org_public_id)
    return {
        "issuer": issuer_url(settings, org_public_id),
        "token_endpoint": f"{settings.public_base}/oid4vci/token",
        "grant_types_supported": [PRE_AUTHORIZED_GRANT],
        "token_endpoint_auth_methods_supported": ["none"],
        "pre-authorized_grant_anonymous_access_supported": True,
    }


# ---------------------------------------------------------------------------
# Oferta, token, nonce, credencial
# ---------------------------------------------------------------------------
@router.get("/oid4vci/offers/{offer_id}")
def credential_offer(offer_id: str, request: Request, session: SessionDep) -> JSONResponse:
    raw = service.offer_id_from_url(offer_id)
    if raw is None:
        raise NotFound("Offer not found")
    return JSONResponse(service.offer_document(session, _settings(request), raw), headers=NO_STORE)


@router.post("/oid4vci/token")
def token(
    request: Request,
    session: SessionDep,
    grant_type: Annotated[str, Form()],
    pre_authorized_code: Annotated[str | None, Form(alias="pre-authorized_code")] = None,
    tx_code: Annotated[str | None, Form()] = None,
) -> JSONResponse:
    try:
        # Freno adicional al bloqueo por oferta: por red de origen (ADR-0008).
        prefix = network_prefix(request.client.host if request.client else None)
        if prefix:
            try:
                ratelimit.hit(
                    session,
                    f"oid4vci:token:{prefix}",
                    limit=TOKEN_RATE_LIMIT,
                    window=TOKEN_RATE_WINDOW,
                )
            except ratelimit.RateLimited as exc:
                raise OidError("slow_down", "too many token requests", 429) from exc
        if grant_type != PRE_AUTHORIZED_GRANT:
            raise OidError(
                "unsupported_grant_type", "only the pre-authorized code grant is supported"
            )
        if not pre_authorized_code:
            raise OidError("invalid_request", "pre-authorized_code is required")
        access_token, ttl = service.redeem_pre_authorized_code(
            session, _settings(request), code=pre_authorized_code, tx_code=tx_code
        )
    except OidError as exc:
        return _oid_error(exc)
    return JSONResponse(
        {"access_token": access_token, "token_type": "Bearer", "expires_in": ttl}, headers=NO_STORE
    )


@router.post("/oid4vci/nonce")
def nonce(request: Request, session: SessionDep) -> JSONResponse:
    return JSONResponse(
        {"c_nonce": service.new_nonce(session, _settings(request))}, headers=NO_STORE
    )


class CredentialRequest(BaseModel):
    credential_configuration_id: str
    proofs: dict[str, list[str]] | None = None
    proof: dict[str, str] | None = (
        None  # forma anterior (draft 13): {"proof_type": "jwt", "jwt": …}
    )


@router.post("/oid4vci/credential")
def credential(
    body: CredentialRequest,
    request: Request,
    session: SessionDep,
    backend: BackendDep,
    encryptor: EncryptorDep,
    authorization: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    settings = _settings(request)
    now = datetime.now(UTC)
    try:
        scheme, _, bearer = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not bearer.strip():
            raise OidError("invalid_token", "missing bearer token", 401)
        access_token, issuance = service.authenticate_access_token(session, bearer.strip(), now)
        proof_jwt = _single_proof(body)
        holder_jwk = _verify_proof(session, settings, proof_jwt, now)
        serialized = service.issue_credential(
            session,
            settings,
            backend,
            encryptor,
            access_token=access_token,
            issuance=issuance,
            configuration_id=body.credential_configuration_id,
            holder_jwk=holder_jwk,
            now=now,
        )
    except OidError as exc:
        session.rollback()
        return _oid_error(exc)
    return JSONResponse({"credentials": [{"credential": serialized}]}, headers=NO_STORE)


def _single_proof(body: CredentialRequest) -> str:
    if body.proofs:
        jwts = body.proofs.get("jwt") or []
        if len(jwts) != 1:
            raise OidError("invalid_proof", "exactly one jwt proof is required")
        return jwts[0]
    if body.proof and body.proof.get("proof_type") == "jwt" and body.proof.get("jwt"):
        return body.proof["jwt"]
    raise OidError("invalid_proof", "a jwt proof is required")


def _verify_proof(
    session: Session, settings: Settings, proof: str, now: datetime
) -> dict[str, Any]:
    try:
        decoded = peek(proof)
    except JwsFormatError as exc:
        raise OidError("invalid_proof", f"malformed proof: {exc}") from exc
    header = decoded.header
    jwk = header.get("jwk")
    if not isinstance(jwk, dict) or "kid" in header:
        raise OidError("invalid_proof", "proof must carry the holder key in the jwk header")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" in jwk:
        raise OidError("invalid_proof", "holder key must be a public EC P-256 key")
    try:
        verify_compact(proof, jwk, expected_typ=OID4VCI_PROOF_TYP, require_kid=False)
    except (JwsFormatError, JwsSignatureError) as exc:
        raise OidError("invalid_proof", f"proof rejected: {exc}") from exc
    payload = decoded.payload
    iat = payload.get("iat")
    if not isinstance(iat, int) or abs(int(now.timestamp()) - iat) > PROOF_MAX_AGE:
        raise OidError("invalid_proof", "proof iat missing or too old")
    aud = payload.get("aud")
    expected_auds = {settings.public_base}
    if aud not in expected_auds and not (
        isinstance(aud, str) and aud.startswith(settings.public_base + "/issuers/")
    ):
        raise OidError("invalid_proof", "proof aud must be the credential issuer")
    nonce_value = payload.get("nonce")
    if not isinstance(nonce_value, str) or not service.consume_nonce(session, nonce_value, now):
        raise OidError("invalid_nonce", "nonce missing, unknown, expired or already used")
    return jwk
