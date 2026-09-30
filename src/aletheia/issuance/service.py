"""Ofertas, emisión y revocación (docs/02 §3.1 y §3.3, ADR-0007, ADR-0009).

Secretos de la oferta: ``offer_id`` (128 bits aleatorios) es la raíz. El
``pre-authorized_code`` se deriva de él (SHA-256 con etiqueta) y sólo se
guarda su hash; el ``tx_code`` (6 dígitos) se guarda con Argon2id y se
devuelve una única vez. Los claims se guardan cifrados hasta la emisión.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from urllib.parse import quote

from sqlalchemy import CursorResult, select, update
from sqlalchemy.orm import Session

from .. import audit
from ..authz.service import Principal, hash_password, verify_password
from ..db import models
from ..organizations.keys import SignerBackend
from ..organizations.service import active_signing_key, issuer_url
from ..platform import ids
from ..platform.config import Settings
from ..platform.crypto import DataEncryptor, DecryptionError, Envelope
from ..platform.errors import AppError, Conflict, NotFound
from ..status import service as status
from ..usage import service as usage
from ..vc.encoding import b64url_encode
from ..vc.keys import jwk_thumbprint
from ..vc.sdjwt import issue_sd_jwt_vc
from ..vc.status_list import StatusReference
from . import templates
from .schema import validate_claims

log = logging.getLogger(__name__)

TX_CODE_LENGTH = 6
IDEMPOTENCY_TTL = timedelta(hours=24)
REVOCATION_REASONS = (
    "superseded",
    "issued_in_error",
    "holder_request",
    "policy_violation",
    "key_compromise",
    "other",
)


class IdempotencyKeyReuse(Conflict):
    code = "idempotency_key_reuse"


class InvalidState(Conflict):
    code = "invalid_state"


# ---------------------------------------------------------------------------
# Secretos de la oferta
# ---------------------------------------------------------------------------
def pre_authorized_code(offer_id: bytes) -> str:
    return b64url_encode(hashlib.sha256(b"aletheia/pre-authorized_code/" + offer_id).digest())


def offer_id_from_url(value: str) -> bytes | None:
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None
    return raw if len(raw) == 16 else None


def offer_url(settings: Settings, offer_id: bytes) -> str:
    return f"{settings.public_base}/oid4vci/offers/{offer_id.hex()}"


def credential_offer_uri(settings: Settings, offer_id: bytes) -> str:
    return "openid-credential-offer://?credential_offer_uri=" + quote(
        offer_url(settings, offer_id), safe=""
    )


def _new_tx_code() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(TX_CODE_LENGTH))


def _claims_context(organization_id: uuid.UUID, issuance_id: uuid.UUID) -> dict[str, str]:
    return {"organization_id": str(organization_id), "issuance_id": str(issuance_id)}


# ---------------------------------------------------------------------------
# Idempotencia
# ---------------------------------------------------------------------------
def request_hash(body: Any) -> bytes:
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).digest()


def find_idempotent(
    session: Session, organization_id: uuid.UUID, key: str, body_hash: bytes
) -> dict[str, Any] | None:
    record = session.get(models.IdempotencyRecord, (organization_id, key))
    if record is None:
        return None
    if record.expires_at <= datetime.now(UTC):
        session.delete(record)
        session.flush()
        return None
    if not ids.constant_time_equal(record.request_hash, body_hash):
        raise IdempotencyKeyReuse("Idempotency-Key was already used with a different request")
    return record.response_body


def store_idempotent(
    session: Session,
    organization_id: uuid.UUID,
    key: str,
    body_hash: bytes,
    status_code: int,
    response: dict[str, Any],
    resource_id: uuid.UUID,
) -> None:
    session.add(
        models.IdempotencyRecord(
            organization_id=organization_id,
            key=key,
            request_hash=body_hash,
            response_status=status_code,
            response_body=response,
            resource_id=resource_id,
            expires_at=datetime.now(UTC) + IDEMPOTENCY_TTL,
        )
    )


# ---------------------------------------------------------------------------
# Ofertas
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Offer:
    issuance: models.Issuance
    tx_code: str


def create_offer(
    session: Session,
    principal: Principal,
    settings: Settings,
    encryptor: DataEncryptor,
    *,
    template_slug: str,
    claims: Any,
    holder_reference: str | None,
    validity_days: int | None,
    now: datetime | None = None,
) -> Offer:
    now = now or datetime.now(UTC)
    org = session.get_one(models.Organization, principal.organization_id)
    profile = session.get(models.IssuerProfile, org.id)
    if profile is None or not profile.enabled:
        raise AppError("Issuer profile is disabled", details=None)
    template = templates.get_template_by_slug(session, org.id, template_slug)
    version = templates.latest_published(session, template)
    validated = validate_claims(version.claims_schema, claims)
    days = validity_days or version.validity_days
    if not 1 <= days <= 3650:
        raise AppError("validity_days must be between 1 and 3650")

    offer_id = secrets.token_bytes(16)
    tx_code = _new_tx_code()
    allocation = status.allocate(session, org.id)
    issuance = models.Issuance(
        id=ids.uuid7(),
        public_id=ids.public_id("cred"),
        organization_id=org.id,
        template_version_id=version.id,
        vct=templates.vct_for(settings, org.public_id, template.slug),
        state="offered",
        holder_reference=holder_reference,
        offer_id=offer_id,
        pre_auth_code_hash=ids.sha256(pre_authorized_code(offer_id)),
        tx_code_hash=hash_password(tx_code),
        tx_code_attempts=0,
        offer_expires_at=now + timedelta(hours=profile.offer_ttl_hours),
        status_list_id=allocation.status_list.id,
        status_idx=allocation.idx,
    )
    session.add(issuance)
    session.flush()
    payload = {"claims": validated, "validity_days": days}
    envelope = encryptor.encrypt(
        json.dumps(payload, ensure_ascii=False).encode(), _claims_context(org.id, issuance.id)
    )
    session.add(
        models.IssuancePendingClaims(
            issuance_id=issuance.id,
            organization_id=org.id,
            ciphertext=envelope.ciphertext,
            encrypted_data_key=envelope.encrypted_data_key,
            key_ref=envelope.key_ref,
        )
    )
    audit.record(
        session,
        organization_id=org.id,
        actor=principal.audit_actor,
        action="credential.offered",
        target_type="issuance",
        target_id=issuance.id,
        metadata={"template": template.slug, "version": version.version},
    )
    usage.record(
        session,
        org.id,
        "credential.offered",
        api_client_id=principal.actor_id if principal.actor_type == "api_client" else None,
    )
    return Offer(issuance, tx_code)


def get_issuance(session: Session, principal: Principal, issuance_id: uuid.UUID) -> models.Issuance:
    issuance = session.get(models.Issuance, issuance_id)
    if issuance is None or issuance.organization_id != principal.organization_id:
        raise NotFound("Credential not found")
    return issuance


def list_issuances(
    session: Session,
    principal: Principal,
    *,
    state: str | None,
    holder_reference: str | None,
    limit: int,
) -> list[models.Issuance]:
    stmt = (
        select(models.Issuance)
        .where(models.Issuance.organization_id == principal.organization_id)
        .order_by(models.Issuance.created_at.desc())
        .limit(limit)
    )
    if state:
        stmt = stmt.where(models.Issuance.state == state)
    if holder_reference:
        stmt = stmt.where(models.Issuance.holder_reference == holder_reference)
    return list(session.scalars(stmt).all())


def reset_offer(
    session: Session,
    principal: Principal,
    issuance_id: uuid.UUID,
    now: datetime | None = None,
) -> Offer:
    """Nuevo ``tx_code`` y nuevo código pre-autorizado; reinicia intentos y plazo."""
    now = now or datetime.now(UTC)
    issuance = get_issuance(session, principal, issuance_id)
    if issuance.state != "offered":
        raise InvalidState("Only pending offers can be reset")
    profile = session.get_one(models.IssuerProfile, issuance.organization_id)
    # Los tokens de acceso emitidos con el código anterior dejan de valer.
    session.execute(
        update(models.Oid4vciAccessToken)
        .where(models.Oid4vciAccessToken.issuance_id == issuance.id)
        .where(models.Oid4vciAccessToken.consumed_at.is_(None))
        .values(consumed_at=now)
    )
    issuance.offer_id = secrets.token_bytes(16)
    issuance.pre_auth_code_hash = ids.sha256(pre_authorized_code(issuance.offer_id))
    tx_code = _new_tx_code()
    issuance.tx_code_hash = hash_password(tx_code)
    issuance.tx_code_attempts = 0
    issuance.offer_expires_at = now + timedelta(hours=profile.offer_ttl_hours)
    audit.record(
        session,
        organization_id=issuance.organization_id,
        actor=principal.audit_actor,
        action="credential.offer_reset",
        target_type="issuance",
        target_id=issuance.id,
    )
    return Offer(issuance, tx_code)


# ---------------------------------------------------------------------------
# Revocación
# ---------------------------------------------------------------------------
def revoke(
    session: Session,
    principal: Principal,
    issuance_id: uuid.UUID,
    *,
    reason: str,
    now: datetime | None = None,
) -> models.Issuance:
    now = now or datetime.now(UTC)
    if reason not in REVOCATION_REASONS:
        raise AppError(f"Unknown revocation reason: {reason}")
    issuance = get_issuance(session, principal, issuance_id)
    if issuance.state == "revoked":
        return issuance  # idempotente: mismo revoked_at, sin nuevo evento
    was = issuance.state
    if was == "offered":
        session.execute(
            update(models.Oid4vciAccessToken)
            .where(models.Oid4vciAccessToken.issuance_id == issuance.id)
            .values(consumed_at=now)
        )
        pending = session.get(models.IssuancePendingClaims, issuance.id)
        if pending is not None:
            session.delete(pending)
    if issuance.status_list_id is not None and issuance.status_idx is not None:
        status.mark_invalid(session, issuance.status_list_id, issuance.status_idx)
    issuance.state = "revoked"
    issuance.revoked_at = now
    issuance.revocation_reason_code = reason
    issuance.revoked_by = principal.actor_id
    audit.record(
        session,
        organization_id=issuance.organization_id,
        actor=principal.audit_actor,
        action="credential.revoked" if was == "issued" else "credential.offer_cancelled",
        target_type="issuance",
        target_id=issuance.id,
        metadata={"reason": reason, "previous_state": was},
    )
    return issuance


# ---------------------------------------------------------------------------
# OID4VCI: canje del código, nonces, emisión
# ---------------------------------------------------------------------------
class OidError(Exception):
    """Error OAuth/OID4VCI: se responde con ``{"error": code}``."""

    def __init__(self, code: str, description: str, http_status: int = 400) -> None:
        super().__init__(description)
        self.code = code
        self.description = description
        self.http_status = http_status


def offer_document(session: Session, settings: Settings, offer_id: bytes) -> dict[str, Any]:
    issuance = session.scalar(select(models.Issuance).where(models.Issuance.offer_id == offer_id))
    if issuance is None or issuance.state != "offered":
        raise NotFound("Offer not found")
    if issuance.offer_expires_at <= datetime.now(UTC):
        raise NotFound("Offer not found")
    org = session.get_one(models.Organization, issuance.organization_id)
    version = session.get_one(models.TemplateVersion, issuance.template_version_id)
    template = session.get_one(models.CredentialTemplate, version.template_id)
    return {
        "credential_issuer": issuer_url(settings, org.public_id),
        "credential_configuration_ids": [template.slug],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": pre_authorized_code(offer_id),
                "tx_code": {
                    "input_mode": "numeric",
                    "length": TX_CODE_LENGTH,
                    "description": "Código enviado por el emisor",
                },
            }
        },
    }


def redeem_pre_authorized_code(
    session: Session,
    settings: Settings,
    *,
    code: str,
    tx_code: str | None,
    now: datetime | None = None,
) -> tuple[str, int]:
    """Canjea el código por un token de acceso (un solo canje por oferta)."""
    now = now or datetime.now(UTC)
    issuance = session.scalar(
        select(models.Issuance)
        .where(models.Issuance.pre_auth_code_hash == ids.sha256(code))
        .with_for_update()
    )
    if issuance is None or issuance.state != "offered" or issuance.offer_expires_at <= now:
        raise OidError("invalid_grant", "unknown, used or expired pre-authorized code")
    if issuance.tx_code_attempts >= settings.tx_code_max_attempts:
        raise OidError("invalid_grant", "offer locked after too many attempts")
    already = session.scalar(
        select(models.Oid4vciAccessToken.token_hash).where(
            models.Oid4vciAccessToken.issuance_id == issuance.id
        )
    )
    if already is not None:
        raise OidError("invalid_grant", "pre-authorized code already used")
    if not tx_code or not verify_password(issuance.tx_code_hash, tx_code):
        issuance.tx_code_attempts += 1
        session.flush()
        session.commit()  # el intento fallido debe persistir aunque respondamos error
        raise OidError("invalid_grant", "invalid tx_code")

    token = ids.new_secret()
    ttl = settings.oid4vci_access_token_ttl_seconds
    session.add(
        models.Oid4vciAccessToken(
            token_hash=ids.sha256(token),
            issuance_id=issuance.id,
            expires_at=now + timedelta(seconds=ttl),
        )
    )
    audit.record(
        session,
        organization_id=issuance.organization_id,
        actor=audit.Actor("holder"),
        action="offer.code_redeemed",
        target_type="issuance",
        target_id=issuance.id,
    )
    return token, ttl


def new_nonce(session: Session, settings: Settings, now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    nonce = ids.new_secret()
    session.add(
        models.Oid4vciNonce(
            nonce_hash=ids.sha256(nonce),
            expires_at=now + timedelta(seconds=settings.oid4vci_nonce_ttl_seconds),
        )
    )
    return nonce


def consume_nonce(session: Session, nonce: str, now: datetime) -> bool:
    result = session.execute(
        update(models.Oid4vciNonce)
        .where(models.Oid4vciNonce.nonce_hash == ids.sha256(nonce))
        .where(models.Oid4vciNonce.consumed_at.is_(None))
        .where(models.Oid4vciNonce.expires_at > now)
        .values(consumed_at=now)
    )
    return bool(cast(CursorResult[Any], result).rowcount)


def authenticate_access_token(
    session: Session, token: str, now: datetime
) -> tuple[models.Oid4vciAccessToken, models.Issuance]:
    record = session.get(models.Oid4vciAccessToken, ids.sha256(token))
    if record is None or record.consumed_at is not None or record.expires_at <= now:
        raise OidError("invalid_token", "invalid or expired access token", 401)
    issuance = session.get_one(models.Issuance, record.issuance_id)
    if issuance.state != "offered":
        raise OidError("invalid_token", "offer no longer redeemable", 401)
    return record, issuance


def issue_credential(
    session: Session,
    settings: Settings,
    backend: SignerBackend,
    encryptor: DataEncryptor,
    *,
    access_token: models.Oid4vciAccessToken,
    issuance: models.Issuance,
    configuration_id: str,
    holder_jwk: dict[str, Any],
    now: datetime | None = None,
) -> str:
    """Firma la credencial con la clave activa y cierra la emisión en una transacción."""
    now = now or datetime.now(UTC)
    org = session.get_one(models.Organization, issuance.organization_id)
    version = session.get_one(models.TemplateVersion, issuance.template_version_id)
    template = session.get_one(models.CredentialTemplate, version.template_id)
    if configuration_id != template.slug:
        raise OidError("invalid_credential_request", "credential_configuration_id does not match")
    pending = session.get(models.IssuancePendingClaims, issuance.id)
    if pending is None:
        raise OidError("invalid_credential_request", "offer has no pending claims")
    try:
        plaintext = encryptor.decrypt(
            Envelope(pending.ciphertext, pending.encrypted_data_key, pending.key_ref),
            _claims_context(org.id, issuance.id),
        )
    except DecryptionError as exc:
        log.error("pending claims could not be decrypted", extra={"issuance_id": str(issuance.id)})
        raise OidError("credential_request_denied", "issuance unavailable", 500) from exc
    stored = json.loads(plaintext)
    claims: dict[str, Any] = stored["claims"]
    validity = timedelta(days=int(stored["validity_days"]))

    key = active_signing_key(session, org.id)
    signer = backend.load(key.key_ref, key.public_jwk)
    iat = int(now.timestamp())
    exp = int((now + validity).timestamp())
    if issuance.status_list_id is None or issuance.status_idx is None:
        raise OidError("credential_request_denied", "offer has no status index", 500)
    status_list = session.get_one(models.StatusList, issuance.status_list_id)
    payload: dict[str, Any] = {
        "iss": issuer_url(settings, org.public_id),
        "iat": iat,
        "nbf": iat,
        "exp": exp,
        "vct": issuance.vct,
        "cnf": {"jwk": {k: holder_jwk[k] for k in ("kty", "crv", "x", "y")}},
        "status": StatusReference(
            idx=issuance.status_idx, uri=status.status_list_uri(settings, status_list.public_id)
        ).to_claim(),
        **claims,
    }
    issued = issue_sd_jwt_vc(
        payload, selectively_disclosable=version.selective_disclosure, signer=signer
    )

    issuance.state = "issued"
    issuance.signing_key_id = key.id
    issuance.holder_key_thumbprint = jwk_thumbprint(payload["cnf"]["jwk"])
    issuance.issued_at = now
    issuance.expires_at = now + validity
    session.delete(pending)
    access_token.consumed_at = now
    audit.record(
        session,
        organization_id=org.id,
        actor=audit.Actor("holder"),
        action="credential.issued",
        target_type="issuance",
        target_id=issuance.id,
        metadata={"kid": key.kid, "template": template.slug, "version": version.version},
    )
    usage.record(session, org.id, "credential.issued")
    return issued.serialized
