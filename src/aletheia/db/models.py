"""Modelo ORM. Espejo de ``migrations/sql/0001_initial_schema.sql`` (docs/03).

Reglas:
- Los tipos enumerados existen en la base (``create_type=False``); aquí sólo se nombran.
- Las restricciones CHECK y los triggers viven en el DDL; el ORM no las repite.
- ``id`` lo genera la aplicación (UUID v7); ``created_at``/``updated_at`` los pone el servidor.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, CITEXT, ENUM, JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def pg_enum(name: str, *values: str) -> ENUM:
    return ENUM(*values, name=name, create_type=False)


ORGANIZATION_STATUS = pg_enum("organization_status", "active", "suspended")
USER_STATUS = pg_enum("user_status", "active", "disabled")
MEMBERSHIP_ROLE = pg_enum("membership_role", "owner", "admin", "issuer", "verifier", "auditor")
KEY_BACKEND = pg_enum("key_backend", "local_dev", "aws_kms")
KEY_STATE = pg_enum("key_state", "active", "retired", "compromised")
TEMPLATE_STATE = pg_enum("template_state", "draft", "published")
ISSUANCE_STATE = pg_enum("issuance_state", "offered", "issued", "offer_expired", "revoked")
REVOCATION_REASON = pg_enum(
    "revocation_reason",
    "superseded",
    "issued_in_error",
    "holder_request",
    "policy_violation",
    "key_compromise",
    "other",
)
STATUS_LIST_STATE = pg_enum("status_list_state", "open", "full")
VERIFICATION_RESULT = pg_enum("verification_result", "valid", "invalid", "indeterminate")
ACTOR_TYPE = pg_enum("actor_type", "user", "api_client", "system", "holder")
USAGE_KIND = pg_enum(
    "usage_kind",
    "credential.offered",
    "credential.issued",
    "verification.performed",
    "status_list.served",
)

TimestampTZ = TIMESTAMP(timezone=True)


class Base(DeclarativeBase):
    type_annotation_map = {  # noqa: RUF012 - contrato de DeclarativeBase
        uuid.UUID: UUID(as_uuid=True),
        datetime: TimestampTZ,
        dict[str, Any]: JSONB,
        list[str]: ARRAY(Text()),
        bytes: LargeBinary,
    }


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(primary_key=True)


def _org_fk() -> Mapped[uuid.UUID]:
    return mapped_column(ForeignKey("organization.id"), nullable=False)


def _created_at() -> Mapped[datetime]:
    return mapped_column(nullable=False, server_default=func.now())


def _updated_at() -> Mapped[datetime]:
    return mapped_column(nullable=False, server_default=func.now())


# ---------------------------------------------------------------------------
# Organizaciones, usuarios, membresías
# ---------------------------------------------------------------------------
class Organization(Base):
    __tablename__ = "organization"

    id: Mapped[uuid.UUID] = _uuid_pk()
    public_id: Mapped[str] = mapped_column(Text, unique=True)
    name: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(ORGANIZATION_STATUS, server_default=text("'active'"))
    data_retention_days: Mapped[int] = mapped_column(Integer, server_default=text("365"))
    default_language: Mapped[str] = mapped_column(Text, server_default=text("'es'"))
    deleted_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()


class UserAccount(Base):
    __tablename__ = "user_account"

    id: Mapped[uuid.UUID] = _uuid_pk()
    email: Mapped[str] = mapped_column(CITEXT, unique=True)
    display_name: Mapped[str] = mapped_column(Text)
    password_hash: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(USER_STATUS, server_default=text("'active'"))
    language: Mapped[str | None] = mapped_column(Text)
    theme: Mapped[str | None] = mapped_column(Text)
    last_login_at: Mapped[datetime | None]
    deleted_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()


class Membership(Base):
    __tablename__ = "membership"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id"),
        Index("membership_user_idx", "user_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user_account.id"))
    role: Mapped[str] = mapped_column(MEMBERSHIP_ROLE)
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()


class Session(Base):
    __tablename__ = "session"
    __table_args__ = (Index("session_expires_idx", "expires_at"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user_account.id"))
    organization_id: Mapped[uuid.UUID] = _org_fk()
    token_hash: Mapped[bytes] = mapped_column(unique=True)
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    ip_prefix: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _created_at()


class ApiClient(Base):
    __tablename__ = "api_client"
    __table_args__ = (Index("api_client_org_revoked_idx", "organization_id", "revoked_at"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(Text)
    key_prefix: Mapped[str] = mapped_column(Text, unique=True)
    secret_hash: Mapped[bytes]
    permissions: Mapped[list[str]] = mapped_column(server_default=text("'{}'"))
    expires_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
    last_used_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()


# ---------------------------------------------------------------------------
# Emisor y claves
# ---------------------------------------------------------------------------
class IssuerProfile(Base):
    __tablename__ = "issuer_profile"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organization.id"), primary_key=True
    )
    display_name: Mapped[str] = mapped_column(Text)
    issuer_path_id: Mapped[str] = mapped_column(Text, unique=True)
    default_credential_validity_days: Mapped[int] = mapped_column(
        Integer, server_default=text("365")
    )
    offer_ttl_hours: Mapped[int] = mapped_column(Integer, server_default=text("72"))
    enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()


class SigningKey(Base):
    __tablename__ = "signing_key"
    __table_args__ = (
        Index(
            "signing_key_one_active_idx",
            "organization_id",
            unique=True,
            postgresql_where=text("state = 'active'"),
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    kid: Mapped[str] = mapped_column(Text, unique=True)
    backend: Mapped[str] = mapped_column(KEY_BACKEND)
    key_ref: Mapped[str] = mapped_column(Text)
    public_jwk: Mapped[dict[str, Any]]
    alg: Mapped[str] = mapped_column(Text, server_default=text("'ES256'"))
    state: Mapped[str] = mapped_column(KEY_STATE, server_default=text("'active'"))
    activated_at: Mapped[datetime] = mapped_column(server_default=func.now())
    retired_at: Mapped[datetime | None]
    compromised_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()


# ---------------------------------------------------------------------------
# Plantillas
# ---------------------------------------------------------------------------
class CredentialTemplate(Base):
    __tablename__ = "credential_template"
    __table_args__ = (UniqueConstraint("organization_id", "slug"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    public_id: Mapped[str] = mapped_column(Text, unique=True)
    slug: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)
    archived_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()


class TemplateVersion(Base):
    __tablename__ = "template_version"
    __table_args__ = (UniqueConstraint("template_id", "version"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    template_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("credential_template.id"))
    version: Mapped[int] = mapped_column(Integer)
    claims_schema: Mapped[dict[str, Any]]
    selective_disclosure: Mapped[list[str]] = mapped_column(server_default=text("'{}'"))
    validity_days: Mapped[int] = mapped_column(Integer)
    display: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    state: Mapped[str] = mapped_column(TEMPLATE_STATE, server_default=text("'draft'"))
    published_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()


# ---------------------------------------------------------------------------
# Estado (Token Status List)
# ---------------------------------------------------------------------------
class StatusList(Base):
    __tablename__ = "status_list"
    __table_args__ = (Index("status_list_org_state_idx", "organization_id", "state"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    public_id: Mapped[str] = mapped_column(Text, unique=True)
    organization_id: Mapped[uuid.UUID] = _org_fk()
    bits: Mapped[int] = mapped_column(SmallInteger, server_default=text("1"))
    size: Mapped[int] = mapped_column(Integer, server_default=text("131072"))
    allocated: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    version: Mapped[int] = mapped_column(BigInteger, server_default=text("0"))
    signing_key_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("signing_key.id"))
    state: Mapped[str] = mapped_column(STATUS_LIST_STATE, server_default=text("'open'"))
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()


class CredentialStatus(Base):
    __tablename__ = "credential_status"

    status_list_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("status_list.id"), primary_key=True
    )
    idx: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[uuid.UUID] = _org_fk()
    value: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"))
    updated_at: Mapped[datetime] = _updated_at()


# ---------------------------------------------------------------------------
# Emisión
# ---------------------------------------------------------------------------
class Issuance(Base):
    __tablename__ = "issuance"
    __table_args__ = (
        UniqueConstraint("status_list_id", "status_idx"),
        ForeignKeyConstraint(
            ["status_list_id", "status_idx"],
            ["credential_status.status_list_id", "credential_status.idx"],
        ),
        Index("issuance_org_created_idx", "organization_id", text("created_at DESC")),
        Index("issuance_org_state_idx", "organization_id", "state"),
        Index("issuance_org_holder_idx", "organization_id", "holder_reference"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    public_id: Mapped[str] = mapped_column(Text, unique=True)
    organization_id: Mapped[uuid.UUID] = _org_fk()
    template_version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("template_version.id"))
    vct: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(ISSUANCE_STATE, server_default=text("'offered'"))
    holder_reference: Mapped[str | None] = mapped_column(Text)
    offer_id: Mapped[bytes] = mapped_column(unique=True)
    pre_auth_code_hash: Mapped[bytes]
    tx_code_hash: Mapped[str] = mapped_column(Text)
    tx_code_attempts: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"))
    offer_expires_at: Mapped[datetime]
    signing_key_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("signing_key.id"))
    holder_key_thumbprint: Mapped[str | None] = mapped_column(Text)
    status_list_id: Mapped[uuid.UUID | None]
    status_idx: Mapped[int | None] = mapped_column(Integer)
    issued_at: Mapped[datetime | None]
    expires_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
    revocation_reason_code: Mapped[str | None] = mapped_column(REVOCATION_REASON)
    revoked_by: Mapped[uuid.UUID | None]
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()
    delivery: Mapped[str] = mapped_column(Text, server_default=text("'oid4vci'"))


class IssuancePendingClaims(Base):
    __tablename__ = "issuance_pending_claims"

    issuance_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("issuance.id", ondelete="CASCADE"), primary_key=True
    )
    organization_id: Mapped[uuid.UUID] = _org_fk()
    ciphertext: Mapped[bytes]
    encrypted_data_key: Mapped[bytes]
    key_ref: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = _created_at()


# ---------------------------------------------------------------------------
# Verificación
# ---------------------------------------------------------------------------
class TrustPolicy(Base):
    __tablename__ = "trust_policy"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    name: Mapped[str] = mapped_column(Text)
    accepted_vcts: Mapped[list[str]] = mapped_column(server_default=text("'{}'"))
    required_claims: Mapped[list[str]] = mapped_column(server_default=text("'{}'"))
    require_holder_binding: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    require_status: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    max_status_age_seconds: Mapped[int] = mapped_column(Integer, server_default=text("900"))
    clock_skew_seconds: Mapped[int] = mapped_column(Integer, server_default=text("60"))
    max_kb_age_seconds: Mapped[int] = mapped_column(Integer, server_default=text("300"))
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = _updated_at()


class TrustedIssuer(Base):
    __tablename__ = "trusted_issuer"
    __table_args__ = (UniqueConstraint("trust_policy_id", "issuer"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    trust_policy_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("trust_policy.id", ondelete="CASCADE")
    )
    issuer: Mapped[str] = mapped_column(Text)
    hosted_org_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("organization.id"))
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _created_at()


class PresentationRequest(Base):
    __tablename__ = "presentation_request"
    __table_args__ = (Index("presentation_request_expires_idx", "expires_at"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    trust_policy_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("trust_policy.id"))
    nonce_hash: Mapped[bytes] = mapped_column(unique=True)
    aud: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime]
    consumed_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = _created_at()


class VerificationRecord(Base):
    __tablename__ = "verification_record"
    __table_args__ = (
        Index("verification_record_org_created_idx", "organization_id", text("created_at DESC")),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    presentation_request_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("presentation_request.id", ondelete="SET NULL")
    )
    result: Mapped[str] = mapped_column(VERIFICATION_RESULT)
    checks: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)  # [{name, outcome, code, detail}]
    issuer: Mapped[str | None] = mapped_column(Text)
    vct: Mapped[str | None] = mapped_column(Text)
    credential_ref: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("issuance.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = _created_at()


# ---------------------------------------------------------------------------
# Auditoría y consumo
# ---------------------------------------------------------------------------
class AuditEvent(Base):
    __tablename__ = "audit_event"
    __table_args__ = (
        Index("audit_event_org_occurred_idx", "organization_id", text("occurred_at DESC")),
        Index("audit_event_org_target_idx", "organization_id", "target_id"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    occurred_at: Mapped[datetime] = mapped_column(server_default=func.now())
    actor_type: Mapped[str] = mapped_column(ACTOR_TYPE)
    actor_id: Mapped[uuid.UUID | None]
    action: Mapped[str] = mapped_column(Text)
    target_type: Mapped[str | None] = mapped_column(Text)
    target_id: Mapped[uuid.UUID | None]
    request_id: Mapped[str | None] = mapped_column(Text)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", server_default=text("'{}'::jsonb")
    )


class UsageEvent(Base):
    __tablename__ = "usage_event"
    __table_args__ = (
        Index("usage_event_org_kind_occurred_idx", "organization_id", "kind", "occurred_at"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    occurred_at: Mapped[datetime] = mapped_column(server_default=func.now())
    kind: Mapped[str] = mapped_column(USAGE_KIND)
    api_client_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("api_client.id", ondelete="SET NULL")
    )
    quantity: Mapped[int] = mapped_column(Integer, server_default=text("1"))


# ---------------------------------------------------------------------------
# Plataforma
# ---------------------------------------------------------------------------
class IdempotencyRecord(Base):
    __tablename__ = "idempotency_record"
    __table_args__ = (Index("idempotency_record_expires_idx", "expires_at"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organization.id"), primary_key=True
    )
    key: Mapped[str] = mapped_column(Text, primary_key=True)
    request_hash: Mapped[bytes]
    response_status: Mapped[int] = mapped_column(SmallInteger)
    response_body: Mapped[dict[str, Any] | None]
    resource_id: Mapped[uuid.UUID | None]
    expires_at: Mapped[datetime]
    created_at: Mapped[datetime] = _created_at()


class Oid4vciNonce(Base):
    __tablename__ = "oid4vci_nonce"
    __table_args__ = (Index("oid4vci_nonce_expires_idx", "expires_at"),)

    nonce_hash: Mapped[bytes] = mapped_column(primary_key=True)
    expires_at: Mapped[datetime]
    consumed_at: Mapped[datetime | None]


class Oid4vciAccessToken(Base):
    __tablename__ = "oid4vci_access_token"
    __table_args__ = (Index("oid4vci_access_token_expires_idx", "expires_at"),)

    token_hash: Mapped[bytes] = mapped_column(primary_key=True)
    issuance_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("issuance.id", ondelete="CASCADE"))
    expires_at: Mapped[datetime]
    consumed_at: Mapped[datetime | None]


class Oid4vpSession(Base):
    __tablename__ = "oid4vp_session"
    __table_args__ = (
        Index("oid4vp_session_org_created_idx", "organization_id", text("created_at DESC")),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    organization_id: Mapped[uuid.UUID] = _org_fk()
    presentation_request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("presentation_request.id", ondelete="CASCADE"), unique=True
    )
    state_hash: Mapped[bytes] = mapped_column(unique=True)
    client_id: Mapped[str] = mapped_column(Text)
    response_uri: Mapped[str] = mapped_column(Text)
    dcql_query: Mapped[dict[str, Any]]
    status: Mapped[str] = mapped_column(Text, server_default=text("'pending'"))
    error: Mapped[str | None] = mapped_column(Text)
    verification_record_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("verification_record.id", ondelete="SET NULL")
    )
    result_ciphertext: Mapped[bytes | None]
    result_encrypted_key: Mapped[bytes | None]
    result_key_ref: Mapped[str | None] = mapped_column(Text)
    completed_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = _created_at()
    client_id_scheme: Mapped[str] = mapped_column(Text, server_default=text("'redirect_uri'"))
    response_mode: Mapped[str] = mapped_column(Text, server_default=text("'direct_post'"))
    request_ref: Mapped[str | None] = mapped_column(Text, unique=True)
    request_object: Mapped[str | None] = mapped_column(Text)
    request_fetched_at: Mapped[datetime | None]
    response_kid: Mapped[str | None] = mapped_column(Text, unique=True)
    response_key_ciphertext: Mapped[bytes | None]
    response_key_encrypted_key: Mapped[bytes | None]
    response_key_ref: Mapped[str | None] = mapped_column(Text)


class RateLimitBucket(Base):
    __tablename__ = "rate_limit_bucket"

    subject: Mapped[str] = mapped_column(Text, primary_key=True)
    window_start: Mapped[datetime] = mapped_column(primary_key=True)
    count: Mapped[int] = mapped_column(Integer, server_default=text("0"))
