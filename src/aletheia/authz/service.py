"""Servicio de autenticación.

- Contraseñas: Argon2id (argon2-cffi, parámetros por defecto de la librería,
  alineados con OWASP).
- Sesiones: token ``st_…`` de 256 bits, 8 h, hash en ``session``.
- Claves de API: ``ak_XXXXXXXX_…``; el secreto se muestra una sola vez.
- Todo fallo de autenticación se responde igual (``invalid_credentials``) y
  con coste de verificación comparable, para no revelar si el correo existe.
"""

from __future__ import annotations

import ipaddress
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import models
from ..platform import ids, ratelimit
from ..platform.errors import AppError, NotFound, Unauthorized
from .permissions import API_CLIENT_PERMISSIONS, Permission, permissions_for_role

log = logging.getLogger(__name__)

SESSION_TTL = timedelta(hours=8)
LOGIN_WINDOW = timedelta(minutes=15)
LOGIN_LIMIT_PER_EMAIL = 10
LOGIN_LIMIT_PER_NETWORK = 100
API_CLIENT_MAX_LIFETIME = timedelta(days=365)
LAST_USED_GRANULARITY = timedelta(minutes=1)

_hasher = PasswordHasher()
# Hash de referencia para igualar el coste cuando el usuario no existe.
_DUMMY_HASH = _hasher.hash("aletheia-dummy-password")


class InvalidCredentials(Unauthorized):
    code = "invalid_credentials"


class OrganizationRequired(AppError):
    status_code = 400
    code = "organization_required"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def network_prefix(host: str | None) -> str | None:
    """/24 para IPv4, /64 para IPv6: suficiente para limitar, no identifica a una persona."""
    if not host:
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    bits = 24 if address.version == 4 else 64
    return str(ipaddress.ip_network(f"{address}/{bits}", strict=False))


@dataclass(frozen=True)
class Principal:
    organization_id: uuid.UUID
    actor_type: str  # user | api_client
    actor_id: uuid.UUID
    permissions: frozenset[Permission]
    role: str | None = None
    session_id: uuid.UUID | None = None
    permission_names: tuple[str, ...] = field(default=(), compare=False)

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions

    @property
    def audit_actor(self) -> audit.Actor:
        return audit.Actor(self.actor_type, self.actor_id)


def _principal_for_user(
    user: models.UserAccount, membership: models.Membership, session_id: uuid.UUID
) -> Principal:
    perms = permissions_for_role(membership.role)
    return Principal(
        organization_id=membership.organization_id,
        actor_type="user",
        actor_id=user.id,
        permissions=perms,
        role=membership.role,
        session_id=session_id,
        permission_names=tuple(sorted(perms)),
    )


# ---------------------------------------------------------------------------
# Login / sesiones
# ---------------------------------------------------------------------------
def login(
    session: Session,
    *,
    email: str,
    password: str,
    organization_public_id: str | None,
    client_host: str | None,
    now: datetime | None = None,
) -> tuple[str, Principal, datetime]:
    now = now or datetime.now(UTC)
    prefix = network_prefix(client_host)
    ratelimit.hit(
        session, f"login:email:{email.lower()}", limit=LOGIN_LIMIT_PER_EMAIL, window=LOGIN_WINDOW
    )
    if prefix:
        ratelimit.hit(
            session, f"login:net:{prefix}", limit=LOGIN_LIMIT_PER_NETWORK, window=LOGIN_WINDOW
        )

    user = session.scalar(select(models.UserAccount).where(models.UserAccount.email == email))
    if user is None or user.status != "active" or user.deleted_at is not None:
        verify_password(_DUMMY_HASH, password)  # coste comparable
        raise InvalidCredentials("Invalid credentials")
    if not verify_password(user.password_hash, password):
        raise InvalidCredentials("Invalid credentials")

    memberships = list(
        session.scalars(
            select(models.Membership)
            .join(models.Organization)
            .where(models.Membership.user_id == user.id)
            .where(models.Organization.status == "active")
            .where(models.Organization.deleted_at.is_(None))
        ).all()
    )
    if organization_public_id is not None:
        org = session.scalar(
            select(models.Organization).where(
                models.Organization.public_id == organization_public_id
            )
        )
        memberships = [m for m in memberships if org is not None and m.organization_id == org.id]
    if not memberships:
        raise InvalidCredentials("Invalid credentials")
    if len(memberships) > 1:
        raise OrganizationRequired(
            "User belongs to several organizations; specify `organization`",
            details={
                "organizations": [
                    session.get_one(models.Organization, m.organization_id).public_id
                    for m in memberships
                ]
            },
        )
    membership = memberships[0]

    if _hasher.check_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.last_login_at = now

    token, token_hash = ids.new_session_token()
    record = models.Session(
        id=ids.uuid7(),
        user_id=user.id,
        organization_id=membership.organization_id,
        token_hash=token_hash,
        expires_at=now + SESSION_TTL,
        ip_prefix=prefix,
    )
    session.add(record)
    principal = _principal_for_user(user, membership, record.id)
    audit.record(
        session,
        organization_id=principal.organization_id,
        actor=principal.audit_actor,
        action="session.created",
        target_type="session",
        target_id=record.id,
    )
    return token, principal, record.expires_at


def logout(session: Session, principal: Principal, now: datetime | None = None) -> None:
    if principal.session_id is None:
        return
    record = session.get(models.Session, principal.session_id)
    if record is not None and record.revoked_at is None:
        record.revoked_at = now or datetime.now(UTC)
        audit.record(
            session,
            organization_id=principal.organization_id,
            actor=principal.audit_actor,
            action="session.revoked",
            target_type="session",
            target_id=record.id,
        )


# ---------------------------------------------------------------------------
# Resolución del principal
# ---------------------------------------------------------------------------
def authenticate(session: Session, token: str, now: datetime | None = None) -> Principal:
    now = now or datetime.now(UTC)
    if token.startswith(ids.SESSION_TOKEN_PREFIX):
        return _authenticate_session(session, token, now)
    if token.startswith(ids.API_KEY_PREFIX):
        return _authenticate_api_key(session, token, now)
    raise Unauthorized("Invalid or expired token")


def _authenticate_session(session: Session, token: str, now: datetime) -> Principal:
    token_hash = ids.parse_session_token(token)
    if token_hash is None:
        raise Unauthorized("Invalid or expired token")
    record = session.scalar(select(models.Session).where(models.Session.token_hash == token_hash))
    if record is None or record.revoked_at is not None or record.expires_at <= now:
        raise Unauthorized("Invalid or expired token")
    user = session.get(models.UserAccount, record.user_id)
    membership = session.scalar(
        select(models.Membership)
        .where(models.Membership.user_id == record.user_id)
        .where(models.Membership.organization_id == record.organization_id)
    )
    org = session.get(models.Organization, record.organization_id)
    if (
        user is None
        or user.status != "active"
        or membership is None
        or org is None
        or org.status != "active"
    ):
        raise Unauthorized("Invalid or expired token")
    return _principal_for_user(user, membership, record.id)


def _authenticate_api_key(session: Session, token: str, now: datetime) -> Principal:
    parsed = ids.parse_api_key(token)
    if parsed is None:
        raise Unauthorized("Invalid or expired token")
    key_prefix, secret_hash = parsed
    client = session.scalar(
        select(models.ApiClient).where(models.ApiClient.key_prefix == key_prefix)
    )
    if (
        client is None
        or not ids.constant_time_equal(client.secret_hash, secret_hash)
        or client.revoked_at is not None
        or (client.expires_at is not None and client.expires_at <= now)
    ):
        raise Unauthorized("Invalid or expired token")
    org = session.get(models.Organization, client.organization_id)
    if org is None or org.status != "active":
        raise Unauthorized("Invalid or expired token")
    if client.last_used_at is None or now - client.last_used_at >= LAST_USED_GRANULARITY:
        client.last_used_at = now
    perms = frozenset(Permission(p) for p in client.permissions) & API_CLIENT_PERMISSIONS
    return Principal(
        organization_id=client.organization_id,
        actor_type="api_client",
        actor_id=client.id,
        permissions=perms,
        permission_names=tuple(sorted(perms)),
    )


# ---------------------------------------------------------------------------
# Claves de API
# ---------------------------------------------------------------------------
class InvalidPermissions(AppError):
    status_code = 422
    code = "invalid_permissions"


def create_api_client(
    session: Session,
    principal: Principal,
    *,
    name: str,
    permissions: list[str],
    expires_at: datetime | None,
    now: datetime | None = None,
) -> tuple[models.ApiClient, str]:
    now = now or datetime.now(UTC)
    requested: set[Permission] = set()
    for value in permissions:
        try:
            requested.add(Permission(value))
        except ValueError:
            raise InvalidPermissions(f"Unknown permission: {value}") from None
    not_allowed = requested - API_CLIENT_PERMISSIONS
    if not_allowed:
        raise InvalidPermissions(
            "Permissions not available to API clients", details=sorted(not_allowed)
        )
    # Nadie puede delegar más de lo que tiene.
    exceeding = requested - principal.permissions
    if exceeding:
        raise InvalidPermissions(
            "Cannot grant permissions you do not hold", details=sorted(exceeding)
        )
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= now or expires_at > now + API_CLIENT_MAX_LIFETIME:
            raise AppError("expires_at must be in the future and at most one year ahead")

    full_key, key_prefix, secret_hash = ids.new_api_key()
    client = models.ApiClient(
        id=ids.uuid7(),
        organization_id=principal.organization_id,
        name=name,
        key_prefix=key_prefix,
        secret_hash=secret_hash,
        permissions=sorted(p.value for p in requested),
        expires_at=expires_at,
    )
    session.add(client)
    audit.record(
        session,
        organization_id=principal.organization_id,
        actor=principal.audit_actor,
        action="api_client.created",
        target_type="api_client",
        target_id=client.id,
        metadata={"permissions": client.permissions},
    )
    return client, full_key


def list_api_clients(session: Session, principal: Principal) -> list[models.ApiClient]:
    return list(
        session.scalars(
            select(models.ApiClient)
            .where(models.ApiClient.organization_id == principal.organization_id)
            .order_by(models.ApiClient.created_at.desc())
        ).all()
    )


def revoke_api_client(
    session: Session, principal: Principal, client_id: uuid.UUID, now: datetime | None = None
) -> models.ApiClient:
    client = session.get(models.ApiClient, client_id)
    if client is None or client.organization_id != principal.organization_id:
        raise NotFound("API client not found")
    if client.revoked_at is None:
        client.revoked_at = now or datetime.now(UTC)
        audit.record(
            session,
            organization_id=principal.organization_id,
            actor=principal.audit_actor,
            action="api_client.revoked",
            target_type="api_client",
            target_id=client.id,
        )
    return client
