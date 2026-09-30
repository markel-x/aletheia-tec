"""Servicios de organización: alta, miembros, perfil de emisor, claves de firma.

Toda consulta se filtra por ``organization_id`` del principal; un recurso de
otra organización responde 404 (doc 02 §4).
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..authz.permissions import validate_role_name
from ..authz.service import Principal, hash_password
from ..db import models
from ..platform import ids
from ..platform.config import Settings
from ..platform.errors import AppError, Conflict, NotFound
from ..vc.signing import Signer
from .keys import SignerBackend

log = logging.getLogger(__name__)

MAX_CREDENTIAL_VALIDITY = timedelta(days=3650)
MIN_PASSWORD_LENGTH = 12


class WeakPassword(AppError):
    code = "weak_password"


def _check_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPassword(f"Password must have at least {MIN_PASSWORD_LENGTH} characters")


def issuer_url(settings: Settings, org_public_id: str) -> str:
    return f"{settings.public_base}/issuers/{org_public_id}"


# ---------------------------------------------------------------------------
# Alta
# ---------------------------------------------------------------------------
def bootstrap_organization(
    session: Session,
    backend: SignerBackend,
    *,
    name: str,
    owner_email: str,
    owner_display_name: str,
    owner_password: str,
    now: datetime | None = None,
) -> tuple[models.Organization, models.UserAccount, models.SigningKey]:
    """Crea organización, perfil de emisor, usuario propietario y clave activa."""
    now = now or datetime.now(UTC)
    _check_password(owner_password)
    if session.scalar(select(models.UserAccount).where(models.UserAccount.email == owner_email)):
        raise Conflict("A user with that email already exists")

    org = models.Organization(id=ids.uuid7(), public_id=ids.public_id("org"), name=name)
    session.add(org)
    session.flush()
    session.add(
        models.IssuerProfile(
            organization_id=org.id, display_name=name, issuer_path_id=org.public_id
        )
    )
    owner = models.UserAccount(
        id=ids.uuid7(),
        email=owner_email,
        display_name=owner_display_name,
        password_hash=hash_password(owner_password),
    )
    session.add(owner)
    session.flush()
    session.add(
        models.Membership(id=ids.uuid7(), organization_id=org.id, user_id=owner.id, role="owner")
    )
    system = audit.Actor.system()
    audit.record(
        session,
        organization_id=org.id,
        actor=system,
        action="organization.created",
        target_type="organization",
        target_id=org.id,
    )
    audit.record(
        session,
        organization_id=org.id,
        actor=system,
        action="member.added",
        target_type="user",
        target_id=owner.id,
        metadata={"role": "owner"},
    )
    key = _create_key(session, backend, org, actor=system, now=now)
    return org, owner, key


# ---------------------------------------------------------------------------
# Organización y perfil de emisor
# ---------------------------------------------------------------------------
def get_organization(session: Session, principal: Principal) -> models.Organization:
    org = session.get(models.Organization, principal.organization_id)
    if org is None:
        raise NotFound("Organization not found")
    return org


def get_issuer_profile(session: Session, principal: Principal) -> models.IssuerProfile:
    profile = session.get(models.IssuerProfile, principal.organization_id)
    if profile is None:
        raise NotFound("Issuer profile not found")
    return profile


def update_issuer_profile(
    session: Session, principal: Principal, changes: dict[str, Any]
) -> models.IssuerProfile:
    profile = get_issuer_profile(session, principal)
    applied: dict[str, Any] = {}
    for field in ("display_name", "default_credential_validity_days", "offer_ttl_hours", "enabled"):
        if field in changes and changes[field] is not None:
            setattr(profile, field, changes[field])
            applied[field] = changes[field]
    if applied:
        audit.record(
            session,
            organization_id=principal.organization_id,
            actor=principal.audit_actor,
            action="issuer_profile.updated",
            target_type="organization",
            target_id=principal.organization_id,
            metadata={"fields": sorted(applied)},
        )
    return profile


# ---------------------------------------------------------------------------
# Miembros
# ---------------------------------------------------------------------------
class LastOwner(Conflict):
    code = "last_owner"


def list_members(
    session: Session, principal: Principal
) -> list[tuple[models.Membership, models.UserAccount]]:
    rows = session.execute(
        select(models.Membership, models.UserAccount)
        .join(models.UserAccount, models.UserAccount.id == models.Membership.user_id)
        .where(models.Membership.organization_id == principal.organization_id)
        .order_by(models.Membership.created_at)
    ).all()
    return [(m, u) for m, u in rows]


def add_member(
    session: Session,
    principal: Principal,
    *,
    email: str,
    display_name: str,
    role: str,
    password: str | None,
) -> tuple[models.Membership, models.UserAccount, str | None]:
    """Añade un miembro. Si el usuario no existe se crea con la contraseña dada
    o con una temporal que se devuelve **una sola vez**."""
    validate_role_name(role)
    user = session.scalar(select(models.UserAccount).where(models.UserAccount.email == email))
    temporary_password: str | None = None
    if user is None:
        if password is None:
            temporary_password = password = ids.new_secret()
        _check_password(password)
        user = models.UserAccount(
            id=ids.uuid7(),
            email=email,
            display_name=display_name,
            password_hash=hash_password(password),
        )
        session.add(user)
        session.flush()
    existing = session.scalar(
        select(models.Membership)
        .where(models.Membership.organization_id == principal.organization_id)
        .where(models.Membership.user_id == user.id)
    )
    if existing is not None:
        raise Conflict("User is already a member")
    membership = models.Membership(
        id=ids.uuid7(), organization_id=principal.organization_id, user_id=user.id, role=role
    )
    session.add(membership)
    audit.record(
        session,
        organization_id=principal.organization_id,
        actor=principal.audit_actor,
        action="member.added",
        target_type="user",
        target_id=user.id,
        metadata={"role": role},
    )
    return membership, user, temporary_password


def _membership(session: Session, principal: Principal, user_id: uuid.UUID) -> models.Membership:
    membership = session.scalar(
        select(models.Membership)
        .where(models.Membership.organization_id == principal.organization_id)
        .where(models.Membership.user_id == user_id)
    )
    if membership is None:
        raise NotFound("Member not found")
    return membership


def _owner_count(session: Session, organization_id: uuid.UUID) -> int:
    return int(
        session.scalar(
            select(func.count())
            .select_from(models.Membership)
            .where(models.Membership.organization_id == organization_id)
            .where(models.Membership.role == "owner")
        )
        or 0
    )


def change_member_role(
    session: Session, principal: Principal, user_id: uuid.UUID, role: str
) -> models.Membership:
    validate_role_name(role)
    membership = _membership(session, principal, user_id)
    if (
        membership.role == "owner"
        and role != "owner"
        and _owner_count(session, principal.organization_id) <= 1
    ):
        raise LastOwner("The organization must keep at least one owner")
    previous = membership.role
    membership.role = role
    audit.record(
        session,
        organization_id=principal.organization_id,
        actor=principal.audit_actor,
        action="member.role_changed",
        target_type="user",
        target_id=user_id,
        metadata={"from": previous, "to": role},
    )
    return membership


def remove_member(session: Session, principal: Principal, user_id: uuid.UUID) -> None:
    membership = _membership(session, principal, user_id)
    if membership.role == "owner" and _owner_count(session, principal.organization_id) <= 1:
        raise LastOwner("The organization must keep at least one owner")
    session.delete(membership)
    # Sus sesiones en esta organización dejan de ser válidas.
    for s in session.scalars(
        select(models.Session)
        .where(models.Session.user_id == user_id)
        .where(models.Session.organization_id == principal.organization_id)
        .where(models.Session.revoked_at.is_(None))
    ):
        s.revoked_at = datetime.now(UTC)
    audit.record(
        session,
        organization_id=principal.organization_id,
        actor=principal.audit_actor,
        action="member.removed",
        target_type="user",
        target_id=user_id,
    )


# ---------------------------------------------------------------------------
# Claves de firma
# ---------------------------------------------------------------------------
def _create_key(
    session: Session,
    backend: SignerBackend,
    org: models.Organization,
    *,
    actor: audit.Actor,
    now: datetime,
) -> models.SigningKey:
    key_ref, signer = backend.create(org.public_id)
    key = models.SigningKey(
        id=ids.uuid7(),
        organization_id=org.id,
        kid=signer.kid,
        backend=backend.name,
        key_ref=key_ref,
        public_jwk=signer.public_jwk,
        alg=signer.alg,
        state="active",
        activated_at=now,
    )
    session.add(key)
    session.flush()
    audit.record(
        session,
        organization_id=org.id,
        actor=actor,
        action="signing_key.created",
        target_type="signing_key",
        target_id=key.id,
        metadata={"kid": key.kid, "backend": key.backend},
    )
    return key


def list_signing_keys(session: Session, principal: Principal) -> list[models.SigningKey]:
    return list(
        session.scalars(
            select(models.SigningKey)
            .where(models.SigningKey.organization_id == principal.organization_id)
            .order_by(models.SigningKey.activated_at.desc())
        ).all()
    )


def active_signing_key(session: Session, organization_id: uuid.UUID) -> models.SigningKey:
    key = session.scalar(
        select(models.SigningKey)
        .where(models.SigningKey.organization_id == organization_id)
        .where(models.SigningKey.state == "active")
    )
    if key is None:
        raise AppError("The organization has no active signing key", details=None)
    return key


def active_signer(session: Session, backend: SignerBackend, organization_id: uuid.UUID) -> Signer:
    key = active_signing_key(session, organization_id)
    return backend.load(key.key_ref, key.public_jwk)


def rotate_signing_key(
    session: Session,
    backend: SignerBackend,
    principal: Principal,
    now: datetime | None = None,
) -> models.SigningKey:
    """Retira la clave activa (sigue publicada) y crea una nueva activa."""
    now = now or datetime.now(UTC)
    org = get_organization(session, principal)
    current = session.scalar(
        select(models.SigningKey)
        .where(models.SigningKey.organization_id == org.id)
        .where(models.SigningKey.state == "active")
    )
    if current is not None:
        current.state = "retired"
        current.retired_at = now
        session.flush()  # libera el índice único parcial antes de crear la nueva
        audit.record(
            session,
            organization_id=org.id,
            actor=principal.audit_actor,
            action="signing_key.retired",
            target_type="signing_key",
            target_id=current.id,
            metadata={"kid": current.kid},
        )
    return _create_key(session, backend, org, actor=principal.audit_actor, now=now)


def compromise_signing_key(
    session: Session,
    backend: SignerBackend,
    principal: Principal,
    key_id: uuid.UUID,
    now: datetime | None = None,
) -> models.SigningKey:
    """Marca la clave como comprometida: sale del JWKS y no firma más.

    Si era la activa, se crea una nueva para que la organización siga operando.
    """
    now = now or datetime.now(UTC)
    key = session.get(models.SigningKey, key_id)
    if key is None or key.organization_id != principal.organization_id:
        raise NotFound("Signing key not found")
    if key.state == "compromised":
        return key
    was_active = key.state == "active"
    key.state = "compromised"
    key.compromised_at = now
    if key.retired_at is None:
        key.retired_at = now
    session.flush()
    audit.record(
        session,
        organization_id=principal.organization_id,
        actor=principal.audit_actor,
        action="signing_key.compromised",
        target_type="signing_key",
        target_id=key.id,
        metadata={"kid": key.kid, "was_active": was_active},
    )
    try:
        backend.disable(key.key_ref)
    except Exception:  # el estado en BD manda; el fallo se registra
        log.exception("could not disable key in backend", extra={"kid": key.kid})
    if was_active:
        org = get_organization(session, principal)
        _create_key(session, backend, org, actor=principal.audit_actor, now=now)
    return key


def published_jwks(
    session: Session, org_public_id: str, now: datetime | None = None
) -> dict[str, Any]:
    """JWKS público del emisor: claves activas y retiradas vigentes; nunca comprometidas."""
    now = now or datetime.now(UTC)
    org = session.scalar(
        select(models.Organization)
        .where(models.Organization.public_id == org_public_id)
        .where(models.Organization.status == "active")
        .where(models.Organization.deleted_at.is_(None))
    )
    if org is None:
        raise NotFound("Issuer not found")
    profile = session.get(models.IssuerProfile, org.id)
    if profile is None or not profile.enabled:
        raise NotFound("Issuer not found")
    keys = session.scalars(
        select(models.SigningKey)
        .where(models.SigningKey.organization_id == org.id)
        .where(models.SigningKey.state.in_(("active", "retired")))
        .order_by(models.SigningKey.activated_at.desc())
    ).all()
    published = []
    for key in keys:
        if (
            key.state == "retired"
            and key.retired_at is not None
            and key.retired_at + MAX_CREDENTIAL_VALIDITY < now
        ):
            continue
        published.append({**key.public_jwk, "kid": key.kid, "alg": key.alg, "use": "sig"})
    return {"keys": published}
