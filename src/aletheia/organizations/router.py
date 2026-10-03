"""``/v1/organization``, ``/v1/members``, ``/v1/signing-keys``, ``/v1/audit-events``
y el endpoint público de metadatos del emisor."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Request, Response, status
from pydantic import BaseModel, EmailStr, Field

from ..admin.router import serve_static
from ..api.deps import BackendDep, PrincipalDep, SessionDep, SystemSessionDep, require
from ..api.routing import TransactionalRoute
from ..audit import service as audit_service
from ..authz.permissions import ROLES, Permission
from ..authz.service import Principal
from ..platform.config import Settings
from . import service

router = APIRouter(route_class=TransactionalRoute, prefix="/v1", tags=["organizations"])
public_router = APIRouter(route_class=TransactionalRoute, tags=["public"])


class OrganizationResponse(BaseModel):
    id: uuid.UUID
    public_id: str
    name: str
    status: str
    issuer: str
    default_language: str
    created_at: datetime


Language = Literal["es", "en"]


class OrganizationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    default_language: Language | None = None


class AccountUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    language: Language | None = Field(
        default=None, description="null = usar el idioma predeterminado de la organización"
    )


class AccountResponse(BaseModel):
    email: str
    display_name: str
    language: str | None


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)


class PasswordChanged(BaseModel):
    sessions_revoked: int = Field(description="Sesiones cerradas en otros dispositivos")


class MemberPasswordReset(BaseModel):
    user_id: uuid.UUID
    email: str
    temporary_password: str = Field(description="Se muestra una sola vez")


class IssuerProfileResponse(BaseModel):
    display_name: str
    issuer_path_id: str
    default_credential_validity_days: int
    offer_ttl_hours: int
    enabled: bool


class IssuerProfileUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    default_credential_validity_days: int | None = Field(default=None, ge=1, le=3650)
    offer_ttl_hours: int | None = Field(default=None, ge=1, le=168)
    enabled: bool | None = None


class MemberResponse(BaseModel):
    user_id: uuid.UUID
    email: str
    display_name: str
    role: str
    status: str
    created_at: datetime


class MemberCreate(BaseModel):
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=200)
    role: str = Field(pattern="^(" + "|".join(ROLES) + ")$")
    password: str | None = Field(default=None, min_length=12, max_length=1024)


class MemberCreated(MemberResponse):
    temporary_password: str | None = Field(
        default=None, description="Sólo si se generó una; se muestra una sola vez"
    )


class MemberRoleUpdate(BaseModel):
    role: str = Field(pattern="^(" + "|".join(ROLES) + ")$")


class SigningKeyResponse(BaseModel):
    id: uuid.UUID
    kid: str
    backend: str
    alg: str
    state: str
    public_jwk: dict[str, Any]
    activated_at: datetime
    retired_at: datetime | None
    compromised_at: datetime | None


class AuditEventResponse(BaseModel):
    id: uuid.UUID
    occurred_at: datetime
    actor_type: str
    actor_id: uuid.UUID | None
    action: str
    target_type: str | None
    target_id: uuid.UUID | None
    request_id: str | None
    metadata: dict[str, Any]


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def _member(m: Any, u: Any) -> MemberResponse:
    return MemberResponse(
        user_id=u.id,
        email=u.email,
        display_name=u.display_name,
        role=m.role,
        status=u.status,
        created_at=m.created_at,
    )


def _key(k: Any) -> SigningKeyResponse:
    return SigningKeyResponse.model_validate(k, from_attributes=True)


# ---------------------------------------------------------------------------
# Organización
# ---------------------------------------------------------------------------
@router.get("/organization", response_model=OrganizationResponse)
def get_organization(
    principal: PrincipalDep, session: SessionDep, request: Request
) -> OrganizationResponse:
    return _organization(service.get_organization(session, principal), request)


def _organization(org: Any, request: Request) -> OrganizationResponse:
    return OrganizationResponse(
        id=org.id,
        public_id=org.public_id,
        name=org.name,
        status=org.status,
        issuer=service.issuer_url(_settings(request), org.public_id),
        default_language=org.default_language,
        created_at=org.created_at,
    )


@router.patch("/organization", response_model=OrganizationResponse)
def update_organization(
    body: OrganizationUpdate,
    principal: Annotated[Principal, Depends(require(Permission.ORG_MANAGE))],
    session: SessionDep,
    request: Request,
) -> OrganizationResponse:
    org = service.update_organization(session, principal, body.model_dump())
    session.flush()
    return _organization(org, request)


# ---------------------------------------------------------------------------
# Cuenta propia (sesiones de usuario; las claves de API no tienen cuenta)
# ---------------------------------------------------------------------------
@router.patch("/auth/me", response_model=AccountResponse, tags=["auth"])
def update_account(
    body: AccountUpdate, principal: PrincipalDep, session: SessionDep
) -> AccountResponse:
    # Sólo los campos enviados: «language: null» vuelve al idioma de la organización.
    changes = body.model_dump(include=body.model_fields_set)
    user = service.update_account(session, principal, changes)
    return AccountResponse(email=user.email, display_name=user.display_name, language=user.language)


@router.post("/auth/password", response_model=PasswordChanged, tags=["auth"])
def change_password(
    body: PasswordChange, principal: PrincipalDep, session: SessionDep
) -> PasswordChanged:
    revoked = service.change_password(
        session,
        principal,
        current_password=body.current_password,
        new_password=body.new_password,
    )
    return PasswordChanged(sessions_revoked=revoked)


@router.get("/organization/issuer-profile", response_model=IssuerProfileResponse)
def get_issuer_profile(principal: PrincipalDep, session: SessionDep) -> IssuerProfileResponse:
    return IssuerProfileResponse.model_validate(
        service.get_issuer_profile(session, principal), from_attributes=True
    )


@router.put("/organization/issuer-profile", response_model=IssuerProfileResponse)
def update_issuer_profile(
    body: IssuerProfileUpdate,
    principal: Annotated[Principal, Depends(require(Permission.ORG_MANAGE))],
    session: SessionDep,
) -> IssuerProfileResponse:
    profile = service.update_issuer_profile(session, principal, body.model_dump())
    return IssuerProfileResponse.model_validate(profile, from_attributes=True)


# ---------------------------------------------------------------------------
# Miembros
# ---------------------------------------------------------------------------
@router.get("/members", response_model=list[MemberResponse])
def list_members(
    principal: Annotated[Principal, Depends(require(Permission.MEMBERS_MANAGE))],
    session: SessionDep,
) -> list[MemberResponse]:
    return [_member(m, u) for m, u in service.list_members(session, principal)]


@router.post("/members", response_model=MemberCreated, status_code=status.HTTP_201_CREATED)
def add_member(
    body: MemberCreate,
    principal: Annotated[Principal, Depends(require(Permission.MEMBERS_MANAGE))],
    session: SessionDep,
) -> MemberCreated:
    membership, user, temporary = service.add_member(
        session,
        principal,
        email=body.email,
        display_name=body.display_name,
        role=body.role,
        password=body.password,
    )
    session.flush()
    return MemberCreated(**_member(membership, user).model_dump(), temporary_password=temporary)


@router.patch("/members/{user_id}", response_model=MemberResponse)
def change_member_role(
    user_id: uuid.UUID,
    body: MemberRoleUpdate,
    principal: Annotated[Principal, Depends(require(Permission.MEMBERS_MANAGE))],
    session: SessionDep,
) -> MemberResponse:
    service.change_member_role(session, principal, user_id, body.role)
    rows = [(m, u) for m, u in service.list_members(session, principal) if u.id == user_id]
    return _member(*rows[0])


@router.post("/members/{user_id}/password-reset", response_model=MemberPasswordReset)
def reset_member_password(
    user_id: uuid.UUID,
    principal: Annotated[Principal, Depends(require(Permission.MEMBERS_MANAGE))],
    session: SessionDep,
) -> MemberPasswordReset:
    user, temporary = service.reset_member_password(session, principal, user_id)
    return MemberPasswordReset(user_id=user.id, email=user.email, temporary_password=temporary)


@router.delete("/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(
    user_id: uuid.UUID,
    principal: Annotated[Principal, Depends(require(Permission.MEMBERS_MANAGE))],
    session: SessionDep,
) -> None:
    service.remove_member(session, principal, user_id)


# ---------------------------------------------------------------------------
# Claves de firma
# ---------------------------------------------------------------------------
@router.get("/signing-keys", response_model=list[SigningKeyResponse])
def list_signing_keys(
    principal: Annotated[Principal, Depends(require(Permission.ORG_MANAGE))],
    session: SessionDep,
) -> list[SigningKeyResponse]:
    return [_key(k) for k in service.list_signing_keys(session, principal)]


@router.post(
    "/signing-keys/rotate", response_model=SigningKeyResponse, status_code=status.HTTP_201_CREATED
)
def rotate_signing_key(
    principal: Annotated[Principal, Depends(require(Permission.ORG_MANAGE))],
    session: SessionDep,
    backend: BackendDep,
) -> SigningKeyResponse:
    return _key(service.rotate_signing_key(session, backend, principal))


@router.post("/signing-keys/{key_id}/compromise", response_model=SigningKeyResponse)
def compromise_signing_key(
    key_id: uuid.UUID,
    principal: Annotated[Principal, Depends(require(Permission.SIGNING_KEYS_COMPROMISE))],
    session: SessionDep,
    backend: BackendDep,
) -> SigningKeyResponse:
    return _key(service.compromise_signing_key(session, backend, principal, key_id))


# ---------------------------------------------------------------------------
# Auditoría
# ---------------------------------------------------------------------------
@router.get("/audit-events", response_model=list[AuditEventResponse])
def list_audit_events(
    principal: Annotated[Principal, Depends(require(Permission.AUDIT_READ))],
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    target_id: uuid.UUID | None = None,
) -> list[AuditEventResponse]:
    events = audit_service.list_events(
        session, principal.organization_id, limit=limit, target_id=target_id
    )
    return [
        AuditEventResponse(
            id=e.id,
            occurred_at=e.occurred_at,
            actor_type=e.actor_type,
            actor_id=e.actor_id,
            action=e.action,
            target_type=e.target_type,
            target_id=e.target_id,
            request_id=e.request_id,
            metadata=e.metadata_,
        )
        for e in events
    ]


# ---------------------------------------------------------------------------
# Público: metadatos del emisor (ADR-0004)
# ---------------------------------------------------------------------------
# Página pública del emisor: la URL ``iss`` de sus credenciales, abierta en un navegador.
# Los wallets no la usan (leen los metadatos en /.well-known/…).
@public_router.get("/issuers/{org_public_id}", include_in_schema=False)
def issuer_page(org_public_id: str) -> Response:
    return serve_static("issuer.html")


@public_router.get("/issuer-info/{org_public_id}")
def issuer_info(
    org_public_id: str, request: Request, response: Response, session: SystemSessionDep
) -> dict[str, Any]:
    info = service.public_issuer_info(session, _settings(request), org_public_id)
    response.headers["Cache-Control"] = "public, max-age=300"
    return info


@public_router.get("/.well-known/jwt-vc-issuer/issuers/{org_public_id}")
def issuer_metadata(
    org_public_id: str, request: Request, response: Response, session: SystemSessionDep
) -> dict[str, Any]:
    jwks = service.published_jwks(session, org_public_id)
    response.headers["Cache-Control"] = "public, max-age=300"
    return {"issuer": service.issuer_url(_settings(request), org_public_id), "jwks": jwks}
