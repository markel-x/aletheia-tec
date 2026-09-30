"""``/v1/auth/*`` y ``/v1/api-clients``."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, EmailStr, Field

from ..api.deps import PrincipalDep, SessionDep, SystemSessionDep, require
from ..api.routing import TransactionalRoute
from . import service
from .permissions import API_CLIENT_PERMISSIONS, Permission

router = APIRouter(route_class=TransactionalRoute, prefix="/v1", tags=["auth"])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=1024)
    organization: str | None = Field(default=None, description="public_id (org_…) si hay varias")


class LoginResponse(BaseModel):
    token: str
    expires_at: datetime
    organization_id: uuid.UUID
    role: str
    permissions: list[str]


class MeResponse(BaseModel):
    actor_type: str
    actor_id: uuid.UUID
    organization_id: uuid.UUID
    role: str | None
    permissions: list[str]


class ApiClientCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    permissions: list[str] = Field(min_length=1, max_length=len(API_CLIENT_PERMISSIONS))
    expires_at: datetime | None = None


class ApiClientResponse(BaseModel):
    id: uuid.UUID
    name: str
    key_prefix: str
    permissions: list[str]
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime


class ApiClientCreated(ApiClientResponse):
    key: str = Field(description="Clave completa; se muestra una sola vez")


def _client_response(client: object) -> ApiClientResponse:
    return ApiClientResponse.model_validate(client, from_attributes=True)


@router.post("/auth/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request, session: SystemSessionDep) -> LoginResponse:
    token, principal, expires_at = service.login(
        session,
        email=body.email,
        password=body.password,
        organization_public_id=body.organization,
        client_host=request.client.host if request.client else None,
    )
    return LoginResponse(
        token=token,
        expires_at=expires_at,
        organization_id=principal.organization_id,
        role=principal.role or "",
        permissions=list(principal.permission_names),
    )


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(principal: PrincipalDep, session: SessionDep) -> None:
    service.logout(session, principal)


@router.get("/auth/me", response_model=MeResponse)
def me(principal: PrincipalDep) -> MeResponse:
    return MeResponse(
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        organization_id=principal.organization_id,
        role=principal.role,
        permissions=list(principal.permission_names),
    )


@router.get("/api-clients", response_model=list[ApiClientResponse])
def list_api_clients(
    principal: Annotated[service.Principal, Depends(require(Permission.API_CLIENTS_MANAGE))],
    session: SessionDep,
) -> list[ApiClientResponse]:
    return [_client_response(c) for c in service.list_api_clients(session, principal)]


@router.post("/api-clients", response_model=ApiClientCreated, status_code=status.HTTP_201_CREATED)
def create_api_client(
    body: ApiClientCreate,
    principal: Annotated[service.Principal, Depends(require(Permission.API_CLIENTS_MANAGE))],
    session: SessionDep,
) -> ApiClientCreated:
    client, key = service.create_api_client(
        session,
        principal,
        name=body.name,
        permissions=body.permissions,
        expires_at=body.expires_at,
    )
    session.flush()
    return ApiClientCreated(**_client_response(client).model_dump(), key=key)


@router.delete("/api-clients/{client_id}", response_model=ApiClientResponse)
def revoke_api_client(
    client_id: uuid.UUID,
    principal: Annotated[service.Principal, Depends(require(Permission.API_CLIENTS_MANAGE))],
    session: SessionDep,
) -> ApiClientResponse:
    return _client_response(service.revoke_api_client(session, principal, client_id))
