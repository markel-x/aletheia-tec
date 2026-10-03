"""``POST /public/access-requests``: formulario «Empezar gratis» de la página de inicio."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request, status
from pydantic import BaseModel, EmailStr, Field

from ..api.deps import SystemSessionDep
from ..api.routing import TransactionalRoute
from ..authz.service import network_prefix
from . import service

router = APIRouter(route_class=TransactionalRoute, tags=["public"])


class AccessRequestCreate(BaseModel):
    organization: str = Field(min_length=1, max_length=200)
    contact_name: str = Field(min_length=1, max_length=200)
    email: EmailStr
    use_case: str = Field(min_length=1, max_length=2000)
    website: str | None = Field(default=None, max_length=300)
    language: Literal["es", "en"] = "es"
    # Campo trampa: oculto para personas; si viene relleno, es un bot.
    nickname: str | None = Field(default=None, max_length=200)


class AccessRequestReceived(BaseModel):
    received: bool = True


@router.post(
    "/public/access-requests",
    response_model=AccessRequestReceived,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_access_request(
    body: AccessRequestCreate, request: Request, session: SystemSessionDep
) -> AccessRequestReceived:
    if body.nickname:  # bot: misma respuesta, nada guardado
        return AccessRequestReceived()
    service.create_request(
        session,
        organization=body.organization.strip(),
        contact_name=body.contact_name.strip(),
        email=str(body.email),
        use_case=body.use_case.strip(),
        website=(body.website or "").strip() or None,
        language=body.language,
        network=network_prefix(request.client.host if request.client else None),
    )
    return AccessRequestReceived()
