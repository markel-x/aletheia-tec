"""``POST /public/access-requests``: formulario «Empezar gratis» de la página de inicio."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

import segno
from fastapi import APIRouter, Request, status
from pydantic import BaseModel, EmailStr, Field

from ..api.deps import EncryptorDep, SystemSessionDep
from ..api.routing import TransactionalRoute
from ..authz.service import network_prefix
from . import demo, service

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


# ---------------------------------------------------------------------------
# «Pruébelo ahora»: credencial de muestra (access/demo.py)
# ---------------------------------------------------------------------------
class DemoStatus(BaseModel):
    enabled: bool


class DemoCreate(BaseModel):
    # Sólo letras, espacios y signos de nombre: lo que se ve en el pase de muestra.
    given_name: str | None = Field(
        default=None, max_length=40, pattern=r"^[^\W\d_]+(?:[ .'-]+[^\W\d_]+)*\.?$"
    )
    language: Literal["es", "en"] = "es"


class DemoOfferResponse(BaseModel):
    claim_url: str
    qr_svg: str
    tx_code: str
    member_id: str
    offer_expires_at: datetime


@router.get("/public/demo", response_model=DemoStatus)
def demo_status(request: Request, session: SystemSessionDep) -> DemoStatus:
    org = demo.demo_organization(session, request.app.state.settings)
    return DemoStatus(enabled=org is not None)


@router.post(
    "/public/demo-credential",
    response_model=DemoOfferResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_demo_credential(
    body: DemoCreate, request: Request, session: SystemSessionDep, encryptor: EncryptorDep
) -> DemoOfferResponse:
    settings = request.app.state.settings
    created = demo.create_demo_offer(
        session,
        settings,
        encryptor,
        given_name=(body.given_name or "").strip() or None,
        language=body.language,
        network=network_prefix(request.client.host if request.client else None),
    )
    issued = created.offer.issuance
    claim_url = f"{settings.public_base}/claim/{issued.offer_id.hex()}"
    return DemoOfferResponse(
        claim_url=claim_url,
        qr_svg=segno.make(claim_url, error="m").svg_data_uri(scale=4, border=2),
        tx_code=created.offer.tx_code,
        member_id=created.member_id,
        offer_expires_at=issued.offer_expires_at,
    )
