"""``/v1/templates`` y ``/v1/credentials``."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

import segno
from fastapi import APIRouter, Depends, Header, Query, Request, Response, status
from pydantic import BaseModel, Field

from ..api.deps import EncryptorDep, SessionDep, require
from ..api.routing import TransactionalRoute
from ..authz.permissions import Permission
from ..authz.service import Principal
from ..platform.config import Settings
from . import service, templates

router = APIRouter(route_class=TransactionalRoute, prefix="/v1", tags=["issuance"])


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


# ---------------------------------------------------------------------------
# Plantillas
# ---------------------------------------------------------------------------
class TemplateCreate(BaseModel):
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    name: str = Field(min_length=1, max_length=200)


class TemplateResponse(BaseModel):
    id: uuid.UUID
    public_id: str
    slug: str
    name: str
    vct: str
    archived_at: datetime | None
    created_at: datetime


class VersionCreate(BaseModel):
    claims_schema: dict[str, Any]
    selective_disclosure: list[str] = Field(default_factory=list, max_length=50)
    validity_days: int = Field(ge=1, le=3650)
    display: dict[str, Any] = Field(default_factory=dict)


class VersionResponse(BaseModel):
    id: uuid.UUID
    template_id: uuid.UUID
    version: int
    state: str
    claims_schema: dict[str, Any]
    selective_disclosure: list[str]
    validity_days: int
    display: dict[str, Any]
    published_at: datetime | None
    created_at: datetime


def _template(t: Any, settings: Settings, org_public_id: str) -> TemplateResponse:
    return TemplateResponse(
        id=t.id,
        public_id=t.public_id,
        slug=t.slug,
        name=t.name,
        vct=templates.vct_for(settings, org_public_id, t.slug),
        archived_at=t.archived_at,
        created_at=t.created_at,
    )


def _org_public_id(session: SessionDep, principal: Principal) -> str:
    from ..organizations.service import get_organization

    return get_organization(session, principal).public_id


@router.get("/templates", response_model=list[TemplateResponse])
def list_templates(
    principal: Annotated[Principal, Depends(require(Permission.TEMPLATES_READ))],
    session: SessionDep,
    request: Request,
) -> list[TemplateResponse]:
    org = _org_public_id(session, principal)
    return [
        _template(t, _settings(request), org) for t in templates.list_templates(session, principal)
    ]


@router.post("/templates", response_model=TemplateResponse, status_code=status.HTTP_201_CREATED)
def create_template(
    body: TemplateCreate,
    principal: Annotated[Principal, Depends(require(Permission.TEMPLATES_WRITE))],
    session: SessionDep,
    request: Request,
) -> TemplateResponse:
    template = templates.create_template(session, principal, slug=body.slug, name=body.name)
    return _template(template, _settings(request), _org_public_id(session, principal))


@router.get("/templates/{template_id}/versions", response_model=list[VersionResponse])
def list_versions(
    template_id: uuid.UUID,
    principal: Annotated[Principal, Depends(require(Permission.TEMPLATES_READ))],
    session: SessionDep,
) -> list[VersionResponse]:
    return [
        VersionResponse.model_validate(v, from_attributes=True)
        for v in templates.list_versions(session, principal, template_id)
    ]


@router.post(
    "/templates/{template_id}/versions",
    response_model=VersionResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_version(
    template_id: uuid.UUID,
    body: VersionCreate,
    principal: Annotated[Principal, Depends(require(Permission.TEMPLATES_WRITE))],
    session: SessionDep,
) -> VersionResponse:
    version = templates.create_version(
        session,
        principal,
        template_id,
        claims_schema=body.claims_schema,
        selective_disclosure=body.selective_disclosure,
        validity_days=body.validity_days,
        display=body.display,
    )
    return VersionResponse.model_validate(version, from_attributes=True)


@router.post(
    "/templates/{template_id}/versions/{version_id}/publish", response_model=VersionResponse
)
def publish_version(
    template_id: uuid.UUID,
    version_id: uuid.UUID,
    principal: Annotated[Principal, Depends(require(Permission.TEMPLATES_WRITE))],
    session: SessionDep,
) -> VersionResponse:
    version = templates.publish_version(session, principal, template_id, version_id)
    session.flush()
    return VersionResponse.model_validate(version, from_attributes=True)


# ---------------------------------------------------------------------------
# Credenciales
# ---------------------------------------------------------------------------
class CredentialCreate(BaseModel):
    template: str = Field(description="slug de la plantilla", pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    claims: dict[str, Any]
    holder_reference: str | None = Field(default=None, max_length=128)
    validity_days: int | None = Field(default=None, ge=1, le=3650)


class CredentialResponse(BaseModel):
    id: uuid.UUID
    public_id: str
    state: str
    template_version_id: uuid.UUID
    vct: str
    holder_reference: str | None
    offer_expires_at: datetime
    issued_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None
    revocation_reason_code: str | None
    tx_code_attempts: int
    created_at: datetime


class OfferResponse(CredentialResponse):
    credential_offer_uri: str = Field(description="URL que sirve la oferta (contiene el offer_id)")
    offer_uri: str = Field(description="URI openid-credential-offer:// para QR o enlace")
    qr_svg: str = Field(description="QR de offer_uri como SVG (data URI)")
    tx_code: str = Field(description="Se muestra una sola vez; enviar al titular por otro canal")


class RevokeRequest(BaseModel):
    reason: str = Field(pattern="^(" + "|".join(service.REVOCATION_REASONS) + ")$")


def _credential(i: Any) -> CredentialResponse:
    return CredentialResponse.model_validate(i, from_attributes=True)


def _offer(offer: service.Offer, settings: Settings) -> OfferResponse:
    offer_uri = service.credential_offer_uri(settings, offer.issuance.offer_id)
    qr = segno.make(offer_uri, error="m")
    return OfferResponse(
        **_credential(offer.issuance).model_dump(),
        credential_offer_uri=service.offer_url(settings, offer.issuance.offer_id),
        offer_uri=offer_uri,
        qr_svg=qr.svg_data_uri(scale=4, border=2),
        tx_code=offer.tx_code,
    )


@router.post("/credentials", response_model=OfferResponse, status_code=status.HTTP_201_CREATED)
def create_credential(
    body: CredentialCreate,
    principal: Annotated[Principal, Depends(require(Permission.CREDENTIALS_ISSUE))],
    session: SessionDep,
    encryptor: EncryptorDep,
    request: Request,
    response: Response,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", max_length=255)] = None,
) -> Any:
    settings = _settings(request)
    body_hash = service.request_hash(body.model_dump(mode="json"))
    if idempotency_key:
        stored = service.find_idempotent(
            session, principal.organization_id, idempotency_key, body_hash
        )
        if stored is not None:
            response.status_code = status.HTTP_200_OK
            return stored  # misma respuesta, sin tx_code (sólo se revela una vez)
    offer = service.create_offer(
        session,
        principal,
        settings,
        encryptor,
        template_slug=body.template,
        claims=body.claims,
        holder_reference=body.holder_reference,
        validity_days=body.validity_days,
    )
    session.flush()
    payload = _offer(offer, settings)
    if idempotency_key:
        replay = payload.model_dump(mode="json")
        replay["tx_code"] = ""
        service.store_idempotent(
            session,
            principal.organization_id,
            idempotency_key,
            body_hash,
            201,
            replay,
            offer.issuance.id,
        )
    return payload


@router.get("/credentials", response_model=list[CredentialResponse])
def list_credentials(
    principal: Annotated[Principal, Depends(require(Permission.CREDENTIALS_READ))],
    session: SessionDep,
    state: Annotated[str | None, Query(pattern="^(offered|issued|offer_expired|revoked)$")] = None,
    holder_reference: Annotated[str | None, Query(max_length=128)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[CredentialResponse]:
    return [
        _credential(i)
        for i in service.list_issuances(
            session, principal, state=state, holder_reference=holder_reference, limit=limit
        )
    ]


@router.get("/credentials/{credential_id}", response_model=CredentialResponse)
def get_credential(
    credential_id: uuid.UUID,
    principal: Annotated[Principal, Depends(require(Permission.CREDENTIALS_READ))],
    session: SessionDep,
) -> CredentialResponse:
    return _credential(service.get_issuance(session, principal, credential_id))


@router.post("/credentials/{credential_id}/offer:reset", response_model=OfferResponse)
def reset_offer(
    credential_id: uuid.UUID,
    principal: Annotated[Principal, Depends(require(Permission.CREDENTIALS_ISSUE))],
    session: SessionDep,
    request: Request,
) -> OfferResponse:
    offer = service.reset_offer(session, principal, _settings(request), credential_id)
    session.flush()
    return _offer(offer, _settings(request))


@router.post("/credentials/{credential_id}/revoke", response_model=CredentialResponse)
def revoke_credential(
    credential_id: uuid.UUID,
    body: RevokeRequest,
    principal: Annotated[Principal, Depends(require(Permission.CREDENTIALS_REVOKE))],
    session: SessionDep,
) -> CredentialResponse:
    issuance = service.revoke(session, principal, credential_id, reason=body.reason)
    session.flush()
    return _credential(issuance)
