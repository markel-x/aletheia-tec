"""Páginas y endpoints públicos del titular y del verificador ocasional:

- ``GET /claim/{offer_id}``: página para recibir la credencial (Apple Wallet u OID4VCI).
- ``GET /claim-info/{offer_id}``: datos de la oferta para esa página.
- ``POST /claim/{offer_id}/apple-pass``: canje con ``tx_code`` → ``.pkpass``.
- ``GET /v``: página de verificación del QR del pase (el token viaja en el fragmento).
- ``POST /public/pass-verifications``: verificación en vivo del token.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Any
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel, Field

from ..admin.router import serve_static
from ..api.deps import BackendDep, EncryptorDep, SystemSessionDep
from ..api.routing import TransactionalRoute
from ..authz.service import network_prefix
from ..issuance.service import OidError, offer_id_from_url
from ..platform import ratelimit
from ..platform.config import Settings
from ..platform.errors import NotFound
from . import service
from .builder import PKPASS_MEDIA_TYPE
from .signing import PassSigner

router = APIRouter(route_class=TransactionalRoute, tags=["holder"])

VERIFY_RATE_LIMIT = 300
VERIFY_RATE_WINDOW = timedelta(minutes=15)


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def _signer(request: Request) -> PassSigner | None:
    signer: PassSigner | None = request.app.state.pass_signer
    return signer


def _offer_id(value: str) -> bytes:
    raw = offer_id_from_url(value)
    if raw is None:
        raise NotFound("Offer not found")
    return raw


@router.get("/claim/{offer_id}", include_in_schema=False)
def claim_page(offer_id: str) -> Response:
    _offer_id(offer_id)
    return serve_static("claim.html")


@router.get("/v", include_in_schema=False)
def verify_page() -> Response:
    return serve_static("verify.html")


@router.get("/claim-info/{offer_id}")
def claim_info(offer_id: str, request: Request, session: SystemSessionDep) -> dict[str, Any]:
    return service.claim_info(session, _settings(request), _offer_id(offer_id), _signer(request))


@router.post("/claim/{offer_id}/apple-pass", response_class=Response)
def apple_pass(
    offer_id: str,
    request: Request,
    session: SystemSessionDep,
    backend: BackendDep,
    encryptor: EncryptorDep,
    tx_code: Annotated[str, Form(max_length=16)] = "",
) -> Response:
    raw = _offer_id(offer_id)
    signer = _signer(request)
    if signer is None:
        raise NotFound("Apple Wallet passes are not enabled")
    try:
        pkpass, serial = service.redeem_for_pass(
            session,
            _settings(request),
            backend,
            encryptor,
            signer,
            offer_id=raw,
            tx_code=tx_code.strip(),
        )
    except OidError as exc:
        session.rollback()  # los intentos fallidos ya se confirmaron en check_offer_code
        code = "invalid_tx_code" if "tx_code" in exc.description else "unavailable"
        if "locked" in exc.description:
            code = "locked"
        return RedirectResponse(f"/claim/{offer_id}?error={quote(code)}", status_code=303)
    return Response(
        content=pkpass,
        media_type=PKPASS_MEDIA_TYPE,
        headers={
            "Content-Disposition": f'attachment; filename="{serial}.pkpass"',
            "Cache-Control": "no-store",
        },
    )


class PassVerification(BaseModel):
    token: str = Field(min_length=1, max_length=8 * 1024)


@router.post("/public/pass-verifications")
def verify_pass(
    body: PassVerification, request: Request, session: SystemSessionDep, backend: BackendDep
) -> dict[str, Any]:
    prefix = network_prefix(request.client.host if request.client else None)
    if prefix:
        ratelimit.hit(
            session, f"pass-verify:{prefix}", limit=VERIFY_RATE_LIMIT, window=VERIFY_RATE_WINDOW
        )
    return service.verify_pass_token(session, _settings(request), backend, body.token)
