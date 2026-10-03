"""Páginas y endpoints públicos del titular y del verificador ocasional:

- ``GET /claim/{offer_id}``: página para recibir la credencial (Apple Wallet u OID4VCI).
- ``GET /claim-info/{offer_id}``: datos de la oferta para esa página.
- ``POST /claim/{offer_id}/apple-pass``: canje con ``tx_code`` → ``.pkpass``.
- ``POST /claim/{offer_id}/google-pass``: canje con ``tx_code`` → enlace de Google Wallet (JSON:
  la página navega con JS porque la CSP ``form-action 'self'`` bloquea redirigir a Google).
- ``GET /wallet/logo.png``: logo del pase de Google (Google lo descarga por URL).
- ``GET /v``: página de verificación del QR del pase (el token viaja en el fragmento).
- ``POST /public/pass-verifications``: verificación en vivo del token.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Any
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from ..api.deps import BackendDep, EncryptorDep, SystemSessionDep
from ..api.routing import TransactionalRoute
from ..authz.service import network_prefix
from ..issuance.service import OidError, offer_id_from_url
from ..platform import ratelimit
from ..platform.config import Settings
from ..platform.errors import NotFound
from . import service
from .builder import PKPASS_MEDIA_TYPE
from .google import GoogleWallet, GoogleWalletError
from .images import mark_png
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


def _google(request: Request) -> GoogleWallet | None:
    wallet: GoogleWallet | None = getattr(request.app.state, "google_wallet", None)
    return wallet


def _redeem_error_code(exc: OidError) -> str:
    if "locked" in exc.description:
        return "locked"
    return "invalid_tx_code" if "tx_code" in exc.description else "unavailable"


def _offer_id(value: str) -> bytes:
    raw = offer_id_from_url(value)
    if raw is None:
        raise NotFound("Offer not found")
    return raw


@router.get("/claim-info/{offer_id}")
def claim_info(offer_id: str, request: Request, session: SystemSessionDep) -> dict[str, Any]:
    return service.claim_info(
        session, _settings(request), _offer_id(offer_id), _signer(request), _google(request)
    )


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
        code = _redeem_error_code(exc)
        return RedirectResponse(f"/claim/{offer_id}?error={quote(code)}", status_code=303)
    return Response(
        content=pkpass,
        media_type=PKPASS_MEDIA_TYPE,
        headers={
            "Content-Disposition": f'attachment; filename="{serial}.pkpass"',
            "Cache-Control": "no-store",
        },
    )


@router.post("/claim/{offer_id}/google-pass")
def google_pass(
    offer_id: str,
    request: Request,
    session: SystemSessionDep,
    backend: BackendDep,
    encryptor: EncryptorDep,
    tx_code: Annotated[str, Form(max_length=16)] = "",
) -> JSONResponse:
    raw = _offer_id(offer_id)
    wallet = _google(request)
    if wallet is None:
        raise NotFound("Google Wallet passes are not enabled")
    try:
        save_url = service.redeem_for_google_pass(
            session,
            _settings(request),
            backend,
            encryptor,
            wallet,
            offer_id=raw,
            tx_code=tx_code.strip(),
        )
    except OidError as exc:
        session.rollback()  # los intentos fallidos ya se confirmaron en check_offer_code
        return JSONResponse({"error": _redeem_error_code(exc)}, status_code=400)
    except GoogleWalletError:
        session.rollback()  # sin pase en Google no se emite: la oferta sigue disponible
        return JSONResponse({"error": "google_unavailable"}, status_code=502)
    return JSONResponse({"save_url": save_url}, headers={"Cache-Control": "no-store"})


@router.get("/wallet/logo.png", include_in_schema=False)
def wallet_logo() -> Response:
    return Response(
        mark_png(120, background=(20, 27, 32)),  # Google lo recorta en círculo: fondo opaco
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=86400"},
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
