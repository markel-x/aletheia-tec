"""``/admin``: HTML + módulos ES sin build, mismo origen, CSP estricta.

El panel es un cliente más de ``/v1``: guarda el token de sesión en
``sessionStorage`` (muere con la pestaña) y lo envía como ``Bearer``.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse, RedirectResponse, Response

from ..api.routing import TransactionalRoute
from ..platform.errors import NotFound

router = APIRouter(route_class=TransactionalRoute, tags=["admin"], include_in_schema=False)

STATIC_DIR = Path(__file__).parent / "static"
_MEDIA_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css"}
CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


def serve_static(name: str) -> Response:
    return _serve(name)


def _serve(name: str) -> Response:
    path = (STATIC_DIR / name).resolve()
    if not path.is_relative_to(STATIC_DIR) or path.suffix not in _MEDIA_TYPES or not path.is_file():
        raise NotFound("Not Found")
    return FileResponse(
        path,
        media_type=_MEDIA_TYPES[path.suffix],
        headers={"Content-Security-Policy": CSP, "Cache-Control": "no-store"},
    )


@router.get("/admin")
def admin_root() -> Response:
    return RedirectResponse("/admin/", status_code=308)


@router.get("/admin/")
def admin_index() -> Response:
    return _serve("index.html")


@router.get("/admin/static/{name}")
def admin_static(name: str) -> Response:
    return _serve(name)
