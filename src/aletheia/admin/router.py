"""``/admin``: HTML + módulos ES sin build, mismo origen, CSP estricta.

El panel es un cliente más de ``/v1``: guarda el token de sesión en
``sessionStorage`` (muere con la pestaña) y lo envía como ``Bearer``.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, RedirectResponse, Response

from ..api.routing import TransactionalRoute
from ..platform.config import Environment, Settings
from ..platform.errors import NotFound

router = APIRouter(route_class=TransactionalRoute, tags=["admin"], include_in_schema=False)

STATIC_DIR = Path(__file__).parent / "static"
_MEDIA_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript",
    ".css": "text/css",
    ".webp": "image/webp",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}
# Imágenes: no cambian entre versiones de código, así que se cachean un día.
_CACHEABLE = {".webp", ".png", ".svg", ".ico"}
CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


# La documentación carga Swagger UI desde jsDelivr (misma versión fijada que usa FastAPI) y
# Swagger aplica estilos en línea: su CSP sólo amplía eso, y sólo en /docs.
_SWAGGER_CDN = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/"
DOCS_CSP = (
    f"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' {_SWAGGER_CDN}; "
    f"script-src 'self' {_SWAGGER_CDN}; connect-src 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; form-action 'self'"
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
        headers={
            "Content-Security-Policy": CSP,
            "Cache-Control": "public, max-age=86400" if path.suffix in _CACHEABLE else "no-store",
        },
    )


@router.get("/", include_in_schema=False)
def home(request: Request) -> Response:
    """Página de inicio pública de CredoSeal. Las vistas previas al compartir el enlace
    (Open Graph) exigen URLs absolutas: se completan con el origen público."""
    settings: Settings = request.app.state.settings
    page = (STATIC_DIR / "landing.html").read_text(encoding="utf-8")
    return Response(
        page.replace("__PUBLIC_BASE__", settings.public_base),
        media_type=_MEDIA_TYPES[".html"],
        headers={"Content-Security-Policy": CSP, "Cache-Control": "no-store"},
    )


@router.get("/docs", include_in_schema=False)
def api_docs(request: Request) -> Response:
    """Referencia de la API con el estilo de CredoSeal (no en producción por ahora)."""
    settings: Settings = request.app.state.settings
    if settings.env is Environment.PRODUCTION:
        raise NotFound("Not Found")
    response = serve_static("docs.html")
    response.headers["Content-Security-Policy"] = DOCS_CSP
    return response


@router.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    """Los navegadores lo piden en la raíz aunque la página no lo declare."""
    return serve_static("favicon.ico")


@router.get("/admin")
def admin_root() -> Response:
    return RedirectResponse("/admin/", status_code=308)


@router.get("/admin/")
def admin_index() -> Response:
    return _serve("index.html")


@router.get("/admin/static/{name}")
def admin_static(name: str) -> Response:
    return _serve(name)
