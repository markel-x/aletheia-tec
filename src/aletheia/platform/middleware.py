"""Middleware HTTP: request-id, access log y cabeceras de seguridad."""

from __future__ import annotations

import ipaddress
import logging
import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

from .logging import request_id_var

access_log = logging.getLogger("aletheia.access")

REQUEST_ID_HEADER = "X-Request-ID"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming = request.headers.get(REQUEST_ID_HEADER, "")
        request_id = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers[REQUEST_ID_HEADER] = request_id
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        request_id_var.set(request_id)
        access_log.info(
            "request",
            extra={
                "method": request.method,
                "path": request.url.path,  # sin query string: puede llevar tokens
                "status": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            },
        )
        return response


class ClientIPMiddleware:
    """IP del visitante desde la cabecera de la CDN (``CloudFront-Viewer-Address: ip:puerto``).

    Detrás de CloudFront, el ALB ve la IP del borde de CloudFront, compartida por miles de
    visitantes: los límites por red la necesitan real. Sólo se instala si el ALB rechaza lo que
    no viene de CloudFront (ver ``Settings.client_ip_header``).
    """

    def __init__(self, app: ASGIApp, header: str) -> None:
        self.app = app
        self.header = header.lower().encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            for name, value in scope.get("headers", []):
                if name == self.header:
                    host = viewer_ip(value.decode("latin1"))
                    if host:
                        scope["client"] = (host, 0)
                    break
        await self.app(scope, receive, send)


def viewer_ip(value: str) -> str | None:
    """``198.51.100.10:46532`` o ``2001:db8::1:46532`` → la IP (sin el puerto final)."""
    host, sep, port = value.strip().rpartition(":")
    if not sep or not port.isdigit():
        return None
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        return None
