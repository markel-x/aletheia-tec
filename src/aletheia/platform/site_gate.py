"""Acceso restringido temporal al sitio (HTTP Basic) mientras no está abierto al público.

Con ``ALETHEIA_SITE_BASIC_AUTH=usuario:contraseña`` las páginas que una persona puede navegar
(inicio, panel, páginas del titular y del emisor, documentación) piden usuario y contraseña, y
todas las respuestas llevan ``X-Robots-Tag: noindex``. Quedan abiertos los endpoints que usan
máquinas y no pueden responder a un diálogo del navegador: salud (ALB/ECS), API ``/v1`` (con su
propio Authorization), OpenID4VCI/VP, metadatos, listas de estado y el logo que descarga Google.
"""

from __future__ import annotations

import base64
import binascii
import hmac

from starlette.types import ASGIApp, Message, Receive, Scope, Send

# Páginas para personas (y sus recursos estáticos).
_GATED_PREFIXES = (
    "/admin",
    "/docs",
    "/openapi.json",
    "/claim/",
    "/claim-info/",
    "/issuers/",
    "/issuer-info/",
)
_GATED_EXACT = frozenset({"/", "/v", "/robots.txt"})


def is_gated(path: str) -> bool:
    return path in _GATED_EXACT or path.startswith(_GATED_PREFIXES)


class SiteGateMiddleware:
    def __init__(self, app: ASGIApp, credentials: str, realm: str = "CredoSeal") -> None:
        self.app = app
        self._expected = credentials.encode()
        self._challenge = f'Basic realm="{realm}", charset="UTF-8"'.encode()

    def _authorized(self, scope: Scope) -> bool:
        for name, value in scope.get("headers", []):
            if name == b"authorization" and value[:6].lower() == b"basic ":
                try:
                    supplied = base64.b64decode(value[6:].strip(), validate=True)
                except (binascii.Error, ValueError):
                    return False
                return hmac.compare_digest(supplied, self._expected)
        return False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_noindex(message: Message) -> None:
            if message["type"] == "http.response.start":
                message["headers"] = [
                    *message.get("headers", []),
                    (b"x-robots-tag", b"noindex, nofollow"),
                ]
            await send(message)

        if is_gated(scope["path"]) and not self._authorized(scope):
            await send_noindex(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"www-authenticate", self._challenge),
                        (b"content-type", b"text/plain; charset=utf-8"),
                        (b"cache-control", b"no-store"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b"Authentication required"})
            return
        await self.app(scope, receive, send_noindex)
