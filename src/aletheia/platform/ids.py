"""Identificadores y secretos (docs/03, convenciones).

- ``uuid7()``: UUID v7 (ordenable por tiempo) generado en la aplicación.
- ``public_id(prefix)``: ``prefix_`` + 22 caracteres base62 aleatorios (≈131 bits).
- Tokens de sesión ``st_…`` y claves de API ``ak_XXXXXXXX_…``: el secreto tiene
  256 bits y sólo se almacena su SHA-256 (alta entropía → sin KDF lento).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import string
import time
import uuid

_BASE62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
PUBLIC_ID_LEN = 22
SESSION_TOKEN_PREFIX = "st_"  # noqa: S105 - prefijo, no secreto
API_KEY_PREFIX = "ak_"
API_KEY_ID_LEN = 8

_API_KEY_RE = re.compile(r"^ak_([0-9A-Za-z]{8})_([A-Za-z0-9_-]{43})$")
_SESSION_TOKEN_RE = re.compile(r"^st_([A-Za-z0-9_-]{43})$")


def uuid7() -> uuid.UUID:
    """UUID v7 (RFC 9562): 48 bits de milisegundos + 74 bits aleatorios."""
    ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    value = (
        (ms << 80)
        | (0x7 << 76)
        | ((rand >> 64) & 0x0FFF) << 64
        | (0b10 << 62)
        | (rand & ((1 << 62) - 1))
    )
    return uuid.UUID(int=value)


def base62(length: int) -> str:
    return "".join(secrets.choice(_BASE62) for _ in range(length))


def public_id(prefix: str) -> str:
    return f"{prefix}_{base62(PUBLIC_ID_LEN)}"


def new_secret() -> str:
    """256 bits en base64url sin relleno (43 caracteres)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


def sha256(value: str | bytes) -> bytes:
    data = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(data).digest()


def constant_time_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def new_session_token() -> tuple[str, bytes]:
    """Devuelve (token para el cliente, hash para la base)."""
    secret = new_secret()
    return f"{SESSION_TOKEN_PREFIX}{secret}", sha256(secret)


def parse_session_token(token: str) -> bytes | None:
    m = _SESSION_TOKEN_RE.match(token)
    return sha256(m.group(1)) if m else None


def new_api_key() -> tuple[str, str, bytes]:
    """Devuelve (clave completa para el cliente, key_prefix, hash del secreto)."""
    key_prefix = f"{API_KEY_PREFIX}{base62(API_KEY_ID_LEN)}"
    secret = new_secret()
    return f"{key_prefix}_{secret}", key_prefix, sha256(secret)


def parse_api_key(token: str) -> tuple[str, bytes] | None:
    """Devuelve (key_prefix, hash del secreto) o ``None`` si el formato no es válido."""
    m = _API_KEY_RE.match(token)
    if not m:
        return None
    return f"{API_KEY_PREFIX}{m.group(1)}", sha256(m.group(2))
