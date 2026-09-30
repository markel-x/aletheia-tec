"""Creación de JWS compactos con un ``Signer`` y verificación con PyJWT."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import jwt
from jwt.exceptions import InvalidSignatureError, PyJWTError

from . import ALLOWED_ALGS
from .encoding import EncodingError, b64url_decode, b64url_encode, json_compact, json_loads_strict
from .keys import KeyFormatError, public_key_from_jwk
from .signing import Signer

MAX_JWS_BYTES = 64 * 1024


class JwsFormatError(ValueError):
    """JWS mal formado o con cabecera no admitida."""


class JwsSignatureError(ValueError):
    """La firma no verifica con la clave indicada."""


@dataclass(frozen=True)
class DecodedJws:
    header: dict[str, Any]
    payload: dict[str, Any]


def sign_compact(header: dict[str, Any], payload: dict[str, Any], signer: Signer) -> str:
    if header.get("alg") != signer.alg:
        raise JwsFormatError("alg de la cabecera no coincide con el firmante")
    signing_input = b64url_encode(json_compact(header)) + "." + b64url_encode(json_compact(payload))
    signature = signer.sign(signing_input.encode("ascii"))
    return signing_input + "." + b64url_encode(signature)


def peek(token: str) -> DecodedJws:
    """Decodifica cabecera y payload **sin verificar** (sólo para enrutar)."""
    if not isinstance(token, str) or len(token) > MAX_JWS_BYTES:
        raise JwsFormatError("JWS ausente o demasiado grande")
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise JwsFormatError("JWS compacto debe tener 3 partes no vacías")
    try:
        header = json_loads_strict(b64url_decode(parts[0]))
        payload = json_loads_strict(b64url_decode(parts[1]))
        b64url_decode(parts[2])
    except EncodingError as exc:
        raise JwsFormatError(str(exc)) from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JwsFormatError("cabecera y payload deben ser objetos JSON")
    return DecodedJws(header=header, payload=payload)


def check_header(header: dict[str, Any], *, expected_typ: str, require_kid: bool) -> None:
    alg = header.get("alg")
    if alg not in ALLOWED_ALGS:
        raise JwsFormatError(f"algoritmo no permitido: {alg!r}")
    if header.get("typ") != expected_typ:
        raise JwsFormatError(f"typ esperado {expected_typ!r}")
    if "crit" in header:
        raise JwsFormatError("cabecera crit no soportada")
    if require_kid and not isinstance(header.get("kid"), str):
        raise JwsFormatError("kid obligatorio")
    for forbidden in ("jku", "x5u"):  # nunca se siguen URLs de claves provistas por el token
        if forbidden in header:
            raise JwsFormatError(f"cabecera {forbidden} no admitida")


def verify_compact(
    token: str, public_jwk: dict[str, Any], *, expected_typ: str, require_kid: bool = True
) -> DecodedJws:
    """Verifica firma y cabecera. No valida claims temporales (lo hace el llamador)."""
    decoded = peek(token)
    check_header(decoded.header, expected_typ=expected_typ, require_kid=require_kid)
    try:
        key = public_key_from_jwk(public_jwk)
    except KeyFormatError as exc:
        raise JwsSignatureError(f"clave no utilizable: {exc}") from exc
    try:
        jwt.PyJWS().decode_complete(token, key=key, algorithms=sorted(ALLOWED_ALGS))
    except InvalidSignatureError as exc:
        raise JwsSignatureError("firma inválida") from exc
    except PyJWTError as exc:
        raise JwsFormatError(f"JWS rechazado: {exc.__class__.__name__}") from exc
    return decoded
