"""Conversión entre claves EC P-256 y JWK, y huellas RFC 7638."""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from .encoding import b64url_decode, b64url_encode, json_compact

_P256_COORD_LEN = 32


class KeyFormatError(ValueError):
    """JWK con formato, curva o tamaño no admitidos."""


def public_jwk_from_key(key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    if not isinstance(key.curve, ec.SECP256R1):
        raise KeyFormatError("sólo se admite P-256")
    numbers = key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(numbers.x.to_bytes(_P256_COORD_LEN, "big")),
        "y": b64url_encode(numbers.y.to_bytes(_P256_COORD_LEN, "big")),
    }


def public_key_from_jwk(jwk: Any) -> ec.EllipticCurvePublicKey:
    """Valida estrictamente un JWK público EC P-256 y devuelve la clave.

    Rechaza JWK con componente privado ``d`` (nunca debe circular una clave
    privada) y puntos fuera de la curva (lo comprueba ``cryptography``).
    """
    if not isinstance(jwk, dict):
        raise KeyFormatError("JWK debe ser un objeto")
    if "d" in jwk:
        raise KeyFormatError("el JWK contiene material privado")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise KeyFormatError("se requiere kty=EC, crv=P-256")
    try:
        x = b64url_decode(jwk["x"])
        y = b64url_decode(jwk["y"])
    except (KeyError, ValueError) as exc:
        raise KeyFormatError("coordenadas x/y inválidas") from exc
    if len(x) != _P256_COORD_LEN or len(y) != _P256_COORD_LEN:
        raise KeyFormatError("longitud de coordenadas incorrecta")
    try:
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        ).public_key()
    except ValueError as exc:
        raise KeyFormatError("el punto no pertenece a la curva") from exc


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """Huella JWK SHA-256 (RFC 7638) de una clave EC."""
    required = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    return b64url_encode(hashlib.sha256(json_compact(required)).digest())
