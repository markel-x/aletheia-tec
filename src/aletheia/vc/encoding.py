"""Codificación base64url y JSON compacto."""

from __future__ import annotations

import base64
import json
from typing import Any


class EncodingError(ValueError):
    """Entrada mal codificada (base64url o JSON)."""


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    if not isinstance(data, str) or any(c in data for c in "=+/ \n\t"):
        raise EncodingError("base64url inválido")
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except (ValueError, TypeError) as exc:  # binascii.Error hereda de ValueError
        raise EncodingError("base64url inválido") from exc


def json_compact(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode(
        "utf-8"
    )


def json_loads_strict(data: bytes | str) -> Any:
    """Carga JSON rechazando claves duplicadas y valores no finitos."""

    def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise EncodingError(f"clave JSON duplicada: {key!r}")
            out[key] = value
        return out

    def _reject_constant(name: str) -> Any:
        raise EncodingError(f"valor JSON no permitido: {name}")

    try:
        return json.loads(data, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except EncodingError:
        raise
    except (
        RecursionError
    ) as exc:  # anidamiento hostil: no debe escapar como excepción no controlada
        raise EncodingError("JSON demasiado anidado") from exc
    except (ValueError, UnicodeDecodeError) as exc:
        raise EncodingError("JSON inválido") from exc
