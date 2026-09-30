"""Token Status List (draft-ietf-oauth-status-list-21), variante JWT."""

from __future__ import annotations

import zlib
from dataclasses import dataclass
from typing import Any

from . import STATUS_LIST_TYP
from .encoding import EncodingError, b64url_decode, b64url_encode
from .jws import sign_compact
from .signing import Signer

VALID = 0x00
INVALID = 0x01
ALLOWED_BITS = (1, 2, 4, 8)
MAX_DECOMPRESSED_BYTES = 1 << 20  # 1 MiB: protección contra "zip bombs"


class StatusListError(ValueError):
    pass


class StatusList:
    """Arreglo de estados de ``bits`` bits; el índice 0 está en el bit menos
    significativo del primer byte (§4.1)."""

    def __init__(self, size: int, bits: int = 1, data: bytes | None = None) -> None:
        if bits not in ALLOWED_BITS:
            raise StatusListError("bits debe ser 1, 2, 4 u 8")
        if size <= 0 or (size * bits) % 8:
            raise StatusListError("el tamaño debe llenar bytes completos")
        n_bytes = size * bits // 8
        if data is not None and len(data) != n_bytes:
            raise StatusListError("longitud de datos inconsistente")
        self.size = size
        self.bits = bits
        self._data = bytearray(data if data is not None else n_bytes)

    def _locate(self, idx: int) -> tuple[int, int, int]:
        if not 0 <= idx < self.size:
            raise StatusListError("índice fuera de rango")
        bit_pos = idx * self.bits
        return bit_pos // 8, bit_pos % 8, (1 << self.bits) - 1

    def get(self, idx: int) -> int:
        byte, shift, mask = self._locate(idx)
        return (self._data[byte] >> shift) & mask

    def set(self, idx: int, value: int) -> None:
        byte, shift, mask = self._locate(idx)
        if not 0 <= value <= mask:
            raise StatusListError("valor de estado fuera de rango")
        self._data[byte] = (self._data[byte] & ~(mask << shift)) | (value << shift)

    def to_bytes(self) -> bytes:
        return bytes(self._data)

    def encode(self) -> dict[str, Any]:
        return {"bits": self.bits, "lst": b64url_encode(zlib.compress(self.to_bytes(), 9))}

    @classmethod
    def decode(cls, obj: Any) -> StatusList:
        if not isinstance(obj, dict):
            raise StatusListError("status_list debe ser un objeto")
        bits, lst = obj.get("bits"), obj.get("lst")
        if bits not in ALLOWED_BITS or not isinstance(lst, str):
            raise StatusListError("status_list inválido")
        try:
            compressed = b64url_decode(lst)
            decomp = zlib.decompressobj()
            raw = decomp.decompress(compressed, MAX_DECOMPRESSED_BYTES)
            if decomp.unconsumed_tail or decomp.unused_data or not decomp.eof:
                raise StatusListError("lista comprimida truncada o demasiado grande")
        except (EncodingError, zlib.error) as exc:
            raise StatusListError("lst no es DEFLATE/ZLIB válido") from exc
        if not raw:
            raise StatusListError("lista vacía")
        return cls(size=len(raw) * 8 // bits, bits=bits, data=raw)


def is_https_or_dev(url: str, dev_http_origin: str | None) -> bool:
    """``https://`` siempre; ``http://`` sólo bajo el origen local de desarrollo indicado."""
    if url.startswith("https://"):
        return True
    return (
        dev_http_origin is not None
        and dev_http_origin.startswith("http://")
        and url.startswith(dev_http_origin.rstrip("/") + "/")
    )


@dataclass(frozen=True)
class StatusReference:
    idx: int
    uri: str

    @classmethod
    def from_claims(
        cls, claims: dict[str, Any], *, dev_http_origin: str | None = None
    ) -> StatusReference:
        ref = (
            claims.get("status", {}).get("status_list")
            if isinstance(claims.get("status"), dict)
            else None
        )
        if not isinstance(ref, dict):
            raise StatusListError("la credencial no referencia un status_list")
        idx, uri = ref.get("idx"), ref.get("uri")
        if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0:
            raise StatusListError("idx inválido")
        if not isinstance(uri, str) or not is_https_or_dev(uri, dev_http_origin):
            raise StatusListError("uri de estado debe ser https")
        return cls(idx=idx, uri=uri)

    def to_claim(self) -> dict[str, Any]:
        return {"status_list": {"idx": self.idx, "uri": self.uri}}


def build_status_list_token(
    status_list: StatusList,
    *,
    uri: str,
    issuer: str,
    signer: Signer,
    iat: int,
    ttl: int = 300,
    lifetime: int = 86_400,
) -> str:
    header = {"alg": signer.alg, "typ": STATUS_LIST_TYP, "kid": signer.kid}
    payload = {
        "iss": issuer,
        "sub": uri,
        "iat": iat,
        "exp": iat + lifetime,
        "ttl": ttl,
        "status_list": status_list.encode(),
    }
    return sign_compact(header, payload, signer)
