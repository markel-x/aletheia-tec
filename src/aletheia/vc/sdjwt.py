"""SD-JWT (RFC 9901) y SD-JWT VC (draft-ietf-oauth-sd-jwt-vc-19).

Emisión, análisis, reconstrucción de claims, presentación y Key Binding JWT.
Sólo se implementa la serialización; los primitivos provienen de ``hashlib``,
``secrets`` y del ``Signer`` (ADR-0003).
"""

from __future__ import annotations

import copy
import hashlib
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from . import KB_JWT_TYP, SD_ALG, SD_JWT_VC_TYP
from .encoding import EncodingError, b64url_decode, b64url_encode, json_compact, json_loads_strict
from .jws import sign_compact
from .signing import Signer

MAX_DISCLOSURES = 200
MAX_SERIALIZED_BYTES = 128 * 1024
MAX_DEPTH = 8

# Claims que SD-JWT VC prohíbe hacer selectivamente divulgables (§3.2.2), más
# ``iat`` (política más estricta de Aletheia para su propia emisión) y nombres
# reservados por RFC 9901.
NEVER_SELECTIVE = frozenset(
    {
        "iss",
        "iat",
        "nbf",
        "exp",
        "cnf",
        "vct",
        "vct#integrity",
        "aka_vcts",
        "status",
        "_sd",
        "_sd_alg",
        "...",
    }
)
_RESERVED_NAMES = frozenset({"_sd", "..."})


class SdJwtError(ValueError):
    """SD-JWT mal formado o inconsistente. ``code`` es estable para la API."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _digest(disclosure: str) -> str:
    return b64url_encode(hashlib.sha256(disclosure.encode("ascii")).digest())


def _salt() -> str:
    return b64url_encode(secrets.token_bytes(16))


@dataclass(frozen=True)
class Disclosure:
    encoded: str
    salt: str
    name: str | None  # None para elementos de array
    value: Any

    @property
    def digest(self) -> str:
        return _digest(self.encoded)


def create_disclosure(name: str | None, value: Any, *, salt: str | None = None) -> Disclosure:
    salt = salt or _salt()
    content: list[Any] = [salt, value] if name is None else [salt, name, value]
    return Disclosure(b64url_encode(json_compact(content)), salt, name, value)


# ---------------------------------------------------------------------------
# Emisión
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IssuedSdJwt:
    serialized: str  # <JWT>~<D1>~...~<Dn>~
    issuer_jwt: str
    disclosures: tuple[Disclosure, ...]


def issue_sd_jwt_vc(
    payload: dict[str, Any],
    *,
    selectively_disclosable: Iterable[str],
    signer: Signer,
    decoys: int = 3,
) -> IssuedSdJwt:
    """Firma un SD-JWT VC.

    ``selectively_disclosable`` contiene rutas con punto (``"given_name"``,
    ``"course.grade"``). Si se indican un objeto y una propiedad interna, se
    aplica divulgación recursiva (primero la más profunda).
    """
    body = copy.deepcopy(payload)
    for required in ("iss", "vct", "iat"):
        if required not in body:
            raise SdJwtError("invalid_payload", f"falta el claim {required!r}")
    if "_sd" in body or "_sd_alg" in body:
        raise SdJwtError("invalid_payload", "el payload no debe traer _sd/_sd_alg")

    paths = sorted(set(selectively_disclosable), key=lambda p: (-p.count("."), p))
    finalized: set[int] = set()

    def finalize(node: Any, n_decoys: int) -> None:
        """Añade señuelos y ordena ``_sd`` (RFC 9901 §4.2.4-4.2.5) antes de que el
        objeto quede congelado dentro de una disclosure o del JWT firmado."""
        if isinstance(node, dict):
            if id(node) not in finalized and ("_sd" in node or n_decoys):
                sd = node.setdefault("_sd", [])
                sd.extend(_digest(_salt()) for _ in range(n_decoys))
                sd.sort()  # orden alfabético: oculta el orden original
                finalized.add(id(node))
            for key, value in node.items():
                if key != "_sd":
                    finalize(value, 0)
        elif isinstance(node, list):
            for item in node:
                finalize(item, 0)

    nested_decoys = 1 if decoys else 0
    disclosures: list[Disclosure] = []
    for path in paths:
        parts = path.split(".")
        if not all(parts) or len(parts) > MAX_DEPTH:
            raise SdJwtError("invalid_sd_path", f"ruta inválida: {path!r}")
        if parts[0] in NEVER_SELECTIVE:
            raise SdJwtError("invalid_sd_path", f"{path!r} no puede ser divulgable")
        if parts[-1] in _RESERVED_NAMES:
            raise SdJwtError("invalid_sd_path", f"nombre reservado en {path!r}")
        parent: Any = body
        for segment in parts[:-1]:
            parent = parent.get(segment) if isinstance(parent, dict) else None
        if not isinstance(parent, dict) or parts[-1] not in parent:
            continue  # claim opcional ausente: nada que ocultar
        value = parent.pop(parts[-1])
        if isinstance(value, dict) and "_sd" in value:
            finalize(value, nested_decoys)
        else:
            finalize(value, 0)
        disclosure = create_disclosure(parts[-1], value)
        parent.setdefault("_sd", []).append(disclosure.digest)
        disclosures.append(disclosure)

    for key, value in body.items():
        if key != "_sd" and isinstance(value, dict) and "_sd" in value:
            finalize(value, nested_decoys)
    finalize(body, decoys)
    body["_sd_alg"] = SD_ALG

    header = {"alg": signer.alg, "typ": SD_JWT_VC_TYP, "kid": signer.kid}
    issuer_jwt = sign_compact(header, body, signer)
    serialized = issuer_jwt + "~" + "".join(d.encoded + "~" for d in disclosures)
    return IssuedSdJwt(serialized, issuer_jwt, tuple(disclosures))


# ---------------------------------------------------------------------------
# Análisis y reconstrucción
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParsedSdJwt:
    issuer_jwt: str
    disclosures: tuple[str, ...]
    kb_jwt: str | None

    @property
    def without_kb(self) -> str:
        return self.issuer_jwt + "~" + "".join(d + "~" for d in self.disclosures)


def parse(serialized: str) -> ParsedSdJwt:
    if not isinstance(serialized, str) or not serialized:
        raise SdJwtError("malformed", "presentación vacía")
    if len(serialized) > MAX_SERIALIZED_BYTES:
        raise SdJwtError("too_large", "presentación demasiado grande")
    parts = serialized.split("~")
    if len(parts) < 2:
        raise SdJwtError("malformed", "falta el separador ~")
    issuer_jwt, *disclosures, last = parts
    if not issuer_jwt or any(not d for d in disclosures):
        raise SdJwtError("malformed", "segmento vacío")
    if len(disclosures) > MAX_DISCLOSURES:
        raise SdJwtError("too_large", "demasiadas disclosures")
    return ParsedSdJwt(issuer_jwt, tuple(disclosures), last or None)


def decode_disclosure(encoded: str) -> Disclosure:
    try:
        content = json_loads_strict(b64url_decode(encoded))
    except EncodingError as exc:
        raise SdJwtError("invalid_disclosure", "disclosure mal codificada") from exc
    if not isinstance(content, list) or len(content) not in (2, 3):
        raise SdJwtError("invalid_disclosure", "disclosure debe ser un array de 2 o 3")
    if not isinstance(content[0], str):
        raise SdJwtError("invalid_disclosure", "salt debe ser string")
    if len(content) == 2:
        return Disclosure(encoded, content[0], None, content[1])
    name = content[1]
    if not isinstance(name, str) or name in _RESERVED_NAMES:
        raise SdJwtError("invalid_disclosure", "nombre de claim inválido")
    return Disclosure(encoded, content[0], name, content[2])


@dataclass
class Reconstruction:
    claims: dict[str, Any]
    # ruta (tupla de segmentos) de cada disclosure, por digest
    paths: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def disclosed_paths(self) -> set[str]:
        return {".".join(p) for p in self.paths.values()}


def reconstruct(payload: dict[str, Any], disclosures: Iterable[str]) -> Reconstruction:
    """Procesa ``_sd`` y ``{"...": d}`` según RFC 9901 §7.1 (pasos 3–5)."""
    alg = payload.get("_sd_alg", SD_ALG)
    if alg != SD_ALG:
        raise SdJwtError("unsupported_sd_alg", f"_sd_alg no soportado: {alg!r}")

    by_digest: dict[str, Disclosure] = {}
    for encoded in disclosures:
        disclosure = decode_disclosure(encoded)
        digest = disclosure.digest
        if digest in by_digest:
            raise SdJwtError("duplicate_disclosure", "disclosure repetida")
        by_digest[digest] = disclosure

    seen: set[str] = set()
    result = Reconstruction(claims={})

    def use(digest: Any) -> Disclosure | None:
        if not isinstance(digest, str):
            raise SdJwtError("malformed", "digest debe ser string")
        if digest in seen:
            raise SdJwtError("duplicate_digest", "digest referenciado más de una vez")
        seen.add(digest)
        return by_digest.get(digest)

    def walk(node: Any, path: tuple[str, ...], depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise SdJwtError("too_deep", "anidamiento excesivo")
        if isinstance(node, dict):
            out: dict[str, Any] = {}
            for key, value in node.items():
                if key == "_sd_alg" and depth > 0:
                    raise SdJwtError("malformed", "_sd_alg sólo se admite en el nivel superior")
                if key in ("_sd", "_sd_alg"):
                    continue
                out[key] = walk(value, (*path, key), depth + 1)
            sd = node.get("_sd", [])
            if not isinstance(sd, list):
                raise SdJwtError("malformed", "_sd debe ser un array")
            for digest in sd:
                disclosure = use(digest)
                if disclosure is None:
                    continue  # no divulgado o señuelo
                if disclosure.name is None:
                    raise SdJwtError("invalid_disclosure", "disclosure de array usada en objeto")
                if disclosure.name in out:
                    raise SdJwtError("claim_conflict", "la disclosure sobrescribe un claim")
                sub_path = (*path, disclosure.name)
                result.paths[disclosure.digest] = sub_path
                out[disclosure.name] = walk(disclosure.value, sub_path, depth + 1)
            return out
        if isinstance(node, list):
            items: list[Any] = []
            for index, item in enumerate(node):
                if isinstance(item, dict) and set(item) == {"..."}:
                    disclosure = use(item["..."])
                    if disclosure is None:
                        continue
                    if disclosure.name is not None:
                        raise SdJwtError(
                            "invalid_disclosure", "disclosure de objeto usada en array"
                        )
                    sub_path = (*path, str(index))
                    result.paths[disclosure.digest] = sub_path
                    items.append(walk(disclosure.value, sub_path, depth + 1))
                else:
                    items.append(walk(item, (*path, str(index)), depth + 1))
            return items
        return node

    claims = walk(payload, (), 0)
    unused = set(by_digest) - set(result.paths)
    if unused:
        raise SdJwtError("unreferenced_disclosure", "disclosure no referenciada por el emisor")
    result.claims = claims
    return result


# ---------------------------------------------------------------------------
# Presentación (lado del titular) y Key Binding
# ---------------------------------------------------------------------------


def sd_hash(presentation_without_kb: str) -> str:
    return b64url_encode(hashlib.sha256(presentation_without_kb.encode("ascii")).digest())


def select_disclosures(
    serialized: str, issuer_payload: dict[str, Any], disclose: Iterable[str]
) -> ParsedSdJwt:
    """Conserva las disclosures pedidas y sus ancestros necesarios."""
    parsed = parse(serialized)
    rec = reconstruct(issuer_payload, parsed.disclosures)
    wanted = {tuple(p.split(".")) for p in disclose}

    def needed(path: tuple[str, ...]) -> bool:
        return any(w[: len(path)] == path for w in wanted)

    kept = tuple(d for d in parsed.disclosures if needed(rec.paths[_digest(d)]))
    return ParsedSdJwt(parsed.issuer_jwt, kept, None)


def create_presentation(
    serialized: str,
    issuer_payload: dict[str, Any],
    *,
    disclose: Iterable[str],
    holder_signer: Signer | None,
    aud: str | None = None,
    nonce: str | None = None,
    iat: int | None = None,
) -> str:
    selected = select_disclosures(serialized, issuer_payload, disclose)
    base = selected.without_kb
    if holder_signer is None:
        return base
    if not aud or not nonce or iat is None:
        raise SdJwtError("invalid_request", "KB-JWT requiere aud, nonce e iat")
    kb = sign_compact(
        {"alg": holder_signer.alg, "typ": KB_JWT_TYP},
        {"iat": iat, "aud": aud, "nonce": nonce, "sd_hash": sd_hash(base)},
        holder_signer,
    )
    return base + kb
