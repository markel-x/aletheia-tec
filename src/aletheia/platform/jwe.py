"""JWE compacto con ECDH-ES (acuerdo directo) y AES-GCM (RFC 7516, RFC 7518 §4.6, §5.3).

Alcance mínimo para respuestas OID4VP ``direct_post.jwt`` (ADR-0015):

- ``alg``: sólo ``ECDH-ES`` sobre P-256 (sin key wrap: la clave derivada es la CEK).
- ``enc``: ``A128GCM`` o ``A256GCM``.
- Sin ``zip``, sin ``crit``; cabecera protegida como AAD.

``encrypt_compact`` existe para pruebas y herramientas; la aplicación sólo descifra.
La interoperabilidad se comprueba con una implementación independiente (``jose``
en ``interop/run.mjs``) y la derivación con el vector del Apéndice C de RFC 7518.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..vc.encoding import EncodingError, b64url_decode, b64url_encode
from ..vc.keys import KeyFormatError, public_jwk_from_key, public_key_from_jwk

ALG = "ECDH-ES"
ENC_KEY_BITS = {"A128GCM": 128, "A256GCM": 256}
MAX_JWE_BYTES = 128 * 1024


class JweError(ValueError):
    pass


@dataclass(frozen=True)
class DecryptedJwe:
    header: dict[str, Any]
    plaintext: bytes


def _len_prefixed(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def concat_kdf(z: bytes, enc: str, apu: bytes, apv: bytes) -> bytes:
    """Concat KDF de NIST SP 800-56A con SHA-256, en la forma de RFC 7518 §4.6.2."""
    bits = ENC_KEY_BITS[enc]
    other_info = (
        _len_prefixed(enc.encode("ascii"))
        + _len_prefixed(apu)
        + _len_prefixed(apv)
        + struct.pack(">I", bits)
    )
    # keydatalen ≤ 256 bits = un bloque SHA-256: basta la ronda 1.
    return hashlib.sha256(struct.pack(">I", 1) + z + other_info).digest()[: bits // 8]


def _decode_part(value: str, name: str) -> bytes:
    try:
        return b64url_decode(value)
    except EncodingError as exc:
        raise JweError(f"{name} no es base64url") from exc


def decrypt_compact(jwe: str, private_key: ec.EllipticCurvePrivateKey) -> DecryptedJwe:
    if not isinstance(jwe, str) or len(jwe) > MAX_JWE_BYTES:
        raise JweError("JWE ausente o demasiado grande")
    parts = jwe.split(".")
    if len(parts) != 5:
        raise JweError("JWE compacto debe tener 5 partes")
    protected_b64, encrypted_key, iv_b64, ct_b64, tag_b64 = parts
    try:
        header = json.loads(_decode_part(protected_b64, "cabecera"))
    except ValueError as exc:
        raise JweError("cabecera no es JSON") from exc
    if not isinstance(header, dict):
        raise JweError("cabecera no es un objeto")
    if header.get("alg") != ALG:
        raise JweError(f"alg no admitido: {header.get('alg')!r}")
    enc = header.get("enc")
    if enc not in ENC_KEY_BITS:
        raise JweError(f"enc no admitido: {enc!r}")
    if "zip" in header or "crit" in header:
        raise JweError("zip/crit no admitidos")
    if encrypted_key:
        raise JweError("ECDH-ES directo no lleva clave cifrada")
    epk = header.get("epk")
    if not isinstance(epk, dict) or "d" in epk:
        raise JweError("epk ausente o con material privado")
    try:
        # public_key_from_jwk exige P-256 y comprueba que el punto esté en la curva.
        peer = public_key_from_jwk(epk)
    except KeyFormatError as exc:
        raise JweError(f"epk inválida: {exc}") from exc
    apu = _decode_part(header["apu"], "apu") if "apu" in header else b""
    apv = _decode_part(header["apv"], "apv") if "apv" in header else b""
    z = private_key.exchange(ec.ECDH(), peer)
    cek = concat_kdf(z, enc, apu, apv)
    iv = _decode_part(iv_b64, "iv")
    if len(iv) != 12:
        raise JweError("iv debe medir 96 bits")
    tag = _decode_part(tag_b64, "tag")
    if len(tag) != 16:
        raise JweError("tag debe medir 128 bits")
    ciphertext = _decode_part(ct_b64, "ciphertext")
    try:
        plaintext = AESGCM(cek).decrypt(iv, ciphertext + tag, protected_b64.encode("ascii"))
    except Exception as exc:
        raise JweError("autenticación fallida") from exc
    return DecryptedJwe(header=header, plaintext=plaintext)


def encrypt_compact(
    plaintext: bytes,
    recipient_jwk: dict[str, Any],
    *,
    enc: str = "A128GCM",
    kid: str | None = None,
    apu: bytes = b"",
    apv: bytes = b"",
) -> str:
    if enc not in ENC_KEY_BITS:
        raise JweError(f"enc no admitido: {enc!r}")
    recipient = public_key_from_jwk(recipient_jwk)
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    header: dict[str, Any] = {
        "alg": ALG,
        "enc": enc,
        "epk": public_jwk_from_key(ephemeral.public_key()),
    }
    if kid:
        header["kid"] = kid
    if apu:
        header["apu"] = b64url_encode(apu)
    if apv:
        header["apv"] = b64url_encode(apv)
    protected_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    cek = concat_kdf(ephemeral.exchange(ec.ECDH(), recipient), enc, apu, apv)
    iv = os.urandom(12)
    sealed = AESGCM(cek).encrypt(iv, plaintext, protected_b64.encode("ascii"))
    ciphertext, tag = sealed[:-16], sealed[-16:]
    return ".".join(
        [protected_b64, "", b64url_encode(iv), b64url_encode(ciphertext), b64url_encode(tag)]
    )
