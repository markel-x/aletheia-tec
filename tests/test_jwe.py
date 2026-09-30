"""JWE ECDH-ES + AES-GCM: vector de RFC 7518 Apéndice C y casos de rechazo."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from aletheia.platform.jwe import JweError, concat_kdf, decrypt_compact, encrypt_compact
from aletheia.vc.encoding import b64url_decode, b64url_encode
from aletheia.vc.keys import public_jwk_from_key, public_key_from_jwk

# RFC 7518, Apéndice C (ECDH-ES, A128GCM, apu "Alice", apv "Bob").
ALICE = {
    "kty": "EC",
    "crv": "P-256",
    "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
    "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
    "d": "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo",
}
BOB = {
    "kty": "EC",
    "crv": "P-256",
    "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
    "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
    "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
}


def _private(jwk: dict[str, str]) -> ec.EllipticCurvePrivateKey:
    key = ec.derive_private_key(int.from_bytes(b64url_decode(jwk["d"]), "big"), ec.SECP256R1())
    assert public_jwk_from_key(key.public_key())["x"] == jwk["x"]  # el vector es coherente
    return key


def _public(jwk: dict[str, str]) -> ec.EllipticCurvePublicKey:
    return public_key_from_jwk({k: v for k, v in jwk.items() if k != "d"})


def test_rfc7518_appendix_c_key_derivation() -> None:
    z = _private(ALICE).exchange(ec.ECDH(), _public(BOB))
    assert z == _private(BOB).exchange(ec.ECDH(), _public(ALICE))
    assert b64url_encode(concat_kdf(z, "A128GCM", b"Alice", b"Bob")) == "VqqN6vgjbSBcIijNcacQGg"


@pytest.mark.parametrize("enc", ["A128GCM", "A256GCM"])
def test_roundtrip(enc: str) -> None:
    recipient = ec.generate_private_key(ec.SECP256R1())
    jwk = public_jwk_from_key(recipient.public_key())
    jwe = encrypt_compact(b'{"vp_token":{}}', jwk, enc=enc, kid="k1", apv=b"nonce")
    out = decrypt_compact(jwe, recipient)
    assert out.plaintext == b'{"vp_token":{}}'
    assert out.header["kid"] == "k1" and out.header["enc"] == enc


def _tamper_header(jwe: str, **changes: object) -> str:
    parts = jwe.split(".")
    header = json.loads(b64url_decode(parts[0]))
    header.update(changes)
    parts[0] = b64url_encode(json.dumps(header).encode())
    return ".".join(parts)


def test_rejections() -> None:
    recipient = ec.generate_private_key(ec.SECP256R1())
    jwk = public_jwk_from_key(recipient.public_key())
    jwe = encrypt_compact(b"secret", jwk)
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(JweError, match="autenticación"):
        decrypt_compact(jwe, other)  # otra clave
    parts = jwe.split(".")
    parts[3] = b64url_encode(b64url_decode(parts[3])[:-1] + b"\x00")
    with pytest.raises(JweError, match="autenticación"):
        decrypt_compact(".".join(parts), recipient)  # texto cifrado alterado
    # La cabecera es AAD: cambiarla (aunque sea un campo inocuo) invalida.
    with pytest.raises(JweError, match="autenticación"):
        decrypt_compact(_tamper_header(jwe, kid="otro"), recipient)
    for changes, fragment in (
        ({"alg": "RSA-OAEP"}, "alg"),
        ({"enc": "A128CBC-HS256"}, "enc"),
        ({"zip": "DEF"}, "zip"),
        ({"epk": {**jwk, "d": "x"}}, "epk"),
        ({"epk": {**jwk, "x": b64url_encode(b"\x01" * 32)}}, "epk"),  # punto fuera de la curva
    ):
        with pytest.raises(JweError, match=fragment):
            decrypt_compact(_tamper_header(jwe, **changes), recipient)
    with pytest.raises(JweError, match="5 partes"):
        decrypt_compact("a.b.c", recipient)
    parts = jwe.split(".")
    parts[1] = "AAAA"
    with pytest.raises(JweError, match="clave cifrada"):
        decrypt_compact(".".join(parts), recipient)
