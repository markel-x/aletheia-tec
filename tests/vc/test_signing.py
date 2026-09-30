"""Firmantes: conversión DER↔R||S, protección del firmante local y adaptador KMS.

La prueba de KMS usa un cliente falso que reproduce el contrato documentado de
``kms:Sign`` (entrada DIGEST, salida DER). **No** valida la integración real
con AWS; esa prueba (marcador ``aws``) se ejecuta contra una cuenta de staging.
"""

from __future__ import annotations

import hashlib
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from aletheia.vc.jws import sign_compact
from aletheia.vc.keys import jwk_thumbprint
from aletheia.vc.signing import (
    KmsSigner,
    LocalDevSigner,
    SigningError,
    der_to_raw_es256,
    raw_to_der_es256,
)


class FakeKms:
    """Imita ``kms:Sign``/``GetPublicKey`` para ECC_NIST_P256."""

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.requests: list[dict[str, Any]] = []

    def get_public_key(self, KeyId: str) -> dict[str, Any]:
        return {
            "KeyId": KeyId,
            "KeySpec": "ECC_NIST_P256",
            "KeyUsage": "SIGN_VERIFY",
            "PublicKey": self._key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
        }

    def sign(self, **kwargs: Any) -> dict[str, Any]:
        self.requests.append(kwargs)
        assert kwargs["MessageType"] == "DIGEST"
        assert kwargs["SigningAlgorithm"] == "ECDSA_SHA_256"
        assert len(kwargs["Message"]) == 32
        der = self._key.sign(kwargs["Message"], ec.ECDSA(Prehashed(hashes.SHA256())))
        return {"KeyId": kwargs["KeyId"], "Signature": der, "SigningAlgorithm": "ECDSA_SHA_256"}


def _pem(signer_jwk_key: ec.EllipticCurvePublicKey) -> bytes:
    return signer_jwk_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def test_der_raw_roundtrip() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    der = key.sign(b"hola", ec.ECDSA(hashes.SHA256()))
    raw = der_to_raw_es256(der)
    assert len(raw) == 64
    key.public_key().verify(raw_to_der_es256(raw), b"hola", ec.ECDSA(hashes.SHA256()))


def test_der_to_raw_rejects_garbage() -> None:
    with pytest.raises(SigningError):
        der_to_raw_es256(b"\x30\x01\x00")


@pytest.mark.parametrize("environment", ["production", "staging", "prod", ""])
def test_local_signer_refused_outside_dev(environment: str) -> None:
    with pytest.raises(SigningError):
        LocalDevSigner.generate(environment=environment)


def test_local_signer_repr_does_not_leak_key() -> None:
    signer = LocalDevSigner.generate(environment="test")
    assert "PRIVATE" not in repr(signer) and signer.kid in repr(signer)


def test_local_signer_persists_key_with_owner_only_permissions(tmp_path: Any) -> None:
    path = tmp_path / ".dev-keys" / "org.pem"
    first = LocalDevSigner.load_or_create(path, environment="development")
    second = LocalDevSigner.load_or_create(path, environment="development")
    assert first.kid == second.kid
    assert (path.stat().st_mode & 0o777) == 0o600


def test_jws_from_local_signer_verifies_with_pyjwt() -> None:
    """PyJWT (implementación independiente) acepta nuestras firmas."""
    signer = LocalDevSigner.generate(environment="test")
    token = sign_compact({"alg": "ES256", "typ": "JWT", "kid": signer.kid}, {"a": 1}, signer)
    pub = jwt.PyJWK(signer.public_jwk).key
    assert jwt.decode(token, pub, algorithms=["ES256"]) == {"a": 1}


def test_kms_signer_uses_digest_and_produces_valid_es256() -> None:
    kms = FakeKms()
    public = KmsSigner.fetch_public_key(kms, "arn:aws:kms:us-east-1:111122223333:key/demo")
    signer = KmsSigner(kms, "arn:aws:kms:us-east-1:111122223333:key/demo", public)
    big_payload = {"blob": "x" * 10_000}  # > 4096 bytes: RAW no serviría
    token = sign_compact({"alg": "ES256", "typ": "JWT", "kid": signer.kid}, big_payload, signer)
    assert jwt.decode(token, public, algorithms=["ES256"]) == big_payload
    signing_input = token.rsplit(".", 1)[0].encode()
    assert kms.requests[0]["Message"] == hashlib.sha256(signing_input).digest()
    assert signer.kid == jwk_thumbprint(signer.public_jwk)


def test_kms_signer_detects_mismatched_public_key() -> None:
    kms = FakeKms()
    wrong = ec.generate_private_key(ec.SECP256R1()).public_key()
    signer = KmsSigner(kms, "key", wrong)
    with pytest.raises(SigningError):
        signer.sign(b"payload")


def test_kms_rejects_non_p256_key_spec() -> None:
    class RsaKms(FakeKms):
        def get_public_key(self, KeyId: str) -> dict[str, Any]:
            return {**super().get_public_key(KeyId), "KeySpec": "RSA_2048"}

    with pytest.raises(SigningError):
        KmsSigner.fetch_public_key(RsaKms(), "key")
