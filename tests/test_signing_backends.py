"""Backends de claves: local (archivo) y KMS (simulado con moto)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import boto3
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from moto import mock_aws

from aletheia.organizations.keys import KmsBackend, LocalDevBackend, build_backend
from aletheia.platform.config import Environment, Settings
from aletheia.vc.keys import public_key_from_jwk
from aletheia.vc.signing import SigningError, raw_to_der_es256


def _verify(public_jwk: dict[str, str], message: bytes, signature: bytes) -> None:
    public_key_from_jwk(public_jwk).verify(
        raw_to_der_es256(signature), message, ec.ECDSA(hashes.SHA256())
    )


def test_local_backend_creates_loads_and_disables(tmp_path: Path) -> None:
    backend = LocalDevBackend(tmp_path, "test")
    key_ref, signer = backend.create("org_test")
    assert (tmp_path / key_ref).exists()
    assert not key_ref.startswith("/") and "/" not in key_ref
    sig = signer.sign(b"hello")
    _verify(signer.public_jwk, b"hello", sig)

    loaded = backend.load(key_ref, signer.public_jwk)
    assert loaded.kid == signer.kid
    _verify(loaded.public_jwk, b"again", loaded.sign(b"again"))

    with pytest.raises(SigningError):
        backend.load("../etc/passwd", signer.public_jwk)
    with pytest.raises(SigningError):
        backend.load(key_ref, {**signer.public_jwk, "x": "AAAA"})

    backend.disable(key_ref)
    assert not (tmp_path / key_ref).exists()


def test_local_backend_refuses_outside_dev(tmp_path: Path) -> None:
    with pytest.raises(SigningError):
        LocalDevBackend(tmp_path, "production")
    settings = Settings(
        env=Environment.PRODUCTION, signing_backend="local_dev", dev_keys_dir=tmp_path
    )
    with pytest.raises(SigningError):
        build_backend(settings)


@mock_aws
def test_kms_backend_creates_signs_and_disables() -> None:
    client = boto3.client("kms", region_name="us-east-1")
    backend = KmsBackend(client, environment="test")
    arn, signer = backend.create("org_test")
    assert arn.startswith("arn:aws:kms:us-east-1:")
    meta = client.describe_key(KeyId=arn)["KeyMetadata"]
    assert meta["KeySpec"] == "ECC_NIST_P256" and meta["KeyUsage"] == "SIGN_VERIFY"
    tags = {t["TagKey"]: t["TagValue"] for t in client.list_resource_tags(KeyId=arn)["Tags"]}
    assert tags["Organization"] == "org_test"

    # moto firma el ``Message`` recibido como si fuera RAW (lo vuelve a hashear) e ignora
    # ``MessageType=DIGEST``: la firma no corresponde a la entrada. La autocomprobación
    # del firmante debe detectarlo en vez de entregar una firma inválida.
    message = b"payload" * 1000  # > 4096 bytes: en KMS real exige MessageType=DIGEST
    with pytest.raises(SigningError, match="no verifica"):
        signer.sign(message)
    raw_resp = client.sign(
        KeyId=arn,
        Message=hashlib.sha256(message).digest(),
        MessageType="DIGEST",
        SigningAlgorithm="ECDSA_SHA_256",
    )
    # Comprobación de la limitación de moto: la firma verifica sobre el *digest* como mensaje.
    public_key_from_jwk(signer.public_jwk).verify(
        raw_resp["Signature"], hashlib.sha256(message).digest(), ec.ECDSA(hashes.SHA256())
    )

    loaded = backend.load(arn, signer.public_jwk)
    assert loaded.kid == signer.kid

    backend.disable(arn)
    assert client.describe_key(KeyId=arn)["KeyMetadata"]["Enabled"] is False
    # moto no impide firmar con una clave deshabilitada; KMS real responde DisabledException.


@mock_aws
def test_build_backend_kms_from_settings() -> None:
    settings = Settings(env=Environment.STAGING, signing_backend="aws_kms", aws_region="us-east-1")
    backend = build_backend(settings)
    assert isinstance(backend, KmsBackend)
