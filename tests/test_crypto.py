"""Envelope encryption local y con KMS simulado."""

from __future__ import annotations

from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from aletheia.platform.config import Environment, Settings
from aletheia.platform.crypto import (
    DecryptionError,
    Envelope,
    KmsDataEncryptor,
    LocalDataEncryptor,
    build_encryptor,
)
from aletheia.vc.signing import SigningError

CTX = {"organization_id": "org-1", "issuance_id": "iss-1"}


def test_local_roundtrip_and_context_binding(tmp_path: Path) -> None:
    enc = LocalDataEncryptor(tmp_path, "test")
    env = enc.encrypt(b'{"given_name": "Ana"}', CTX)
    assert env.ciphertext != b'{"given_name": "Ana"}'
    assert b"Ana" not in env.ciphertext
    assert enc.decrypt(env, CTX) == b'{"given_name": "Ana"}'
    # Otro contexto (otra oferta u organización) no puede abrirlo.
    with pytest.raises(DecryptionError):
        enc.decrypt(env, {**CTX, "issuance_id": "iss-2"})
    # Alteración del texto cifrado o de la clave envuelta.
    with pytest.raises(DecryptionError):
        enc.decrypt(
            Envelope(env.ciphertext[:-1] + b"\x00", env.encrypted_data_key, env.key_ref), CTX
        )
    with pytest.raises(DecryptionError):
        enc.decrypt(
            Envelope(env.ciphertext, env.encrypted_data_key[:-1] + b"\x00", env.key_ref), CTX
        )
    # La clave maestra persiste en el directorio: una nueva instancia descifra.
    assert LocalDataEncryptor(tmp_path, "test").decrypt(env, CTX) == b'{"given_name": "Ana"}'
    assert (tmp_path / "data-master.key").stat().st_size == 32


def test_local_refuses_deployed_environments(tmp_path: Path) -> None:
    with pytest.raises(SigningError):
        LocalDataEncryptor(tmp_path, "production")
    with pytest.raises(SigningError):
        build_encryptor(
            Settings(env=Environment.STAGING, signing_backend="local_dev", dev_keys_dir=tmp_path)
        )


@mock_aws
def test_kms_roundtrip_with_encryption_context() -> None:
    client = boto3.client("kms", region_name="us-east-1")
    key_id = client.create_key(KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT")[
        "KeyMetadata"
    ]["Arn"]
    enc = KmsDataEncryptor(client, key_id)
    env = enc.encrypt(b"secret claims", CTX)
    assert env.key_ref == key_id
    assert enc.decrypt(env, CTX) == b"secret claims"
    with pytest.raises(DecryptionError):
        enc.decrypt(env, {**CTX, "issuance_id": "other"})


@mock_aws
def test_build_encryptor_requires_kms_key_id() -> None:
    with pytest.raises(SigningError, match="KMS_DATA_KEY_ID"):
        build_encryptor(
            Settings(env=Environment.STAGING, signing_backend="aws_kms", aws_region="us-east-1")
        )
    settings = Settings(
        env=Environment.STAGING,
        signing_backend="aws_kms",
        aws_region="us-east-1",
        kms_data_key_id="alias/x",
    )
    assert isinstance(build_encryptor(settings), KmsDataEncryptor)


def test_tx_code_hmac(tmp_path: Path) -> None:
    from aletheia.platform.crypto import hash_tx_code, tx_code_key, verify_tx_code

    settings = Settings(env=Environment.TEST, dev_keys_dir=tmp_path)
    key = tx_code_key(settings)
    assert len(key) == 32 and tx_code_key(settings) == key  # persistente y en caché
    stored = hash_tx_code(key, "iss-1", "123456")
    assert stored.startswith("hmac-sha256$v1$") and "123456" not in stored
    assert verify_tx_code(key, "iss-1", "123456", stored)
    assert not verify_tx_code(key, "iss-1", "123457", stored)
    assert not verify_tx_code(key, "iss-2", "123456", stored)  # ligado a la emisión
    assert not verify_tx_code(b"x" * 32, "iss-1", "123456", stored)  # sin la clave no sirve
    assert not verify_tx_code(key, "iss-1", "123456", "$argon2id$legacy")


def test_tx_code_key_required_when_deployed(tmp_path: Path) -> None:
    import base64

    from aletheia.platform.crypto import tx_code_key

    with pytest.raises(SigningError, match="TX_CODE_KEY"):
        tx_code_key(Settings(env=Environment.PRODUCTION, dev_keys_dir=tmp_path))
    short = base64.urlsafe_b64encode(b"k" * 16).decode()
    with pytest.raises(SigningError, match="32 bytes"):
        tx_code_key(Settings(env=Environment.PRODUCTION, tx_code_key=short))  # type: ignore[arg-type]
    good = base64.urlsafe_b64encode(b"k" * 32).decode().rstrip("=")
    assert tx_code_key(Settings(env=Environment.PRODUCTION, tx_code_key=good)) == b"k" * 32  # type: ignore[arg-type]
