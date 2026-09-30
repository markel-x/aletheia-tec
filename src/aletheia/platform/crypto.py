"""Cifrado de datos pendientes (envelope encryption, ADR-0009).

Cada registro se cifra con una clave de datos AES-256-GCM propia; la clave de
datos viaja cifrada ("envuelta") junto al texto cifrado:

- ``aws_kms``: ``GenerateDataKey``/``Decrypt`` sobre una clave KMS simétrica,
  con contexto de cifrado (organización e identificador del registro).
- ``local_dev``: clave maestra de 256 bits en el directorio de claves de
  desarrollo; la clave de datos se envuelve con AES-GCM. Sólo dev/test.

El texto cifrado lleva el contexto como datos autenticados adicionales: un
registro no puede reutilizarse en otra oferta ni organización.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..vc.signing import DEV_ENVIRONMENTS, SigningError
from .config import Settings

_NONCE_LEN = 12


class DecryptionError(RuntimeError):
    pass


@dataclass(frozen=True)
class Envelope:
    ciphertext: bytes
    encrypted_data_key: bytes
    key_ref: str


def _aad(context: dict[str, str]) -> bytes:
    return json.dumps(context, sort_keys=True, separators=(",", ":")).encode()


class DataEncryptor(Protocol):
    def encrypt(self, plaintext: bytes, context: dict[str, str]) -> Envelope: ...

    def decrypt(self, envelope: Envelope, context: dict[str, str]) -> bytes: ...


def _seal(data_key: bytes, plaintext: bytes, context: dict[str, str]) -> bytes:
    nonce = os.urandom(_NONCE_LEN)
    return nonce + AESGCM(data_key).encrypt(nonce, plaintext, _aad(context))


def _open(data_key: bytes, blob: bytes, context: dict[str, str]) -> bytes:
    if len(blob) < _NONCE_LEN + 16:
        raise DecryptionError("ciphertext too short")
    try:
        return AESGCM(data_key).decrypt(blob[:_NONCE_LEN], blob[_NONCE_LEN:], _aad(context))
    except Exception as exc:
        raise DecryptionError("authentication failed") from exc


class LocalDataEncryptor:
    key_ref = "local-master-v1"

    def __init__(self, directory: Path, environment: str) -> None:
        if environment not in DEV_ENVIRONMENTS:
            raise SigningError(f"cifrado local no permitido en el entorno {environment!r}")
        path = directory / "data-master.key"
        if not path.exists():
            directory.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "wb") as fh:
                fh.write(os.urandom(32))
        self._master = path.read_bytes()
        if len(self._master) != 32:
            raise SigningError("clave maestra local inválida")

    def encrypt(self, plaintext: bytes, context: dict[str, str]) -> Envelope:
        data_key = os.urandom(32)
        return Envelope(
            ciphertext=_seal(data_key, plaintext, context),
            encrypted_data_key=_seal(self._master, data_key, context),
            key_ref=self.key_ref,
        )

    def decrypt(self, envelope: Envelope, context: dict[str, str]) -> bytes:
        if envelope.key_ref != self.key_ref:
            raise DecryptionError("unknown key_ref")
        data_key = _open(self._master, envelope.encrypted_data_key, context)
        return _open(data_key, envelope.ciphertext, context)


class KmsDataEncryptor:
    def __init__(self, client: Any, key_id: str) -> None:
        self._client = client
        self._key_id = key_id

    def encrypt(self, plaintext: bytes, context: dict[str, str]) -> Envelope:
        resp = self._client.generate_data_key(
            KeyId=self._key_id, KeySpec="AES_256", EncryptionContext=context
        )
        data_key: bytes = resp["Plaintext"]
        try:
            return Envelope(
                ciphertext=_seal(data_key, plaintext, context),
                encrypted_data_key=resp["CiphertextBlob"],
                key_ref=str(resp["KeyId"]),
            )
        finally:
            del data_key

    def decrypt(self, envelope: Envelope, context: dict[str, str]) -> bytes:
        try:
            resp = self._client.decrypt(
                CiphertextBlob=envelope.encrypted_data_key,
                KeyId=envelope.key_ref,
                EncryptionContext=context,
            )
        except Exception as exc:
            raise DecryptionError("KMS decrypt failed") from exc
        return _open(resp["Plaintext"], envelope.ciphertext, context)


def build_encryptor(settings: Settings, kms_client: Any | None = None) -> DataEncryptor:
    if settings.signing_backend == "local_dev":
        if settings.env.is_deployed:
            raise SigningError("cifrado local no permitido en entornos desplegados")
        return LocalDataEncryptor(settings.dev_keys_dir, settings.env.value)
    if settings.kms_data_key_id is None:
        raise SigningError("ALETHEIA_KMS_DATA_KEY_ID es obligatoria con el backend aws_kms")
    if kms_client is None:
        import boto3

        kms_client = boto3.client("kms", region_name=settings.aws_region)
    return KmsDataEncryptor(kms_client, settings.kms_data_key_id)
