"""Backends de claves de firma (ADR-0006).

``SignerBackend`` crea claves y reconstruye un ``Signer`` a partir de la
referencia guardada en ``signing_key.key_ref`` (ARN de KMS o nombre de
archivo). Ninguna implementación devuelve ni registra material privado.
"""

from __future__ import annotations

import logging
import secrets
from pathlib import Path
from typing import Any, Protocol

from ..platform.config import Environment, Settings
from ..vc.keys import public_key_from_jwk
from ..vc.signing import DEV_ENVIRONMENTS, KmsSigner, LocalDevSigner, Signer, SigningError

log = logging.getLogger(__name__)


class SignerBackend(Protocol):
    name: str

    def create(self, org_public_id: str) -> tuple[str, Signer]:
        """Crea una clave nueva y devuelve ``(key_ref, signer)``."""
        ...

    def load(self, key_ref: str, public_jwk: dict[str, Any]) -> Signer: ...

    def disable(self, key_ref: str) -> None:
        """Impide nuevas firmas con la clave (compromiso). No la destruye."""
        ...


class LocalDevBackend:
    name = "local_dev"

    def __init__(self, directory: Path, environment: str) -> None:
        if environment not in DEV_ENVIRONMENTS:
            raise SigningError(f"local_dev no está permitido en el entorno {environment!r}")
        self._dir = directory
        self._environment = environment

    def _path(self, key_ref: str) -> Path:
        if "/" in key_ref or key_ref.startswith("."):
            raise SigningError("key_ref local inválido")
        return self._dir / key_ref

    def create(self, org_public_id: str) -> tuple[str, Signer]:
        key_ref = f"{org_public_id}-{secrets.token_hex(8)}.pem"
        signer = LocalDevSigner.load_or_create(self._path(key_ref), environment=self._environment)
        return key_ref, signer

    def load(self, key_ref: str, public_jwk: dict[str, Any]) -> Signer:
        signer = LocalDevSigner.load_or_create(self._path(key_ref), environment=self._environment)
        if signer.public_jwk != {k: public_jwk[k] for k in ("kty", "crv", "x", "y")}:
            raise SigningError("la clave local no coincide con la clave pública registrada")
        return signer

    def disable(self, key_ref: str) -> None:
        path = self._path(key_ref)
        if path.exists():
            path.rename(path.with_suffix(".pem.disabled"))


class KmsBackend:
    name = "aws_kms"

    def __init__(self, client: Any, *, environment: str) -> None:
        self._client = client
        self._environment = environment

    def create(self, org_public_id: str) -> tuple[str, Signer]:
        resp = self._client.create_key(
            Description=f"aletheia {self._environment} issuer signing key for {org_public_id}",
            KeyUsage="SIGN_VERIFY",
            KeySpec="ECC_NIST_P256",
            Origin="AWS_KMS",
            Tags=[
                {"TagKey": "Project", "TagValue": "aletheia"},
                {"TagKey": "Environment", "TagValue": self._environment},
                {"TagKey": "Organization", "TagValue": org_public_id},
                {"TagKey": "Purpose", "TagValue": "issuer-signing"},
            ],
        )
        arn = str(resp["KeyMetadata"]["Arn"])
        public_key = KmsSigner.fetch_public_key(self._client, arn)
        return arn, KmsSigner(self._client, arn, public_key)

    def load(self, key_ref: str, public_jwk: dict[str, Any]) -> Signer:
        return KmsSigner(self._client, key_ref, public_key_from_jwk(public_jwk))

    def disable(self, key_ref: str) -> None:
        # KMS acepta ARN o id; se envía el id (algunos simuladores sólo aceptan este).
        key_id = key_ref.rsplit("key/", 1)[-1]
        self._client.disable_key(KeyId=key_id)


def build_backend(settings: Settings, kms_client: Any | None = None) -> SignerBackend:
    env = settings.env.value
    if settings.signing_backend == "local_dev":
        if settings.env.is_deployed:
            raise SigningError(
                "signing_backend=local_dev no está permitido en entornos desplegados"
            )
        settings.dev_keys_dir.mkdir(parents=True, exist_ok=True)
        return LocalDevBackend(settings.dev_keys_dir, env)
    if kms_client is None:
        import boto3  # importación diferida: sólo con backend KMS

        kms_client = boto3.client("kms", region_name=settings.aws_region)
    if settings.env is Environment.DEVELOPMENT:
        log.warning("usando AWS KMS en desarrollo")
    return KmsBackend(kms_client, environment=env)
