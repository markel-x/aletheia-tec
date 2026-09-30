"""Firmantes ES256: local (sólo desarrollo) y AWS KMS.

Contrato: ``sign(signing_input)`` devuelve la firma JWS ES256, es decir
``R || S`` en 64 bytes (RFC 7518 §3.4). Ninguna implementación expone material
privado.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from .keys import jwk_thumbprint, public_jwk_from_key

_ES256_COMPONENT_LEN = 32
DEV_ENVIRONMENTS = frozenset({"development", "test"})


class SigningError(RuntimeError):
    """El firmante no pudo producir una firma válida."""


class Signer(Protocol):
    @property
    def alg(self) -> str: ...

    @property
    def kid(self) -> str: ...

    @property
    def public_jwk(self) -> dict[str, str]: ...

    def sign(self, signing_input: bytes) -> bytes: ...


def der_to_raw_es256(der: bytes) -> bytes:
    """Convierte una firma ECDSA DER (ANSI X9.62, formato de KMS) a R||S."""
    try:
        r, s = decode_dss_signature(der)
    except ValueError as exc:
        raise SigningError("firma DER inválida") from exc
    if r.bit_length() > 256 or s.bit_length() > 256:
        raise SigningError("componentes de firma fuera de rango para P-256")
    return r.to_bytes(_ES256_COMPONENT_LEN, "big") + s.to_bytes(_ES256_COMPONENT_LEN, "big")


def raw_to_der_es256(raw: bytes) -> bytes:
    if len(raw) != 2 * _ES256_COMPONENT_LEN:
        raise SigningError("firma ES256 debe medir 64 bytes")
    r = int.from_bytes(raw[:_ES256_COMPONENT_LEN], "big")
    s = int.from_bytes(raw[_ES256_COMPONENT_LEN:], "big")
    return encode_dss_signature(r, s)


@dataclass(frozen=True)
class _PublicInfo:
    public_jwk: dict[str, str]
    kid: str


def _public_info(key: ec.EllipticCurvePublicKey) -> _PublicInfo:
    jwk = public_jwk_from_key(key)
    return _PublicInfo(public_jwk=jwk, kid=jwk_thumbprint(jwk))


class LocalDevSigner:
    """Firmante con clave en archivo PEM. **Exclusivo para desarrollo y pruebas.**

    Se niega a funcionar fuera de ``development``/``test`` para impedir que una
    clave en disco llegue a un entorno desplegado (ADR-0006).
    """

    alg = "ES256"

    def __init__(self, private_key: ec.EllipticCurvePrivateKey, *, environment: str) -> None:
        if environment not in DEV_ENVIRONMENTS:
            raise SigningError(f"LocalDevSigner no está permitido en el entorno {environment!r}")
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise SigningError("sólo se admite P-256")
        self._key = private_key
        self._info = _public_info(private_key.public_key())

    @classmethod
    def generate(cls, *, environment: str) -> LocalDevSigner:
        return cls(ec.generate_private_key(ec.SECP256R1()), environment=environment)

    @classmethod
    def load_or_create(cls, path: Path, *, environment: str) -> LocalDevSigner:
        if environment not in DEV_ENVIRONMENTS:
            raise SigningError(f"LocalDevSigner no está permitido en el entorno {environment!r}")
        if path.exists():
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise SigningError("la clave local no es EC")
            return cls(key, environment=environment)
        signer = cls.generate(environment=environment)
        path.parent.mkdir(parents=True, exist_ok=True)
        pem = signer._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        return signer

    @property
    def kid(self) -> str:
        return self._info.kid

    @property
    def public_jwk(self) -> dict[str, str]:
        return dict(self._info.public_jwk)

    def sign(self, signing_input: bytes) -> bytes:
        der = self._key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        return der_to_raw_es256(der)

    def __repr__(self) -> str:  # evita volcar la clave en logs o trazas
        return f"LocalDevSigner(kid={self.kid!r})"


class KmsSigner:
    """Firmante sobre AWS KMS (clave ``ECC_NIST_P256``, ``ECDSA_SHA_256``).

    - El SHA-256 se calcula localmente y se envía con ``MessageType=DIGEST``:
      ``RAW`` está limitado a 4096 bytes y la entrada de firma JWS puede
      superarlo.
    - KMS devuelve DER; se convierte a R||S.
    - ``kms_client`` es un cliente ``boto3.client("kms")`` (inyectado para
      pruebas y para controlar región, reintentos y timeouts).
    - La clave pública se obtiene al registrar la clave (``GetPublicKey``) y
      se pasa aquí; así la firma no depende de una llamada extra.
    """

    alg = "ES256"

    def __init__(self, kms_client: Any, key_id: str, public_key: ec.EllipticCurvePublicKey):
        self._client = kms_client
        self._key_id = key_id
        self._public_key = public_key
        self._info = _public_info(public_key)

    @staticmethod
    def fetch_public_key(kms_client: Any, key_id: str) -> ec.EllipticCurvePublicKey:
        resp = kms_client.get_public_key(KeyId=key_id)
        # ``CustomerMasterKeySpec`` es el nombre heredado que aún devuelven algunos clientes.
        spec = resp.get("KeySpec") or resp.get("CustomerMasterKeySpec")
        if spec != "ECC_NIST_P256" or resp.get("KeyUsage") != "SIGN_VERIFY":
            raise SigningError("la clave KMS debe ser ECC_NIST_P256 / SIGN_VERIFY")
        key = serialization.load_der_public_key(resp["PublicKey"])
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise SigningError("la clave pública KMS no es EC")
        return key

    @property
    def kid(self) -> str:
        return self._info.kid

    @property
    def public_jwk(self) -> dict[str, str]:
        return dict(self._info.public_jwk)

    def sign(self, signing_input: bytes) -> bytes:
        digest = hashlib.sha256(signing_input).digest()
        resp = self._client.sign(
            KeyId=self._key_id,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        raw = der_to_raw_es256(resp["Signature"])
        # Autocomprobación: detecta clave equivocada o respuesta corrupta antes
        # de entregar una credencial que nadie podría verificar.
        try:
            self._public_key.verify(raw_to_der_es256(raw), signing_input, ec.ECDSA(hashes.SHA256()))
        except Exception as exc:  # InvalidSignature u otros
            raise SigningError("la firma de KMS no verifica con la clave registrada") from exc
        return raw

    def __repr__(self) -> str:
        return f"KmsSigner(kid={self.kid!r})"
