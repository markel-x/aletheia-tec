"""Identidad X.509 del verificador para solicitudes OID4VP firmadas (ADR-0015).

- Desplegado: clave PEM (P-256) y cadena de certificados PEM (hoja primero) desde
  configuración (Secrets Manager). Sin ellas no hay solicitudes firmadas.
- Desarrollo/pruebas: se genera en ``dev_keys_dir`` una clave y un certificado
  **autofirmado** cuyo SAN cubre el host público. Ningún wallet de producción lo
  aceptará: sirve para probar el protocolo, no la confianza.

La clave de firma de solicitudes es de la plataforma (no de cada organización):
los wallets identifican al verificador por el host de Aletheia. Ver ADR-0015.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import logging
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ..platform.config import Settings
from ..vc.encoding import b64url_encode
from ..vc.keys import jwk_thumbprint, public_jwk_from_key
from ..vc.signing import SigningError, der_to_raw_es256

log = logging.getLogger(__name__)
DEV_CERT_LIFETIME = timedelta(days=365)


class PemSigner:
    """Firmante ES256 con una clave en memoria (cargada de un secreto)."""

    alg = "ES256"

    def __init__(self, key: ec.EllipticCurvePrivateKey) -> None:
        if not isinstance(key.curve, ec.SECP256R1):
            raise SigningError("la clave del verificador debe ser P-256")
        self._key = key
        self._jwk = public_jwk_from_key(key.public_key())

    @property
    def kid(self) -> str:
        return jwk_thumbprint(self._jwk)

    @property
    def public_jwk(self) -> dict[str, str]:
        return dict(self._jwk)

    def sign(self, signing_input: bytes) -> bytes:
        return der_to_raw_es256(self._key.sign(signing_input, ec.ECDSA(hashes.SHA256())))

    def __repr__(self) -> str:
        return f"PemSigner(kid={self.kid!r})"


@dataclass(frozen=True)
class VerifierIdentity:
    signer: PemSigner
    chain: tuple[x509.Certificate, ...]

    @property
    def leaf(self) -> x509.Certificate:
        return self.chain[0]

    @property
    def x5c(self) -> list[str]:
        """``x5c`` usa base64 estándar (no base64url) del DER, RFC 7515 §4.1.6."""
        return [
            base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()
            for c in self.chain
        ]

    @property
    def x509_hash(self) -> str:
        der = self.leaf.public_bytes(serialization.Encoding.DER)
        return b64url_encode(hashlib.sha256(der).digest())

    def dns_names(self) -> list[str]:
        try:
            san = self.leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            return []
        return [str(n) for n in san.value.get_values_for_type(x509.DNSName)]


def _load_chain(pem: str) -> tuple[x509.Certificate, ...]:
    chain = tuple(x509.load_pem_x509_certificates(pem.encode()))
    if not chain:
        raise SigningError("la cadena del verificador está vacía")
    return chain


def _check_pair(key: ec.EllipticCurvePrivateKey, leaf: x509.Certificate) -> None:
    if public_jwk_from_key(key.public_key()) != public_jwk_from_key(leaf.public_key()):  # type: ignore[arg-type]
        raise SigningError("el certificado del verificador no corresponde a su clave")


def _dev_identity(settings: Settings) -> VerifierIdentity:
    host = urlsplit(settings.public_base).hostname or "localhost"
    directory = settings.dev_keys_dir
    directory.mkdir(parents=True, exist_ok=True)
    key_path, cert_path = directory / "verifier-key.pem", directory / "verifier-cert.pem"
    if key_path.exists():
        loaded = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(loaded, ec.EllipticCurvePrivateKey):
            raise SigningError("verifier-key.pem no es EC")
        key = loaded
    else:
        key = ec.generate_private_key(ec.SECP256R1())
        _write_private(key_path, key)
    if cert_path.exists():
        chain = _load_chain(cert_path.read_text())
        identity = VerifierIdentity(PemSigner(key), chain)
        if _covers(identity, host) and chain[0].not_valid_after_utc > datetime.now(UTC):
            return identity
    cert = _self_signed(key, host)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return VerifierIdentity(PemSigner(key), (cert,))


def _covers(identity: VerifierIdentity, host: str) -> bool:
    try:
        san = identity.leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host in san.value.get_values_for_type(x509.DNSName)
    return ip in san.value.get_values_for_type(x509.IPAddress)


def _self_signed(key: ec.EllipticCurvePrivateKey, host: str) -> x509.Certificate:
    try:
        san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        san = x509.DNSName(host)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Aletheia verifier (dev) {host}")])
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + DEV_CERT_LIFETIME)
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )


def _write_private(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)


def load_identity(settings: Settings) -> VerifierIdentity | None:
    if settings.verifier_key_pem is not None and settings.verifier_cert_chain_pem:
        loaded = serialization.load_pem_private_key(
            settings.verifier_key_pem.get_secret_value().encode(), password=None
        )
        if not isinstance(loaded, ec.EllipticCurvePrivateKey):
            raise SigningError("ALETHEIA_VERIFIER_KEY_PEM debe ser una clave EC P-256")
        chain = _load_chain(settings.verifier_cert_chain_pem)
        _check_pair(loaded, chain[0])
        return VerifierIdentity(PemSigner(loaded), chain)
    if settings.env.is_deployed:
        log.info("verifier certificate not configured: signed OID4VP requests disabled")
        return None
    return _dev_identity(settings)
