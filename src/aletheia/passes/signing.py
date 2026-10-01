"""Firma de pases: PKCS#7 desacoplado (DER) de ``manifest.json`` con el certificado del
Pass Type ID y la cadena intermedia Apple WWDR, como exige PassKit.

- Con ``ALETHEIA_PASS_CERT_PEM``, ``ALETHEIA_PASS_KEY_PEM`` y ``ALETHEIA_PASS_WWDR_PEM``
  (cuenta de Apple Developer) el pase es válido en iPhone.
- En desarrollo/pruebas sin esos valores se genera una CA y un certificado **de prueba**
  con el mismo formato de sujeto que Apple (UID = Pass Type ID, OU = Team ID). La
  estructura es correcta, pero **ningún iPhone acepta el pase**: falta la confianza de Apple.
"""

from __future__ import annotations

import logging
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from ..platform.config import Settings
from ..vc.signing import SigningError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PassSigner:
    cert: x509.Certificate
    key: rsa.RSAPrivateKey
    wwdr: x509.Certificate
    trusted_by_apple: bool

    def sign(self, manifest: bytes) -> bytes:
        return (
            pkcs7.PKCS7SignatureBuilder()
            .set_data(manifest)
            .add_signer(self.cert, self.key, hashes.SHA256())
            .add_certificate(self.wwdr)
            .sign(
                serialization.Encoding.DER,
                [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary],
            )
        )


def _uid(cert: x509.Certificate) -> str | None:
    attrs = cert.subject.get_attributes_for_oid(NameOID.USER_ID)
    return str(attrs[0].value) if attrs else None


def _write_private(path: Path, key: rsa.RSAPrivateKey) -> None:
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)


def _dev_signer(settings: Settings) -> PassSigner:
    directory = settings.dev_keys_dir
    directory.mkdir(parents=True, exist_ok=True)
    ca_key_p, ca_p = directory / "pass-dev-ca-key.pem", directory / "pass-dev-ca.pem"
    key_p, cert_p = directory / "pass-dev-key.pem", directory / "pass-dev-cert.pem"
    now = datetime.now(UTC)
    if not (ca_key_p.exists() and ca_p.exists() and key_p.exists() and cert_p.exists()):
        for p in (ca_key_p, ca_p, key_p, cert_p):
            p.unlink(missing_ok=True)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Aletheia DEV pass CA (no Apple)"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Aletheia development"),
            ]
        )
        ca = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.USER_ID, settings.pass_type_identifier),
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, f"Pass Type ID: {settings.pass_type_identifier}"
                        ),
                        x509.NameAttribute(
                            NameOID.ORGANIZATIONAL_UNIT_NAME, settings.pass_team_identifier
                        ),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Aletheia development"),
                    ]
                )
            )
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .sign(ca_key, hashes.SHA256())
        )
        _write_private(ca_key_p, ca_key)
        ca_p.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        _write_private(key_p, key)
        cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    loaded = serialization.load_pem_private_key(key_p.read_bytes(), password=None)
    if not isinstance(loaded, rsa.RSAPrivateKey):
        raise SigningError("pass-dev-key.pem no es RSA")
    return PassSigner(
        cert=x509.load_pem_x509_certificate(cert_p.read_bytes()),
        key=loaded,
        wwdr=x509.load_pem_x509_certificate(ca_p.read_bytes()),
        trusted_by_apple=False,
    )


def load_pass_signer(settings: Settings) -> PassSigner | None:
    if settings.pass_cert_pem and settings.pass_key_pem is not None and settings.pass_wwdr_pem:
        cert = x509.load_pem_x509_certificate(settings.pass_cert_pem.encode())
        key = serialization.load_pem_private_key(
            settings.pass_key_pem.get_secret_value().encode(), password=None
        )
        if not isinstance(key, rsa.RSAPrivateKey):
            raise SigningError("ALETHEIA_PASS_KEY_PEM debe ser la clave RSA del certificado")
        if cert.public_key().public_numbers() != key.public_key().public_numbers():  # type: ignore[union-attr]
            raise SigningError("el certificado del pase no corresponde a su clave")
        if _uid(cert) != settings.pass_type_identifier:
            raise SigningError(
                f"el certificado es para {_uid(cert)!r}, no para {settings.pass_type_identifier!r}"
            )
        return PassSigner(
            cert=cert,
            key=key,
            wwdr=x509.load_pem_x509_certificate(settings.pass_wwdr_pem.encode()),
            trusted_by_apple=True,
        )
    if settings.env.is_deployed:
        log.info("Apple Wallet pass certificate not configured: passes disabled")
        return None
    return _dev_signer(settings)
