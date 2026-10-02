"""Pases de Google Wallet (ADR-0017).

A diferencia del ``.pkpass`` de Apple, el pase de Google vive en los servidores de Google:
Aletheia crea el objeto (``genericObject``) con la API de Google Wallet usando una cuenta de
servicio y entrega al titular un enlace «Agregar a Google Wallet» (JWT ``savetowallet``
firmado con la misma cuenta) que sólo referencia el objeto por su id. El QR del pase es el
mismo que el de Apple: la página de verificación de Aletheia, con la credencial en el fragmento.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ..platform.config import Settings
from .builder import _flatten, _label

log = logging.getLogger(__name__)

API_BASE = "https://walletobjects.googleapis.com/walletobjects/v1"
TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105 - URL, no secreto
SCOPE = "https://www.googleapis.com/auth/wallet_object.issuer"
SAVE_URL = "https://pay.google.com/gp/v/save/"
CLASS_SUFFIX = "aletheia_credential"
TIMEOUT = httpx.Timeout(10.0)


class GoogleWalletError(Exception):
    """La API de Google Wallet no aceptó la operación (configuración, red o datos)."""


@dataclass(frozen=True)
class ServiceAccount:
    client_email: str
    private_key: rsa.RSAPrivateKey
    private_key_id: str | None

    @classmethod
    def from_json(cls, raw: str) -> ServiceAccount:
        try:
            data = json.loads(raw)
            key = serialization.load_pem_private_key(data["private_key"].encode(), password=None)
            email = data["client_email"]
        except (ValueError, KeyError, TypeError) as exc:
            raise GoogleWalletError("clave de cuenta de servicio de Google inválida") from exc
        if not isinstance(key, rsa.RSAPrivateKey) or not isinstance(email, str):
            raise GoogleWalletError("la cuenta de servicio de Google debe tener clave RSA")
        return cls(email, key, data.get("private_key_id"))

    def sign(self, claims: dict[str, Any]) -> str:
        headers = {"kid": self.private_key_id} if self.private_key_id else None
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers=headers)


@dataclass
class GoogleWallet:
    issuer_id: str
    account: ServiceAccount
    origin: str
    transport: httpx.BaseTransport | None = None
    _token: tuple[str, float] | None = field(default=None, repr=False)
    _class_ready: bool = field(default=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def class_id(self) -> str:
        return f"{self.issuer_id}.{CLASS_SUFFIX}"

    def object_id(self, serial: str) -> str:
        # Ids de Google: «<issuer>.<sufijo>» con letras, dígitos, «.», «_» o «-».
        return f"{self.issuer_id}.{serial}"

    # -- API ------------------------------------------------------------------------------
    def _http(self) -> httpx.Client:
        return httpx.Client(transport=self.transport, timeout=TIMEOUT)

    def _access_token(self, http: httpx.Client) -> str:
        with self._lock:
            if self._token and self._token[1] > time.time() + 60:
                return self._token[0]
            now = int(time.time())
            assertion = self.account.sign(
                {
                    "iss": self.account.client_email,
                    "scope": SCOPE,
                    "aud": TOKEN_URL,
                    "iat": now,
                    "exp": now + 3600,
                }
            )
            r = http.post(
                TOKEN_URL,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": assertion,
                },
            )
            if r.status_code != 200:
                raise GoogleWalletError(f"token de Google rechazado ({r.status_code})")
            body = r.json()
            self._token = (body["access_token"], now + int(body.get("expires_in", 3600)))
            return self._token[0]

    def _call(self, http: httpx.Client, method: str, path: str, body: dict[str, Any]) -> int:
        r = http.request(
            method,
            f"{API_BASE}/{path}",
            json=body,
            headers={"Authorization": f"Bearer {self._access_token(http)}"},
        )
        if r.status_code >= 400 and r.status_code != 409:
            # Sin el cuerpo: puede repetir datos del titular.
            log.error("google wallet api error", extra={"path": path, "status": r.status_code})
            raise GoogleWalletError(f"Google Wallet respondió {r.status_code} en {path}")
        return r.status_code

    def _ensure_class(self, http: httpx.Client) -> None:
        if self._class_ready:
            return
        # Clase mínima compartida por todos los pases; 409 = ya existe.
        self._call(
            http,
            "POST",
            "genericClass",
            {"id": self.class_id, "multipleDevicesAndHoldersAllowedStatus": "ONE_USER_ALL_DEVICES"},
        )
        self._class_ready = True

    def publish(self, document: dict[str, Any]) -> str:
        """Crea (o, si ya existía, reemplaza) el objeto y devuelve el enlace para guardarlo."""
        try:
            with self._http() as http:
                self._ensure_class(http)
                if self._call(http, "POST", "genericObject", document) == 409:
                    # Canje anterior que no llegó a confirmarse: el objeto ya existe con esta id.
                    self._call(http, "PUT", f"genericObject/{document['id']}", document)
        except httpx.HTTPError as exc:  # red, tiempo de espera, respuesta ilegible
            raise GoogleWalletError(f"Google Wallet no respondió: {type(exc).__name__}") from exc
        return self.save_url(document["id"])

    def save_url(self, object_id: str) -> str:
        token = self.account.sign(
            {
                "iss": self.account.client_email,
                "aud": "google",
                "typ": "savetowallet",
                "iat": int(time.time()),
                "origins": [self.origin],
                "payload": {"genericObjects": [{"id": object_id}]},
            }
        )
        return SAVE_URL + token


def generic_object(
    wallet: GoogleWallet,
    *,
    serial_number: str,
    organization_name: str,
    credential_name: str,
    claims: dict[str, Any],
    issued_at: datetime,
    expires_at: datetime,
    verify_url: str,
    logo_url: str,
) -> dict[str, Any]:
    """Objeto genérico: emisor, título (p. ej. el curso), titular, datos y QR de verificación."""
    flat = dict(_flatten(claims))
    holder = " ".join(str(flat[k]) for k in ("given_name", "family_name") if k in flat)
    title = flat.get("course.title") or flat.get("title") or credential_name
    shown = {"given_name", "family_name", "course.title", "title"}

    def text(value: str) -> dict[str, Any]:
        return {"defaultValue": {"language": "es", "value": value}}

    # Con titular, el subtítulo es su nombre y el tipo de credencial pasa a los datos.
    modules = [{"id": "type", "header": "Credencial", "body": credential_name}] if holder else []
    modules += [
        {"id": f"c{i}", "header": _label(path), "body": str(value)}
        for i, (path, value) in enumerate(flat.items())
        if path not in shown
    ]
    modules += [
        {"id": "issued", "header": "Emitida", "body": issued_at.astimezone(UTC).date().isoformat()},
        {
            "id": "expires",
            "header": "Válida hasta",
            "body": expires_at.astimezone(UTC).date().isoformat(),
        },
        {"id": "credential", "header": "Identificador", "body": serial_number},
        {
            "id": "how",
            "header": "Cómo verificar",
            "body": "Escanee el código QR: abre la verificación de Aletheia, que comprueba la "
            "firma del emisor y si la credencial sigue vigente o fue revocada.",
        },
    ]
    return {
        "id": wallet.object_id(serial_number),
        "classId": wallet.class_id,
        "state": "ACTIVE",
        "cardTitle": text(organization_name),
        "subheader": text(holder or credential_name),
        "header": text(str(title)),
        "logo": {
            "sourceUri": {"uri": logo_url},
            "contentDescription": text(organization_name),
        },
        "hexBackgroundColor": "#141b20",
        "textModulesData": modules,
        "barcode": {"type": "QR_CODE", "value": verify_url, "alternateText": "Verificar"},
        "validTimeInterval": {
            "start": {"date": issued_at.astimezone(UTC).isoformat(timespec="seconds")},
            "end": {"date": expires_at.astimezone(UTC).isoformat(timespec="seconds")},
        },
    }


def load_google_wallet(settings: Settings) -> GoogleWallet | None:
    if not settings.google_wallet_issuer_id or settings.google_wallet_service_account is None:
        return None
    account = ServiceAccount.from_json(settings.google_wallet_service_account.get_secret_value())
    return GoogleWallet(settings.google_wallet_issuer_id, account, settings.public_base)
