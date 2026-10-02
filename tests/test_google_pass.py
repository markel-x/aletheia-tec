"""Entrega como pase de Google Wallet con la API de Google simulada (PostgreSQL)."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from aletheia.passes.google import (
    API_BASE,
    SAVE_URL,
    SCOPE,
    TOKEN_URL,
    GoogleWallet,
    GoogleWalletError,
    ServiceAccount,
)
from aletheia.platform.config import Settings
from aletheia.status import service as status_service
from aletheia.verification import resolvers
from tests.fixtures_org import _auth
from tests.test_issuance_flow import CLAIMS

pytestmark = pytest.mark.db

ISSUER_ID = "3388000000012345678"
EMAIL = "wallet@aletheia-test.iam.gserviceaccount.com"


@pytest.fixture(autouse=True)
def _clear_caches() -> None:
    status_service.clear_cache()
    resolvers.clear_caches()


@dataclass
class FakeGoogle:
    """API de Google Wallet en memoria: registra las llamadas y responde como Google."""

    key: rsa.RSAPrivateKey
    calls: list[tuple[str, str, Any]] = field(default_factory=list)
    objects: dict[str, dict[str, Any]] = field(default_factory=dict)
    classes: set[str] = field(default_factory=set)
    fail_objects: bool = False
    unreachable: bool = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.unreachable:
            raise httpx.ConnectTimeout("timed out", request=request)
        url = str(request.url)
        if url == TOKEN_URL:
            form = parse_qs(request.content.decode())
            self.calls.append(("token", url, form))
            return httpx.Response(200, json={"access_token": "ya29.test", "expires_in": 3600})
        assert request.headers["authorization"] == "Bearer ya29.test"
        body = json.loads(request.content)
        path = url.removeprefix(API_BASE + "/")
        self.calls.append((request.method, path, body))
        if path == "genericClass":
            if body["id"] in self.classes:
                return httpx.Response(409, json={"error": {"code": 409}})
            self.classes.add(body["id"])
            return httpx.Response(200, json=body)
        if self.fail_objects:
            return httpx.Response(500, json={"error": {"code": 500}})
        if request.method == "POST" and path == "genericObject":
            if body["id"] in self.objects:
                return httpx.Response(409, json={"error": {"code": 409}})
            self.objects[body["id"]] = body
            return httpx.Response(200, json=body)
        if request.method == "PUT" and path.startswith("genericObject/"):
            self.objects[path.split("/", 1)[1]] = body
            return httpx.Response(200, json=body)
        return httpx.Response(404)


@pytest.fixture
def google(client: TestClient, app_settings: Settings) -> FakeGoogle:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fake = FakeGoogle(key)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    account = ServiceAccount.from_json(
        json.dumps({"client_email": EMAIL, "private_key": pem, "private_key_id": "k1"})
    )
    client.app.state.google_wallet = GoogleWallet(  # type: ignore[attr-defined]
        ISSUER_ID, account, app_settings.public_base, transport=httpx.MockTransport(fake.handler)
    )
    return fake


def _offer(client: TestClient, token: str) -> dict[str, Any]:
    r = client.post(
        "/v1/credentials",
        json={"template": "course-completion", "claims": CLAIMS},
        headers=_auth(token),
    )
    assert r.status_code == 201, r.text
    return r.json()


def _redeem(client: TestClient, offer: dict[str, Any], tx_code: str) -> Any:
    return client.post(
        urlparse(offer["claim_url"]).path + "/google-pass", data={"tx_code": tx_code}
    )


def _info(client: TestClient, offer: dict[str, Any]) -> Any:
    return client.get(urlparse(offer["claim_url"]).path.replace("/claim/", "/claim-info/"))


def _decode(google: FakeGoogle, token: str, **kwargs: Any) -> dict[str, Any]:
    claims: dict[str, Any] = jwt.decode(
        token, google.key.public_key(), algorithms=["RS256"], **kwargs
    )
    return claims


def test_google_pass_delivery(
    client: TestClient,
    owner_token: str,
    template: dict[str, Any],
    app_settings: Settings,
    google: FakeGoogle,
) -> None:
    offer = _offer(client, owner_token)
    assert _info(client, offer).json()["google_pass"] is True

    # Código incorrecto: intento contado, sin llamar a Google.
    r = _redeem(client, offer, "000000")
    assert r.status_code == 400 and r.json() == {"error": "invalid_tx_code"}
    assert _info(client, offer).json()["attempts_left"] == 4 and google.calls == []

    r = _redeem(client, offer, offer["tx_code"])
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "no-store"
    save_url = r.json()["save_url"]
    assert save_url.startswith(SAVE_URL)

    # Token OAuth: JWT de la cuenta de servicio para el alcance de emisor de Wallet.
    kind, _, form = google.calls[0]
    assert kind == "token"
    assert form["grant_type"] == ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
    assertion = _decode(google, form["assertion"][0], audience=TOKEN_URL)
    assert assertion["iss"] == EMAIL and assertion["scope"] == SCOPE

    # Clase compartida y objeto con los datos y el QR de verificación.
    object_id = f"{ISSUER_ID}.{offer['public_id']}"
    assert [c[:2] for c in google.calls[1:]] == [
        ("POST", "genericClass"),
        ("POST", "genericObject"),
    ]
    obj = google.objects[object_id]
    assert obj["classId"] == f"{ISSUER_ID}.aletheia_credential" and obj["state"] == "ACTIVE"
    assert obj["header"]["defaultValue"]["value"] == "Curso de prueba"
    assert obj["subheader"]["defaultValue"]["value"] == "Ana Pérez"
    assert obj["cardTitle"]["defaultValue"]["value"] == "Universidad de Prueba"
    assert obj["logo"]["sourceUri"]["uri"] == f"{app_settings.public_base}/wallet/logo.png"
    assert obj["barcode"]["type"] == "QR_CODE"
    assert obj["barcode"]["value"].startswith(f"{app_settings.public_base}/v#")

    # Enlace «Agregar a Google Wallet»: sólo referencia el objeto, firmado por la cuenta.
    save = _decode(google, save_url.removeprefix(SAVE_URL), audience="google")
    assert save["iss"] == EMAIL and save["typ"] == "savetowallet"
    assert save["origins"] == [app_settings.public_base]
    assert save["payload"] == {"genericObjects": [{"id": object_id}]}
    assert jwt.get_unverified_header(save_url.removeprefix(SAVE_URL))["kid"] == "k1"

    # Emisión cerrada por el canal de Google; no hay segundo canje.
    rec = client.get(f"/v1/credentials/{offer['id']}", headers=_auth(owner_token)).json()
    assert rec["state"] == "issued" and rec["delivery"] == "google_pass"
    assert _redeem(client, offer, offer["tx_code"]).json() == {"error": "unavailable"}
    assert _info(client, offer).status_code == 404

    # El QR del pase se verifica igual que el de Apple, y deja de valer al revocar.
    token = obj["barcode"]["value"].split("#", 1)[1]
    v = client.post("/public/pass-verifications", json={"token": token}).json()
    assert v["result"] == "valid", v["checks"]
    client.post(
        f"/v1/credentials/{offer['id']}/revoke",
        json={"reason": "issued_in_error"},
        headers=_auth(owner_token),
    )
    status_service.clear_cache()
    v = client.post("/public/pass-verifications", json={"token": token}).json()
    assert v["result"] == "invalid" and v["reason"] == "credential_revoked"

    # La clase se crea una sola vez por proceso.
    second = _offer(client, owner_token)
    assert _redeem(client, second, second["tx_code"]).status_code == 200
    assert [c[1] for c in google.calls].count("genericClass") == 1


def test_google_failure_keeps_offer_available(
    client: TestClient, owner_token: str, template: dict[str, Any], google: FakeGoogle
) -> None:
    offer = _offer(client, owner_token)
    google.fail_objects = True
    r = _redeem(client, offer, offer["tx_code"])
    assert r.status_code == 502 and r.json() == {"error": "google_unavailable"}

    # Sin pase en Google no hay emisión: la oferta sigue abierta y el código vale.
    rec = client.get(f"/v1/credentials/{offer['id']}", headers=_auth(owner_token)).json()
    assert rec["state"] == "offered"
    assert _info(client, offer).json()["attempts_left"] == 5

    # Google inalcanzable: mismo resultado, sin error 500.
    google.fail_objects = False
    google.unreachable = True
    r = _redeem(client, offer, offer["tx_code"])
    assert r.status_code == 502 and r.json() == {"error": "google_unavailable"}
    google.unreachable = False

    # Reintento: el objeto ya existe (409) → se reemplaza con la credencial nueva.
    google.fail_objects = False
    object_id = f"{ISSUER_ID}.{offer['public_id']}"
    google.objects[object_id] = {"id": object_id, "stale": True}
    assert _redeem(client, offer, offer["tx_code"]).status_code == 200
    assert ("PUT", f"genericObject/{object_id}") in [c[:2] for c in google.calls]
    assert "stale" not in google.objects[object_id]


def test_google_pass_disabled_without_configuration(
    client: TestClient, owner_token: str, template: dict[str, Any]
) -> None:
    offer = _offer(client, owner_token)
    assert _info(client, offer).json()["google_pass"] is False
    assert _redeem(client, offer, offer["tx_code"]).status_code == 404


def test_wallet_logo_is_public_png(client: TestClient) -> None:
    r = client.get("/wallet/logo.png")
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"
    assert r.content[:8] == b"\x89PNG\r\n\x1a\n"


def test_service_account_json_is_validated() -> None:
    bad: list[Callable[[], object]] = [
        lambda: ServiceAccount.from_json("not json"),
        lambda: ServiceAccount.from_json(json.dumps({"client_email": EMAIL})),
        lambda: ServiceAccount.from_json(json.dumps({"client_email": EMAIL, "private_key": "x"})),
    ]
    for build in bad:
        with pytest.raises(GoogleWalletError):
            build()
