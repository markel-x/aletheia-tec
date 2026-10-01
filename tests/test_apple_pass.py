"""Entrega como pase de Apple Wallet y verificación pública de su QR (PostgreSQL)."""

from __future__ import annotations

import hashlib
import io
import json
import struct
import zipfile
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from aletheia.platform.config import Settings
from aletheia.status import service as status_service
from aletheia.vc.signing import LocalDevSigner
from aletheia.verification import resolvers
from tests.fixtures_org import _auth
from tests.test_issuance_flow import CLAIMS
from tests.test_verification_api import _issue

pytestmark = pytest.mark.db


@pytest.fixture(autouse=True)
def _clear_caches() -> None:
    status_service.clear_cache()
    resolvers.clear_caches()


def _offer(client: TestClient, token: str) -> dict[str, Any]:
    r = client.post(
        "/v1/credentials",
        json={"template": "course-completion", "claims": CLAIMS},
        headers=_auth(token),
    )
    assert r.status_code == 201, r.text
    return r.json()


def _pass(client: TestClient, offer: dict[str, Any], tx_code: str) -> Any:
    return client.post(
        urlparse(offer["claim_url"]).path + "/apple-pass",
        data={"tx_code": tx_code},
        follow_redirects=False,
    )


def _png_size(data: bytes) -> tuple[int, int]:
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    return struct.unpack(">II", data[16:24])


def test_claim_page_and_pass_delivery(
    client: TestClient, owner_token: str, template: dict[str, Any], app_settings: Settings
) -> None:
    offer = _offer(client, owner_token)
    path = urlparse(offer["claim_url"]).path
    assert offer["claim_url"] == f"{app_settings.public_base}/claim/{path.rsplit('/', 1)[1]}"

    page = client.get(path)
    assert page.status_code == 200 and "claim.js" in page.text
    assert page.headers["content-security-policy"].startswith("default-src 'self'")
    info = client.get(path.replace("/claim/", "/claim-info/")).json()
    assert (
        info["apple_pass"] is True and info["apple_pass_trusted"] is False
    )  # certificado de desarrollo
    assert info["attempts_left"] == 5 and info["credential_name"] == "Certificado"
    assert info["offer_uri"] == offer["offer_uri"]

    # Código incorrecto: intento contado y vuelta a la página con el error.
    r = _pass(client, offer, "000000")
    assert r.status_code == 303 and r.headers["location"].endswith("?error=invalid_tx_code")
    assert client.get(path.replace("/claim/", "/claim-info/")).json()["attempts_left"] == 4

    r = _pass(client, offer, offer["tx_code"])
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/vnd.apple.pkpass"
    assert r.headers["content-disposition"] == f'attachment; filename="{offer["public_id"]}.pkpass"'

    archive = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(archive.namelist())
    assert {
        "pass.json",
        "manifest.json",
        "signature",
        "icon.png",
        "icon@2x.png",
        "logo.png",
    } <= names
    manifest = json.loads(archive.read("manifest.json"))
    assert set(manifest) == names - {"manifest.json", "signature"}
    for name, digest in manifest.items():
        assert hashlib.sha1(archive.read(name)).hexdigest() == digest  # noqa: S324 - formato PassKit
    assert _png_size(archive.read("icon.png")) == (29, 29)
    assert _png_size(archive.read("icon@3x.png")) == (87, 87)

    doc = json.loads(archive.read("pass.json"))
    assert (
        doc["formatVersion"] == 1 and doc["passTypeIdentifier"] == app_settings.pass_type_identifier
    )
    assert doc["teamIdentifier"] == app_settings.pass_team_identifier
    assert doc["serialNumber"] == offer["public_id"]
    assert doc["generic"]["primaryFields"][0]["value"] == "Curso de prueba"
    assert doc["generic"]["secondaryFields"][0]["value"] == "Ana Pérez"
    barcode = doc["barcodes"][0]
    assert barcode["format"] == "PKBarcodeFormatQR"
    assert barcode["message"].startswith(f"{app_settings.public_base}/v#")
    token = barcode["message"].split("#", 1)[1]

    # Firma PKCS#7 con el certificado del Pass Type ID y la cadena intermedia.
    certs = pkcs7.load_der_pkcs7_certificates(archive.read("signature"))
    assert len(certs) == 2
    uids = [c.subject.get_attributes_for_oid(NameOID.USER_ID) for c in certs]
    assert any(u and u[0].value == app_settings.pass_type_identifier for u in uids)

    # La emisión queda cerrada por el canal del pase, sin clave del titular.
    rec = client.get(f"/v1/credentials/{offer['id']}", headers=_auth(owner_token)).json()
    assert rec["state"] == "issued" and rec["delivery"] == "apple_pass"
    assert _pass(client, offer, offer["tx_code"]).headers["location"].endswith("?error=unavailable")
    assert client.get(path.replace("/claim/", "/claim-info/")).status_code == 404
    assert (
        client.get(urlparse(offer["credential_offer_uri"]).path).status_code == 404
    )  # no hay segundo canje

    # Verificación pública del QR: válida y con los datos firmados por el emisor.
    v = client.post("/public/pass-verifications", json={"token": token}).json()
    assert v["result"] == "valid", v["checks"]
    assert (
        v["claims"]["family_name"] == "Pérez"
        and v["claims"]["course"]["title"] == "Curso de prueba"
    )
    assert v["issuer_name"] == "Universidad de Prueba" and v["credential_name"] == "Certificado"
    assert "status" not in v["claims"] and "iss" not in v["claims"]

    # Firma alterada → inválida.
    jwt, rest = token.split("~", 1)
    head, body, sig = jwt.split(".")
    tampered = f"{head}.{body}.{sig[:-4]}AAAA~{rest}"
    assert (
        client.post("/public/pass-verifications", json={"token": tampered}).json()["result"]
        == "invalid"
    )

    # Revocación → el mismo QR deja de ser válido.
    client.post(
        f"/v1/credentials/{offer['id']}/revoke",
        json={"reason": "issued_in_error"},
        headers=_auth(owner_token),
    )
    status_service.clear_cache()
    v = client.post("/public/pass-verifications", json={"token": token}).json()
    assert v["result"] == "invalid" and v["reason"] == "credential_revoked" and v["claims"] is None

    # Las páginas públicas se sirven con CSP.
    assert client.get("/v").status_code == 200


def test_pass_offer_locks_after_attempts(
    client: TestClient, owner_token: str, template: dict[str, Any], app_settings: Settings
) -> None:
    offer = _offer(client, owner_token)
    for _ in range(app_settings.tx_code_max_attempts):
        _pass(client, offer, "999999")
    r = _pass(client, offer, offer["tx_code"])
    assert r.status_code == 303 and r.headers["location"].endswith("?error=locked")


def test_public_verification_rejects_holder_bound_and_garbage(
    client: TestClient,
    owner_token: str,
    org: dict[str, Any],
    template: dict[str, Any],
    app_settings: Settings,
) -> None:
    issuer = f"{app_settings.public_base}/issuers/{org['public_id']}"
    credential, _ = _issue(client, owner_token, LocalDevSigner.generate(environment="test"), issuer)
    r = client.post("/public/pass-verifications", json={"token": credential}).json()
    assert r["result"] == "invalid" and r["reason"] == "holder_bound_credential"
    r = client.post("/public/pass-verifications", json={"token": "no-es-un-token"}).json()
    assert r["result"] == "invalid" and r["reason"] == "malformed"
    assert client.get("/claim/zz").status_code == 404


def test_openid_offer_still_works_alongside(
    client: TestClient, owner_token: str, template: dict[str, Any]
) -> None:
    """La oferta sigue canjeable por OID4VCI; si un wallet ya canjeó el código, no hay pase."""
    offer = _offer(client, owner_token)
    doc = client.get(urlparse(offer["credential_offer_uri"]).path).json()
    grant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    tok = client.post(
        "/oid4vci/token",
        data={
            "grant_type": grant,
            "pre-authorized_code": doc["grants"][grant]["pre-authorized_code"],
            "tx_code": offer["tx_code"],
        },
    )
    assert tok.status_code == 200
    r = _pass(client, offer, offer["tx_code"])
    assert r.status_code == 303 and "error=unavailable" in r.headers["location"]
    assert parse_qs(urlparse(r.headers["location"]).query)["error"] == ["unavailable"]
