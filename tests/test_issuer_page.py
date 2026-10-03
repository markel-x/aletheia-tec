"""Página pública del emisor en su URL ``iss`` y sus datos (PostgreSQL)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from aletheia.platform.config import Settings
from tests.fixtures_org import _auth

pytestmark = pytest.mark.db


def test_issuer_url_opens_a_public_page(
    client: TestClient, org: dict[str, Any], owner_token: str, app_settings: Settings
) -> None:
    org_public_id = org["public_id"]
    issuer = client.get("/v1/organization", headers=_auth(owner_token)).json()["issuer"]
    assert issuer == f"{app_settings.public_base}/issuers/{org_public_id}"

    page = client.get(f"/issuers/{org_public_id}")
    assert page.status_code == 200 and "issuer.js" in page.text
    assert page.headers["content-security-policy"].startswith("default-src 'self'")

    info = client.get(f"/issuer-info/{org_public_id}")
    assert info.status_code == 200
    body = info.json()
    assert body["name"] == "Universidad de Prueba" and body["issuer"] == issuer
    assert body["language"] == "es"
    assert [k["kid"] for k in body["active_keys"]] == [org["kid"]]
    assert body["metadata"]["jwt_vc_issuer"].endswith(
        f"/.well-known/jwt-vc-issuer/issuers/{org_public_id}"
    )
    # Sólo datos públicos: nada de miembros, correos ni identificadores internos.
    assert set(body) == {"name", "issuer", "language", "since", "active_keys", "metadata"}
    assert str(org["id"]) not in info.text


def test_issuer_page_follows_profile_and_language(
    client: TestClient, org: dict[str, Any], owner_token: str
) -> None:
    client.put(
        "/v1/organization/issuer-profile",
        json={"display_name": "Instituto Público"},
        headers=_auth(owner_token),
    )
    client.patch("/v1/organization", json={"default_language": "en"}, headers=_auth(owner_token))
    body = client.get(f"/issuer-info/{org['public_id']}").json()
    assert body["name"] == "Instituto Público" and body["language"] == "en"


def test_unknown_or_disabled_issuer_is_not_found(
    client: TestClient, org: dict[str, Any], owner_token: str
) -> None:
    assert client.get("/issuer-info/org_doesnotexist0000000000").status_code == 404
    client.put(
        "/v1/organization/issuer-profile", json={"enabled": False}, headers=_auth(owner_token)
    )
    assert client.get(f"/issuer-info/{org['public_id']}").status_code == 404
    # La página carga igual (es estática) y muestra «emisor no encontrado» en el cliente.
    assert client.get(f"/issuers/{org['public_id']}").status_code == 200


def test_renaming_the_organization_updates_the_public_name(
    client: TestClient, org: dict[str, Any], owner_token: str
) -> None:
    info = client.get(f"/issuer-info/{org['public_id']}")
    assert info.headers["cache-control"] == "no-cache"
    # Mismo nombre en organización y perfil (alta): el nombre visible sigue al renombrar.
    client.patch("/v1/organization", json={"name": "Nuevo Nombre"}, headers=_auth(owner_token))
    assert client.get(f"/issuer-info/{org['public_id']}").json()["name"] == "Nuevo Nombre"
    profile = client.get("/v1/organization/issuer-profile", headers=_auth(owner_token)).json()
    assert profile["display_name"] == "Nuevo Nombre"

    # Con un nombre visible propio, renombrar la organización no lo pisa.
    client.put(
        "/v1/organization/issuer-profile",
        json={"display_name": "Marca Pública"},
        headers=_auth(owner_token),
    )
    client.patch("/v1/organization", json={"name": "Otro Nombre"}, headers=_auth(owner_token))
    assert client.get(f"/issuer-info/{org['public_id']}").json()["name"] == "Marca Pública"
