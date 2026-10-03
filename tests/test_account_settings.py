"""Configuración: cuenta propia (perfil, idioma, contraseña), organización e idioma
predeterminado, y restablecimiento de contraseñas de miembros (PostgreSQL)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from aletheia.organizations.keys import LocalDevBackend
from aletheia.organizations.service import bootstrap_organization
from aletheia.platform.config import Settings
from aletheia.platform.db import Database
from tests.fixtures_org import OWNER_EMAIL, OWNER_PASSWORD, _auth, _login
from tests.test_issuance_flow import CLAIMS

pytestmark = pytest.mark.db

NEW_PASSWORD = "a brand new long passphrase"


def _member(client: TestClient, token: str, email: str, role: str) -> dict[str, Any]:
    r = client.post(
        "/v1/members",
        json={"email": email, "display_name": email.split("@")[0], "role": role},
        headers=_auth(token),
    )
    assert r.status_code == 201, r.text
    return dict(r.json())


def _token(client: TestClient, email: str, password: str, **extra: Any) -> str:
    r = _login(client, email, password, **extra)
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


def test_account_profile_and_language(client: TestClient, owner_token: str) -> None:
    me = client.get("/v1/auth/me", headers=_auth(owner_token)).json()
    assert me["email"] == OWNER_EMAIL and me["display_name"] == "Propietaria"
    assert me["language"] is None  # sin elección: el de la organización

    r = client.patch(
        "/v1/auth/me",
        json={"display_name": "Ana Owner", "language": "en"},
        headers=_auth(owner_token),
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"email": OWNER_EMAIL, "display_name": "Ana Owner", "language": "en"}

    # Sólo se cambia lo enviado; language: null vuelve al de la organización.
    r = client.patch("/v1/auth/me", json={"language": None}, headers=_auth(owner_token))
    assert r.json()["display_name"] == "Ana Owner" and r.json()["language"] is None
    assert (
        client.patch("/v1/auth/me", json={"language": "fr"}, headers=_auth(owner_token)).status_code
        == 422
    )


def test_organization_settings(client: TestClient, owner_token: str) -> None:
    org = client.get("/v1/organization", headers=_auth(owner_token)).json()
    assert org["default_language"] == "es"
    r = client.patch(
        "/v1/organization",
        json={"name": "Universidad Renombrada", "default_language": "en"},
        headers=_auth(owner_token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "Universidad Renombrada" and r.json()["default_language"] == "en"
    events = client.get("/v1/audit-events?limit=50", headers=_auth(owner_token)).json()
    assert any(e["action"] == "organization.updated" for e in events)


def test_claim_info_carries_organization_language(
    client: TestClient, owner_token: str, template: dict[str, Any]
) -> None:
    client.patch("/v1/organization", json={"default_language": "en"}, headers=_auth(owner_token))
    offer = client.post(
        "/v1/credentials",
        json={"template": "course-completion", "claims": CLAIMS},
        headers=_auth(owner_token),
    ).json()
    path = urlparse(offer["claim_url"]).path.replace("/claim/", "/claim-info/")
    assert client.get(path).json()["language"] == "en"


def test_issuer_cannot_change_organization(client: TestClient, owner_token: str) -> None:
    created = _member(client, owner_token, "issuer@example.org", "issuer")
    issuer = _token(client, "issuer@example.org", created["temporary_password"])
    r = client.patch("/v1/organization", json={"name": "x"}, headers=_auth(issuer))
    assert r.status_code == 403
    # Pero sí su propia cuenta.
    r = client.patch("/v1/auth/me", json={"language": "en"}, headers=_auth(issuer))
    assert r.status_code == 200


def test_change_own_password(client: TestClient, owner_token: str) -> None:
    other_device = _token(client, OWNER_EMAIL, OWNER_PASSWORD)

    r = client.post(
        "/v1/auth/password",
        json={"current_password": "wrong password!!", "new_password": NEW_PASSWORD},
        headers=_auth(owner_token),
    )
    # 400 (no 401): el panel no debe cerrar la sesión por un error al escribir.
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_current_password"
    r = client.post(
        "/v1/auth/password",
        json={"current_password": OWNER_PASSWORD, "new_password": "short"},
        headers=_auth(owner_token),
    )
    assert r.status_code == 422
    r = client.post(
        "/v1/auth/password",
        json={"current_password": OWNER_PASSWORD, "new_password": OWNER_PASSWORD},
        headers=_auth(owner_token),
    )
    assert r.status_code == 400 and r.json()["error"]["code"] == "weak_password"

    r = client.post(
        "/v1/auth/password",
        json={"current_password": OWNER_PASSWORD, "new_password": NEW_PASSWORD},
        headers=_auth(owner_token),
    )
    assert r.status_code == 200 and r.json() == {"sessions_revoked": 1}
    # Esta sesión sigue; la del otro dispositivo se cerró; la contraseña vieja ya no sirve.
    assert client.get("/v1/auth/me", headers=_auth(owner_token)).status_code == 200
    assert client.get("/v1/auth/me", headers=_auth(other_device)).status_code == 401
    assert _login(client, OWNER_EMAIL, OWNER_PASSWORD).status_code == 401
    _token(client, OWNER_EMAIL, NEW_PASSWORD)


def test_api_keys_have_no_account(client: TestClient, owner_token: str) -> None:
    key = client.post(
        "/v1/api-clients",
        json={"name": "sis", "permissions": ["credentials:read"]},
        headers=_auth(owner_token),
    ).json()["key"]
    assert client.get("/v1/auth/me", headers=_auth(key)).json()["email"] is None
    r = client.patch("/v1/auth/me", json={"language": "en"}, headers=_auth(key))
    assert r.status_code == 403 and r.json()["error"]["code"] == "user_session_required"


def test_admin_resets_member_password(client: TestClient, owner_token: str) -> None:
    created = _member(client, owner_token, "issuer@example.org", "issuer")
    issuer_session = _token(client, "issuer@example.org", created["temporary_password"])

    r = client.post(f"/v1/members/{created['user_id']}/password-reset", headers=_auth(owner_token))
    assert r.status_code == 200, r.text
    temporary = r.json()["temporary_password"]
    assert r.json()["email"] == "issuer@example.org" and len(temporary) >= 12
    # Sus sesiones se cierran y sólo vale la temporal nueva.
    assert client.get("/v1/auth/me", headers=_auth(issuer_session)).status_code == 401
    assert _login(client, "issuer@example.org", created["temporary_password"]).status_code == 401
    _token(client, "issuer@example.org", temporary)
    events = client.get("/v1/audit-events?limit=50", headers=_auth(owner_token)).json()
    assert any(e["action"] == "member.password_reset" for e in events)


def test_password_reset_rules(
    client: TestClient, owner_token: str, org: dict[str, Any], app_settings: Settings
) -> None:
    # Nadie se restablece a sí mismo (para eso, cambio de contraseña).
    r = client.post(f"/v1/members/{org['owner_id']}/password-reset", headers=_auth(owner_token))
    assert r.status_code == 409 and r.json()["error"]["code"] == "use_password_change"

    # Un administrador no restablece a un propietario.
    admin = _member(client, owner_token, "admin@example.org", "admin")
    admin_token = _token(client, "admin@example.org", admin["temporary_password"])
    r = client.post(f"/v1/members/{org['owner_id']}/password-reset", headers=_auth(admin_token))
    assert r.status_code == 403

    # Un usuario de otra organización no se restablece desde ésta (la cuenta es global).
    db = Database(app_settings)
    try:
        with db.session(bypass_rls=True) as s:
            bootstrap_organization(
                s,
                LocalDevBackend(app_settings.dev_keys_dir, "test"),
                name="Otra organización",
                owner_email="other-owner@example.org",
                owner_display_name="Otra",
                owner_password=OWNER_PASSWORD,
            )
    finally:
        db.dispose()
    other = _token(client, "other-owner@example.org", OWNER_PASSWORD)
    shared = _member(client, other, "shared@example.org", "issuer")
    r = client.post(
        "/v1/members",
        json={"email": "shared@example.org", "display_name": "shared", "role": "issuer"},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201, r.text
    r = client.post(f"/v1/members/{shared['user_id']}/password-reset", headers=_auth(owner_token))
    assert r.status_code == 409 and r.json()["error"]["code"] == "member_in_other_organizations"
    # Y un miembro de otra organización no existe para ésta.
    lone = _member(client, other, "lone@example.org", "issuer")
    r = client.post(f"/v1/members/{lone['user_id']}/password-reset", headers=_auth(owner_token))
    assert r.status_code == 404
