"""Flujo completo de organización, autenticación, permisos y claves (con PostgreSQL)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from aletheia.cli import main as cli_main
from aletheia.organizations.keys import LocalDevBackend
from aletheia.organizations.service import bootstrap_organization
from aletheia.platform.config import Settings
from aletheia.platform.db import Database
from tests.fixtures_org import OWNER_EMAIL, OWNER_PASSWORD, _auth, _login

pytestmark = pytest.mark.db


def test_login_and_me(client: TestClient, org: dict[str, Any]) -> None:
    r = _login(client, OWNER_EMAIL, OWNER_PASSWORD)
    assert r.status_code == 200
    body = r.json()
    assert body["role"] == "owner" and "signing_keys:compromise" in body["permissions"]
    me = client.get("/v1/auth/me", headers=_auth(body["token"]))
    assert me.status_code == 200 and me.json()["actor_type"] == "user"

    assert client.get("/v1/auth/me").status_code == 401
    assert client.get("/v1/auth/me", headers=_auth("st_" + "A" * 43)).status_code == 401

    assert client.post("/v1/auth/logout", headers=_auth(body["token"])).status_code == 204
    assert client.get("/v1/auth/me", headers=_auth(body["token"])).status_code == 401


def test_login_failures_are_uniform_and_rate_limited(
    client: TestClient, org: dict[str, Any]
) -> None:
    wrong = _login(client, OWNER_EMAIL, "wrong password")
    unknown = _login(client, "nobody@example.org", "wrong password")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["error"]["code"] == unknown.json()["error"]["code"] == "invalid_credentials"
    # 10 intentos por correo y ventana; ya van 1 (y 1 de otro correo).
    for _ in range(9):
        assert _login(client, OWNER_EMAIL, "wrong password").status_code == 401
    r = _login(client, OWNER_EMAIL, OWNER_PASSWORD)  # incluso la contraseña correcta
    assert r.status_code == 429 and r.json()["error"]["code"] == "rate_limited"


def test_organization_and_issuer_profile(
    client: TestClient, org: dict[str, Any], owner_token: str
) -> None:
    r = client.get("/v1/organization", headers=_auth(owner_token))
    assert r.status_code == 200
    assert r.json()["public_id"] == org["public_id"]
    assert r.json()["issuer"].endswith(f"/issuers/{org['public_id']}")

    r = client.put(
        "/v1/organization/issuer-profile",
        json={"display_name": "Universidad de Prueba (emisor)", "offer_ttl_hours": 24},
        headers=_auth(owner_token),
    )
    assert r.status_code == 200 and r.json()["offer_ttl_hours"] == 24
    assert (
        client.put(
            "/v1/organization/issuer-profile",
            json={"offer_ttl_hours": 999},
            headers=_auth(owner_token),
        ).status_code
        == 422
    )


def test_members_roles_and_permissions(
    client: TestClient, org: dict[str, Any], owner_token: str
) -> None:
    r = client.post(
        "/v1/members",
        json={"email": "issuer@example.org", "display_name": "Emisor", "role": "issuer"},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201, r.text
    issuer = r.json()
    assert issuer["temporary_password"]  # generada, se muestra una sola vez
    assert (
        client.post(
            "/v1/members",
            json={"email": "issuer@example.org", "display_name": "Emisor", "role": "issuer"},
            headers=_auth(owner_token),
        ).status_code
        == 409
    )

    it = _login(client, "issuer@example.org", issuer["temporary_password"]).json()["token"]
    # El emisor no gestiona miembros, claves de API ni claves de firma.
    assert client.get("/v1/members", headers=_auth(it)).status_code == 403
    assert client.get("/v1/api-clients", headers=_auth(it)).status_code == 403
    assert client.post("/v1/signing-keys/rotate", headers=_auth(it)).status_code == 403
    assert client.get("/v1/organization", headers=_auth(it)).status_code == 200

    # Cambio de rol y protección del último propietario.
    r = client.patch(
        f"/v1/members/{issuer['user_id']}", json={"role": "admin"}, headers=_auth(owner_token)
    )
    assert r.status_code == 200 and r.json()["role"] == "admin"
    r = client.patch(
        f"/v1/members/{org['owner_id']}", json={"role": "admin"}, headers=_auth(owner_token)
    )
    assert r.status_code == 409 and r.json()["error"]["code"] == "last_owner"
    assert (
        client.delete(f"/v1/members/{org['owner_id']}", headers=_auth(owner_token)).status_code
        == 409
    )

    # Al quitar al miembro, su sesión muere.
    assert (
        client.delete(f"/v1/members/{issuer['user_id']}", headers=_auth(owner_token)).status_code
        == 204
    )
    assert client.get("/v1/auth/me", headers=_auth(it)).status_code == 401
    assert (
        client.delete(f"/v1/members/{issuer['user_id']}", headers=_auth(owner_token)).status_code
        == 404
    )


def test_api_clients(client: TestClient, org: dict[str, Any], owner_token: str) -> None:
    r = client.post(
        "/v1/api-clients",
        json={"name": "SIS", "permissions": ["credentials:issue", "credentials:read"]},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201, r.text
    created = r.json()
    key = created["key"]
    assert key.startswith(created["key_prefix"] + "_")

    listed = client.get("/v1/api-clients", headers=_auth(owner_token)).json()
    assert [c["id"] for c in listed] == [created["id"]] and "key" not in listed[0]

    me = client.get("/v1/auth/me", headers=_auth(key))
    assert me.status_code == 200
    assert me.json()["actor_type"] == "api_client"
    assert me.json()["permissions"] == ["credentials:issue", "credentials:read"]
    # La clave de API no puede hacer lo que no tiene, ni crear otras claves.
    assert client.get("/v1/members", headers=_auth(key)).status_code == 403
    assert client.get("/v1/api-clients", headers=_auth(key)).status_code == 403

    # Permisos vedados a claves de API, desconocidos o superiores a los del creador.
    for perms in (["members:manage"], ["nope:x"]):
        r = client.post(
            "/v1/api-clients", json={"name": "x", "permissions": perms}, headers=_auth(owner_token)
        )
        assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_permissions"

    # Clave alterada → 401; revocada → 401.
    assert client.get("/v1/auth/me", headers=_auth(key[:-2] + "zz")).status_code == 401
    assert (
        client.delete(f"/v1/api-clients/{created['id']}", headers=_auth(owner_token)).status_code
        == 200
    )
    assert client.get("/v1/auth/me", headers=_auth(key)).status_code == 401


def test_signing_keys_rotation_compromise_and_metadata(
    client: TestClient, org: dict[str, Any], owner_token: str
) -> None:
    well_known = f"/.well-known/jwt-vc-issuer/issuers/{org['public_id']}"
    r = client.get(well_known)
    assert r.status_code == 200
    assert r.headers["Cache-Control"] == "public, max-age=300"
    assert r.json()["issuer"].endswith(f"/issuers/{org['public_id']}")
    assert [k["kid"] for k in r.json()["jwks"]["keys"]] == [org["kid"]]
    assert "d" not in r.json()["jwks"]["keys"][0]
    assert client.get("/.well-known/jwt-vc-issuer/issuers/org_nope").status_code == 404

    r = client.post("/v1/signing-keys/rotate", headers=_auth(owner_token))
    assert r.status_code == 201
    new_kid = r.json()["kid"]
    keys = client.get("/v1/signing-keys", headers=_auth(owner_token)).json()
    assert {k["kid"]: k["state"] for k in keys} == {org["kid"]: "retired", new_kid: "active"}
    # La retirada sigue publicada (credenciales antiguas siguen verificando).
    assert {k["kid"] for k in client.get(well_known).json()["jwks"]["keys"]} == {
        org["kid"],
        new_kid,
    }

    # Compromiso: sólo el propietario; la clave sale del JWKS; si era activa se crea otra.
    admin = client.post(
        "/v1/members",
        json={
            "email": "admin@example.org",
            "display_name": "Admin",
            "role": "admin",
            "password": "another strong password",
        },
        headers=_auth(owner_token),
    ).json()
    at = _login(client, "admin@example.org", "another strong password").json()["token"]
    active_id = next(k["id"] for k in keys if k["kid"] == new_kid)
    assert (
        client.post(f"/v1/signing-keys/{active_id}/compromise", headers=_auth(at)).status_code
        == 403
    )
    r = client.post(f"/v1/signing-keys/{active_id}/compromise", headers=_auth(owner_token))
    assert r.status_code == 200 and r.json()["state"] == "compromised"
    keys = client.get("/v1/signing-keys", headers=_auth(owner_token)).json()
    states = {k["kid"]: k["state"] for k in keys}
    assert states[new_kid] == "compromised" and list(states.values()).count("active") == 1
    published = {k["kid"] for k in client.get(well_known).json()["jwks"]["keys"]}
    assert new_kid not in published and org["kid"] in published

    # Auditoría: el auditor lee; el emisor no.
    events = client.get("/v1/audit-events", headers=_auth(owner_token)).json()
    actions = [e["action"] for e in events]
    assert "signing_key.compromised" in actions and "signing_key.retired" in actions
    assert "organization.created" in actions and "session.created" in actions
    assert all("password" not in str(e["metadata"]) for e in events)
    del admin


def test_cross_organization_isolation(
    client: TestClient, org: dict[str, Any], owner_token: str, app_settings: Settings
) -> None:
    db = Database(app_settings)
    backend = LocalDevBackend(app_settings.dev_keys_dir, "test")
    try:
        with db.session() as s:
            _, _, other_key = bootstrap_organization(
                s,
                backend,
                name="Otra",
                owner_email="other@example.org",
                owner_display_name="Otra",
                owner_password="yet another strong password",
            )
            other_key_id, other_owner_id = other_key.id, None
            other_owner_id = s.execute(
                text("SELECT id FROM user_account WHERE email='other@example.org'")
            ).scalar()
    finally:
        db.dispose()
    # Recursos de otra organización: 404, nunca 403.
    assert (
        client.post(
            f"/v1/signing-keys/{other_key_id}/compromise", headers=_auth(owner_token)
        ).status_code
        == 404
    )
    assert (
        client.delete(f"/v1/members/{other_owner_id}", headers=_auth(owner_token)).status_code
        == 404
    )
    kids = {k["kid"] for k in client.get("/v1/signing-keys", headers=_auth(owner_token)).json()}
    assert other_key.kid not in kids


def test_user_in_two_organizations_must_choose(
    client: TestClient, org: dict[str, Any], owner_token: str, app_settings: Settings
) -> None:
    db = Database(app_settings)
    backend = LocalDevBackend(app_settings.dev_keys_dir, "test")
    try:
        with db.session() as s:
            other, _, _ = bootstrap_organization(
                s,
                backend,
                name="Otra",
                owner_email="other@example.org",
                owner_display_name="Otra",
                owner_password="yet another strong password",
            )
            other_public_id = other.public_id
    finally:
        db.dispose()
    other_token = _login(client, "other@example.org", "yet another strong password").json()["token"]
    r = client.post(
        "/v1/members",
        json={"email": OWNER_EMAIL, "display_name": "Propietaria", "role": "auditor"},
        headers=_auth(other_token),
    )
    assert r.status_code == 201 and r.json()["temporary_password"] is None  # usuario existente
    r = _login(client, OWNER_EMAIL, OWNER_PASSWORD)
    assert r.status_code == 400 and r.json()["error"]["code"] == "organization_required"
    assert set(r.json()["error"]["details"]["organizations"]) == {org["public_id"], other_public_id}
    r = _login(client, OWNER_EMAIL, OWNER_PASSWORD, organization=other_public_id)
    assert r.status_code == 200 and r.json()["role"] == "auditor"


def test_bootstrap_cli(
    app_settings: Settings,
    clean_db: None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("ALETHEIA_ENV", "test")
    monkeypatch.setenv("ALETHEIA_DATABASE_URL", app_settings.require_database_url())
    monkeypatch.setenv("ALETHEIA_SIGNING_BACKEND", "local_dev")
    monkeypatch.setenv("ALETHEIA_DEV_KEYS_DIR", str(app_settings.dev_keys_dir))
    monkeypatch.setenv("ALETHEIA_LOG_FORMAT", "text")
    monkeypatch.setenv("ALETHEIA_BOOTSTRAP_PASSWORD", OWNER_PASSWORD)
    from aletheia.platform.config import get_settings

    get_settings.cache_clear()
    code = cli_main(
        [
            "bootstrap",
            "--name",
            "CLI Org",
            "--owner-email",
            "cli@example.org",
            "--owner-name",
            "CLI",
        ]
    )
    out = capsys.readouterr().out.strip().splitlines()[-1]
    assert code == 0, out
    import json

    result = json.loads(out)
    assert result["organization"].startswith("org_") and result["signing_kid"]
    assert OWNER_PASSWORD not in out
    # Repetir con el mismo correo falla limpiamente.
    assert (
        cli_main(
            [
                "bootstrap",
                "--name",
                "CLI Org 2",
                "--owner-email",
                "cli@example.org",
                "--owner-name",
                "CLI",
            ]
        )
        == 1
    )
    get_settings.cache_clear()
