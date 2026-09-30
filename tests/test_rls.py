"""Row-Level Security (migración 0004) con el rol de la aplicación."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from aletheia.platform.config import Settings
from tests.conftest import TEST_APP_DATABASE_URL
from tests.fixtures_org import _auth

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not TEST_APP_DATABASE_URL, reason="requiere ALETHEIA_TEST_APP_DATABASE_URL"),
]


def _app_conn_count(org: uuid.UUID | None, *, bypass: bool = False) -> dict[str, int]:
    assert TEST_APP_DATABASE_URL
    engine = create_engine(TEST_APP_DATABASE_URL)
    try:
        with engine.begin() as conn:
            if org is not None:
                conn.execute(
                    text("SELECT set_config('app.current_org', :o, true)"), {"o": str(org)}
                )
            if bypass:
                conn.execute(text("SELECT set_config('app.bypass_rls', 'on', true)"))
            return {
                t: int(conn.execute(text(f"SELECT count(*) FROM {t}")).scalar_one())  # noqa: S608
                for t in ("organization", "signing_key", "membership", "audit_event")
            }
    finally:
        engine.dispose()


def _second_org(client: TestClient, owner_token: str, app_settings: Settings) -> uuid.UUID:
    from aletheia.organizations.keys import LocalDevBackend
    from aletheia.organizations.service import bootstrap_organization
    from aletheia.platform.db import Database

    db = Database(app_settings)
    try:
        with db.session(bypass_rls=True) as s:
            other, _, _ = bootstrap_organization(
                s,
                LocalDevBackend(app_settings.dev_keys_dir, "test"),
                name="Otra",
                owner_email="other@example.org",
                owner_display_name="Otra",
                owner_password="yet another strong password",
            )
            return other.id
    finally:
        db.dispose()


def test_app_role_sees_nothing_without_tenant(org: dict[str, Any]) -> None:
    assert _app_conn_count(None) == {
        "organization": 0,
        "signing_key": 0,
        "membership": 0,
        "audit_event": 0,
    }


def test_tenant_sees_only_its_rows_and_bypass_sees_all(
    client: TestClient, owner_token: str, org: dict[str, Any], app_settings: Settings
) -> None:
    other = _second_org(client, owner_token, app_settings)
    mine = _app_conn_count(org["id"])
    theirs = _app_conn_count(other)
    everything = _app_conn_count(None, bypass=True)
    assert mine["organization"] == theirs["organization"] == 1
    assert mine["signing_key"] == theirs["signing_key"] == 1
    assert everything["organization"] == 2 and everything["signing_key"] == 2
    assert everything["audit_event"] == mine["audit_event"] + theirs["audit_event"]


def test_with_check_blocks_writes_into_another_tenant(org: dict[str, Any]) -> None:
    assert TEST_APP_DATABASE_URL
    engine = create_engine(TEST_APP_DATABASE_URL)
    try:
        with engine.begin() as conn:
            conn.execute(
                text("SELECT set_config('app.current_org', :o, true)"), {"o": str(uuid.uuid4())}
            )
            insert = text(
                "INSERT INTO audit_event (id, organization_id, actor_type, action) "
                "VALUES (gen_random_uuid(), :org, 'system', 'x.y')"
            )
            with pytest.raises(DBAPIError, match="row-level security"):
                conn.execute(insert, {"org": str(org["id"])})
            conn.rollback()
        with pytest.raises(DBAPIError, match="permission denied"), engine.begin() as conn:
            conn.execute(text("UPDATE alembic_version SET version_num = version_num"))
    finally:
        engine.dispose()


def test_api_still_works_across_tenants_where_data_is_public(
    client: TestClient, owner_token: str, org: dict[str, Any], app_settings: Settings
) -> None:
    """Con RLS activo: el JWKS público de otra organización se sirve, y un verificador
    puede confiar en un emisor alojado de otra organización."""
    other = _second_org(client, owner_token, app_settings)
    engine = create_engine(TEST_APP_DATABASE_URL or "")
    try:
        with engine.begin() as conn:
            conn.execute(text("SELECT set_config('app.bypass_rls', 'on', true)"))
            other_public = conn.execute(
                text("SELECT public_id FROM organization WHERE id = :i"), {"i": str(other)}
            ).scalar_one()
    finally:
        engine.dispose()
    assert client.get(f"/.well-known/jwt-vc-issuer/issuers/{other_public}").status_code == 200
    policy = client.post(
        "/v1/trust-policies", json={"name": "p"}, headers=_auth(owner_token)
    ).json()
    issuer = f"{app_settings.public_base}/issuers/{other_public}"
    r = client.post(
        f"/v1/trust-policies/{policy['id']}/issuers",
        json={"issuer": issuer},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201, r.text
    assert r.json()["hosted_org_id"] == str(other)
    # Base http (desarrollo): el emisor alojado se acepta; uno externo http no (regresión 0003).
    assert issuer.startswith("http://")
    r = client.post(
        f"/v1/trust-policies/{policy['id']}/issuers",
        json={"issuer": "http://external.example/issuer"},
        headers=_auth(owner_token),
    )
    assert r.status_code == 400
