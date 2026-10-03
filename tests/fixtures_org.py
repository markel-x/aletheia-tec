"""Fixtures compartidas por las pruebas de API con PostgreSQL: organización de
prueba, cliente HTTP y sesión del propietario."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from aletheia.api import create_app
from aletheia.organizations.keys import LocalDevBackend
from aletheia.organizations.service import bootstrap_organization
from aletheia.platform.config import Settings
from aletheia.platform.db import Database
from tests.test_schema import COURSE_SCHEMA

OWNER_EMAIL = "owner@example.org"
OWNER_PASSWORD = "correct horse battery staple"


@pytest.fixture
def app_settings(db_settings: Settings, tmp_path: Path) -> Settings:
    return db_settings.model_copy(update={"signing_backend": "local_dev", "dev_keys_dir": tmp_path})


@pytest.fixture
def clean_db(migrated_database_url: str) -> None:
    engine = create_engine(migrated_database_url)  # propietario: TRUNCATE no es del rol de la app
    tables = (
        "audit_event",
        "usage_event",
        "verification_record",
        "presentation_request",
        "trusted_issuer",
        "trust_policy",
        "issuance_pending_claims",
        "oid4vci_access_token",
        "issuance",
        "credential_status",
        "status_list",
        "template_version",
        "credential_template",
        "signing_key",
        "issuer_profile",
        "api_client",
        "session",
        "membership",
        "user_account",
        "organization",
        "rate_limit_bucket",
        "access_request",
        "idempotency_record",
        "oid4vci_nonce",
    )
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE " + ", ".join(tables) + " CASCADE"))
    engine.dispose()


@pytest.fixture
def org(app_settings: Settings, clean_db: None) -> dict[str, Any]:
    db = Database(app_settings)
    backend = LocalDevBackend(app_settings.dev_keys_dir, "test")
    try:
        with db.session(bypass_rls=True) as s:
            o, owner, key = bootstrap_organization(
                s,
                backend,
                name="Universidad de Prueba",
                owner_email=OWNER_EMAIL,
                owner_display_name="Propietaria",
                owner_password=OWNER_PASSWORD,
            )
            return {"public_id": o.public_id, "id": o.id, "owner_id": owner.id, "kid": key.kid}
    finally:
        db.dispose()


@pytest.fixture
def client(app_settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(app_settings), raise_server_exceptions=False) as c:
        yield c


def _login(client: TestClient, email: str, password: str, **extra: Any) -> Any:
    return client.post("/v1/auth/login", json={"email": email, "password": password, **extra})


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def owner_token(client: TestClient, org: dict[str, Any]) -> str:
    r = _login(client, OWNER_EMAIL, OWNER_PASSWORD)
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


@pytest.fixture
def template(client: TestClient, owner_token: str) -> dict[str, Any]:
    r = client.post(
        "/v1/templates",
        json={"slug": "course-completion", "name": "Certificado"},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201, r.text
    tpl = r.json()
    r = client.post(
        f"/v1/templates/{tpl['id']}/versions",
        json={
            "claims_schema": COURSE_SCHEMA,
            "selective_disclosure": [
                "given_name",
                "family_name",
                "completion_date",
                "course.grade",
                "student_id",
            ],
            "validity_days": 365,
            "display": {"display": [{"name": "Certificado de curso", "locale": "es"}]},
        },
        headers=_auth(owner_token),
    )
    assert r.status_code == 201, r.text
    ver = r.json()
    assert ver["state"] == "draft"
    r = client.post(
        f"/v1/templates/{tpl['id']}/versions/{ver['id']}/publish", headers=_auth(owner_token)
    )
    assert r.status_code == 200 and r.json()["state"] == "published"
    return tpl
