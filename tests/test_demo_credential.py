"""«Pruébelo ahora»: credencial de muestra desde la página de inicio (PostgreSQL)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from aletheia.access.demo import setup_demo_template
from aletheia.api import create_app
from aletheia.db import models
from aletheia.platform.config import Settings
from aletheia.platform.db import Database

pytestmark = pytest.mark.db


@pytest.fixture
def demo_template(app_settings: Settings, org: dict[str, Any]) -> None:
    db = Database(app_settings)
    try:
        for _ in range(2):  # idempotente: la segunda vez no crea otra versión
            with db.session(bypass_rls=True) as s:
                setup_demo_template(s, org["public_id"])
        with db.session(bypass_rls=True) as s:
            versions = list(s.scalars(select(models.TemplateVersion)))
            assert [v.state for v in versions] == ["published"]
    finally:
        db.dispose()


@pytest.fixture
def demo_client(
    app_settings: Settings, org: dict[str, Any], demo_template: None
) -> Iterator[TestClient]:
    settings = app_settings.model_copy(
        update={"demo_organization": org["public_id"], "demo_daily_limit": 3}
    )
    with TestClient(create_app(settings), raise_server_exceptions=False) as c:
        yield c


def test_demo_disabled_without_organization(client: TestClient, clean_db: None) -> None:
    assert client.get("/public/demo").json() == {"enabled": False}
    assert client.post("/public/demo-credential", json={}).status_code == 404


def test_demo_offer_is_issued_by_the_demo_organization(
    demo_client: TestClient, app_settings: Settings, org: dict[str, Any]
) -> None:
    assert demo_client.get("/public/demo").json() == {"enabled": True}
    r = demo_client.post("/public/demo-credential", json={"given_name": "María José"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["claim_url"].endswith("/claim/" + body["claim_url"].rsplit("/", 1)[1])
    assert body["qr_svg"].startswith("data:image/svg+xml")
    assert len(body["tx_code"]) == 6 and body["member_id"].startswith("DEMO-")
    # La oferta funciona como cualquier otra: la página de reclamo la reconoce.
    offer_id = body["claim_url"].rsplit("/", 1)[1]
    assert demo_client.get(f"/claim-info/{offer_id}").status_code == 200
    db = Database(app_settings)
    try:
        with db.session(bypass_rls=True) as s:
            [issuance] = s.scalars(select(models.Issuance))
            assert issuance.organization_id == org["id"] and issuance.holder_reference == "demo"
            [event] = s.scalars(
                select(models.AuditEvent).where(models.AuditEvent.action == "credential.offered")
            )
            assert event.actor_type == "system" and event.actor_id is None
    finally:
        db.dispose()


def test_demo_validates_name_and_has_a_daily_cap(demo_client: TestClient) -> None:
    for bad in ("<b>hola</b>", "Ana1", "x" * 41, "https://evil.example"):
        r = demo_client.post("/public/demo-credential", json={"given_name": bad})
        assert r.status_code == 422
    codes = [demo_client.post("/public/demo-credential", json={}).status_code for _ in range(4)]
    assert codes == [201, 201, 201, 429]  # tope diario de la prueba: 3
