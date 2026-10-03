"""Página de inicio y solicitudes de acceso «Empezar gratis» (PostgreSQL)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from aletheia.access import service as access
from aletheia.db import models
from aletheia.maintenance import run_maintenance
from aletheia.platform.config import Settings
from aletheia.platform.db import Database

pytestmark = pytest.mark.db

REQUEST = {
    "organization": "Club Ejemplo",
    "contact_name": "Ana Pérez",
    "email": "ana@club.example.com",
    "use_case": "Acreditaciones de socios",
    "website": "https://club.example.com",
    "language": "es",
}


def _stored(app_settings: Settings) -> list[models.AccessRequest]:
    db = Database(app_settings)
    try:
        with db.session(bypass_rls=True) as s:
            rows = list(s.scalars(select(models.AccessRequest)))
            s.expunge_all()
            return rows
    finally:
        db.dispose()


def test_home_page_is_served(client: TestClient, clean_db: None) -> None:
    r = client.get("/")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert r.headers["content-security-policy"].startswith("default-src 'self'")
    assert "CredoSeal" in r.text and 'href="/admin/"' in r.text and "hello@credoseal.com" in r.text
    assert client.get("/admin/static/landing.js").status_code == 200
    assert client.get("/admin/static/landing.css").status_code == 200
    # Favicon: SVG, ICO en la raíz e ícono para la pantalla de inicio del iPhone.
    assert 'rel="icon" href="/admin/static/favicon.svg"' in r.text
    ico = client.get("/favicon.ico")
    assert ico.status_code == 200 and ico.headers["content-type"] == "image/x-icon"
    assert ico.content[:4] == b"\x00\x00\x01\x00"
    assert client.get("/admin/static/favicon.svg").headers["content-type"] == "image/svg+xml"
    assert client.get("/admin/static/apple-touch-icon.png").status_code == 200
    # Vista previa al compartir: URLs absolutas con el origen público.
    assert "__PUBLIC_BASE__" not in r.text
    assert 'property="og:image" content="http://localhost:8000/admin/static/og-image.png"' in r.text
    og = client.get("/admin/static/og-image.png")
    assert og.status_code == 200 and og.content[:8] == b"\x89PNG\r\n\x1a\n"
    # Capturas del panel y de la verificación, en ambos idiomas.
    for name in (
        "home-panel-overview",
        "home-panel-offer",
        "home-mobile-claim",
        "home-mobile-verify",
    ):
        for lang in ("es", "en"):
            img = client.get(f"/admin/static/{name}-{lang}.webp")
            assert img.status_code == 200 and img.headers["content-type"] == "image/webp"
            assert img.content[:4] == b"RIFF" and img.content[8:12] == b"WEBP"


def test_access_request_is_stored(
    client: TestClient, clean_db: None, app_settings: Settings
) -> None:
    r = client.post("/public/access-requests", json=REQUEST)
    assert r.status_code == 202 and r.json() == {"received": True}
    [row] = _stored(app_settings)
    assert row.organization == "Club Ejemplo" and row.email == "ana@club.example.com"
    assert row.status == "pending" and row.processed_at is None and row.language == "es"


def test_honeypot_and_validation(
    client: TestClient, clean_db: None, app_settings: Settings
) -> None:
    # Bot: misma respuesta, nada guardado.
    assert (
        client.post("/public/access-requests", json={**REQUEST, "nickname": "x"}).status_code == 202
    )
    assert _stored(app_settings) == []
    for bad in ({"email": "not-an-email"}, {"organization": ""}, {"use_case": "x" * 2001}):
        assert client.post("/public/access-requests", json={**REQUEST, **bad}).status_code == 422


def test_rate_limited_per_email(client: TestClient, clean_db: None) -> None:
    codes = [client.post("/public/access-requests", json=REQUEST).status_code for _ in range(4)]
    assert codes == [202, 202, 202, 429]


def test_operator_lists_marks_and_maintenance_purges(
    client: TestClient, clean_db: None, app_settings: Settings
) -> None:
    client.post("/public/access-requests", json=REQUEST)
    client.post("/public/access-requests", json={**REQUEST, "email": "otra@example.com"})
    db = Database(app_settings)
    try:
        with db.session(bypass_rls=True) as s:
            pending = access.list_requests(s)
            assert [p.email for p in pending] == ["ana@club.example.com", "otra@example.com"]
            access.mark(s, str(pending[0].id), "approved")
            with pytest.raises(ValueError, match="approved or rejected"):
                access.mark(s, str(pending[1].id), "maybe")
        with db.session(bypass_rls=True) as s:
            assert [p.email for p in access.list_requests(s)] == ["otra@example.com"]
            assert len(access.list_requests(s, "approved")) == 1
            # Resuelta hace más de 180 días → se purga; la pendiente reciente se conserva.
            old = datetime.now(UTC) - timedelta(days=200)
            s.execute(
                update(models.AccessRequest)
                .where(models.AccessRequest.status == "approved")
                .values(processed_at=old, created_at=old)
            )
        with db.session(bypass_rls=True) as s:
            counts: dict[str, Any] = run_maintenance(s)
            assert counts["access_requests"] == 1
            assert [r.email for r in s.scalars(select(models.AccessRequest))] == [
                "otra@example.com"
            ]
    finally:
        db.dispose()
