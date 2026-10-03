"""API sin frontend (AWS: CloudFront sirve las páginas desde S3) e IP del visitante de la CDN."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aletheia.api import create_app
from aletheia.platform.config import Settings
from aletheia.platform.middleware import ClientIPMiddleware, viewer_ip

STATIC = Path(__file__).parents[1] / "src" / "aletheia" / "admin" / "static"
CLOUDFRONT = Path(__file__).parents[1] / "infra" / "terraform" / "cloudfront"


@pytest.fixture
def api_only(settings_without_db: Settings) -> Iterator[TestClient]:
    settings = settings_without_db.model_copy(update={"serve_frontend": False})
    with TestClient(create_app(settings), raise_server_exceptions=False) as c:
        yield c


def test_api_only_serves_no_pages(api_only: TestClient) -> None:
    for path in ("/", "/admin/", "/admin/static/app.js", "/docs", "/v", "/favicon.ico"):
        assert api_only.get(path).status_code == 404, path
    assert api_only.get("/claim/" + "ab" * 16).status_code == 404
    assert api_only.get("/issuers/org_x").status_code == 404
    assert api_only.get("/healthz").status_code == 200


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("198.51.100.10:46532", "198.51.100.10"),
        ("2001:db8::1:46532", "2001:db8::1"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("not-an-ip:80", None),
        ("198.51.100.10", None),  # sin puerto: no es el formato de CloudFront
    ],
)
def test_viewer_ip(value: str, expected: str | None) -> None:
    assert viewer_ip(value) == expected


def test_client_ip_middleware_replaces_the_edge_address() -> None:
    seen: dict[str, Any] = {}

    async def app(scope: dict[str, Any], receive: object, send: object) -> None:
        seen["client"] = scope["client"]

    mw = ClientIPMiddleware(app, "CloudFront-Viewer-Address")  # type: ignore[arg-type]
    headers = [(b"cloudfront-viewer-address", b"203.0.113.9:5555")]
    asyncio.run(mw({"type": "http", "client": ("10.40.1.2", 1), "headers": headers}, None, None))  # type: ignore[arg-type]
    assert seen["client"] == ("203.0.113.9", 0)
    asyncio.run(mw({"type": "http", "client": ("10.40.1.2", 1), "headers": []}, None, None))  # type: ignore[arg-type]
    assert seen["client"] == ("10.40.1.2", 1)


def test_cloudfront_routes_cover_every_page() -> None:
    """La función de CloudFront conoce todas las páginas HTML que existen."""
    code = (CLOUDFRONT / "viewer-request.js").read_text()
    pages = {p.name for p in STATIC.glob("*.html")}
    for page in pages:
        assert f"/admin/static/{page}" in code, page
