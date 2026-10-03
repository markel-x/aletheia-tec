"""Acceso restringido temporal (HTTP Basic) a las páginas del sitio, sin base de datos."""

from __future__ import annotations

import base64
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from aletheia.api import create_app
from aletheia.platform.config import Settings
from aletheia.platform.site_gate import is_gated


def _basic(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


@pytest.fixture
def gated(settings_without_db: Settings) -> Iterator[TestClient]:
    settings = settings_without_db.model_copy(
        update={"site_basic_auth": SecretStr("credoseal:s3cret-pass")}
    )
    with TestClient(create_app(settings), raise_server_exceptions=False) as c:
        yield c


def test_pages_ask_for_credentials(gated: TestClient) -> None:
    for path in ("/", "/admin/", "/admin/static/app.js", "/v", "/claim/abc", "/issuers/org_x"):
        r = gated.get(path)
        assert r.status_code == 401, path
        assert r.headers["www-authenticate"].startswith('Basic realm="CredoSeal"')
        assert r.headers["x-robots-tag"] == "noindex, nofollow"
    assert gated.get("/", headers=_basic("credoseal", "wrong")).status_code == 401
    assert gated.get("/", headers={"Authorization": "Basic %%%"}).status_code == 401
    ok = gated.get("/", headers=_basic("credoseal", "s3cret-pass"))
    assert ok.status_code == 200 and "CredoSeal" in ok.text
    assert ok.headers["x-robots-tag"] == "noindex, nofollow"


def test_machine_endpoints_stay_open(gated: TestClient) -> None:
    # Salud (ALB/ECS): sin credenciales.
    assert gated.get("/healthz").status_code == 200
    # API: responde la propia autenticación de la API, no el diálogo del navegador.
    r = gated.get("/v1/auth/me")
    assert "basic" not in r.headers.get("www-authenticate", "").lower()
    assert r.text != "Authentication required"
    # Logo que descarga Google Wallet.
    assert gated.get("/wallet/logo.png").status_code == 200


def test_gated_paths() -> None:
    assert all(is_gated(p) for p in ("/", "/admin", "/docs", "/v", "/claim/x", "/issuer-info/x"))
    assert not any(
        is_gated(p)
        for p in (
            "/healthz",
            "/readyz",
            "/v1/credentials",
            "/oid4vci/token",
            "/oid4vp/request/x",
            "/.well-known/jwt-vc-issuer/issuers/x",
            "/status-lists/x",
            "/public/pass-verifications",
            "/wallet/logo.png",
            "/verify",
        )
    )


def test_gate_is_off_by_default(settings_without_db: Settings) -> None:
    with TestClient(create_app(settings_without_db), raise_server_exceptions=False) as c:
        assert c.get("/").status_code == 200
        assert "x-robots-tag" not in {k.lower() for k in c.get("/").headers}


def test_api_docs_page(settings_without_db: Settings) -> None:
    with TestClient(create_app(settings_without_db), raise_server_exceptions=False) as c:
        r = c.get("/docs")
        assert r.status_code == 200 and 'id="swagger-ui"' in r.text and "docs.css" in r.text
        csp = r.headers["content-security-policy"]
        assert "script-src 'self' https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/" in csp
        spec = c.get("/openapi.json").json()
        assert spec["info"]["title"] == "CredoSeal"
        assert [t["name"] for t in spec["tags"]][:2] == ["issuance", "verification"]
    # En las demás páginas la CSP sigue sin orígenes externos.
    with TestClient(create_app(settings_without_db), raise_server_exceptions=False) as c:
        assert "jsdelivr" not in c.get("/").headers["content-security-policy"]


def test_api_docs_hidden_in_production(settings_without_db: Settings) -> None:
    from aletheia.platform.config import Environment

    prod = settings_without_db.model_copy(update={"env": Environment.PRODUCTION})
    with TestClient(create_app(prod), raise_server_exceptions=False) as c:
        assert c.get("/docs").status_code == 404
        assert c.get("/openapi.json").status_code == 404
