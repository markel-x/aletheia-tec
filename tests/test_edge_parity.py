"""El borde local (infra/local-edge, nginx) y CloudFront (infra/terraform/frontend.tf) enrutan y
protegen igual, y ambos coinciden con la API: cada endpoint va a la API y cada página al
frontend."""

from __future__ import annotations

import re
from fnmatch import fnmatchcase
from pathlib import Path

import pytest

from aletheia.admin.router import CSP, DOCS_CSP
from aletheia.api import create_app
from aletheia.platform.config import Settings

ROOT = Path(__file__).parents[1]
TERRAFORM = (ROOT / "infra" / "terraform" / "frontend.tf").read_text()
NGINX = (ROOT / "infra" / "local-edge" / "nginx.conf").read_text()

PAGES = [
    "/",
    "/admin/",
    "/v",
    "/docs",
    "/favicon.ico",
    "/claim/0123456789abcdef0123456789abcdef",
    "/issuers/org_2ufXIZpoQpIQjYBnsnmPdT",
    "/admin/static/app.js",
]


def _cloudfront_api_paths() -> list[str]:
    block = re.search(r"api_paths = \[(.*?)\]", TERRAFORM, re.S)
    assert block
    return re.findall(r'"([^"]+)"', block.group(1))


def _nginx_api_locations() -> list[re.Pattern[str]]:
    api_section = NGINX.split("# --- Frontend")[0]
    return [re.compile(rx) for rx in re.findall(r"location ~ (\S+) \{", api_section)]


def _to_cloudfront_api(path: str) -> bool:
    return any(fnmatchcase(path, pattern) for pattern in _cloudfront_api_paths())


def _to_nginx_api(path: str) -> bool:
    return any(rx.search(path) for rx in _nginx_api_locations())


def _api_endpoints(settings: Settings) -> list[str]:
    app = create_app(settings.model_copy(update={"serve_frontend": False}))
    paths = [re.sub(r"\{[^}]+\}", "x1", p) for p in app.openapi()["paths"]]
    return [*paths, "/wallet/logo.png", "/openapi.json"]  # fuera del esquema, pero de la API


def test_every_api_endpoint_reaches_the_api(settings_without_db: Settings) -> None:
    for path in _api_endpoints(settings_without_db):
        assert _to_cloudfront_api(path), f"CloudFront no envía {path} a la API"
        assert _to_nginx_api(path), f"el borde local no envía {path} a la API"


@pytest.mark.parametrize("path", PAGES)
def test_pages_go_to_the_frontend(path: str) -> None:
    assert not _to_cloudfront_api(path)
    assert not _to_nginx_api(path)


def test_same_content_security_policy_everywhere() -> None:
    tf_csp = re.search(r'^\s*csp\s*=\s*"([^"]+)"', TERRAFORM, re.M)
    tf_docs = re.search(r'^\s*docs_csp\s*=\s*"([^"]+)"', TERRAFORM, re.M)
    tf_cdn = re.search(r'^\s*docs_cdn\s*=\s*"([^"]+)"', TERRAFORM, re.M)
    assert tf_csp and tf_docs and tf_cdn
    assert tf_csp.group(1) == CSP
    assert tf_docs.group(1).replace("${local.docs_cdn}", tf_cdn.group(1)) == DOCS_CSP
    assert f'default "{CSP}";' in NGINX
    assert f'"{DOCS_CSP}";' in NGINX
