"""Configuración, logging y errores: sin base de datos."""

from __future__ import annotations

import json
import logging
import os

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient
from pydantic import ValidationError

from aletheia.api import create_app
from aletheia.platform.config import Environment, Settings
from aletheia.platform.errors import NotFound
from aletheia.platform.logging import JsonFormatter, redact, request_id_var


def test_settings_default_to_production(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in [k for k in os.environ if k.startswith("ALETHEIA_")]:
        monkeypatch.delenv(key)
    settings = Settings()
    assert settings.env is Environment.PRODUCTION
    assert settings.database_url is None
    with pytest.raises(RuntimeError, match="ALETHEIA_DATABASE_URL"):
        settings.require_database_url()


def test_settings_reject_non_psycopg_dsn() -> None:
    with pytest.raises(ValidationError, match="postgresql\\+psycopg"):
        Settings(database_url="postgresql://u:p@h/db")  # type: ignore[arg-type]


def test_settings_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALETHEIA_ENV", "staging")
    monkeypatch.setenv("ALETHEIA_DATABASE_URL", "postgresql+psycopg://u:p@h:5432/db")
    monkeypatch.setenv("ALETHEIA_PUBLIC_BASE_URL", "https://aletheia.example/")
    settings = Settings()
    assert settings.env.is_deployed
    assert settings.public_base == "https://aletheia.example"
    assert settings.require_database_url().startswith("postgresql+psycopg://")


def test_redaction_of_sensitive_keys() -> None:
    payload = {"user": {"email": "a@b", "display": "x"}, "tx_code": "1234", "items": [{"token": 1}]}
    assert redact(payload) == {
        "user": {"email": "[redacted]", "display": "x"},
        "tx_code": "[redacted]",
        "items": [{"token": "[redacted]"}],
    }


def test_json_formatter_includes_request_id_and_extras() -> None:
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "hola", (), None)
    record.__dict__["status"] = 200
    record.__dict__["password"] = "no"
    token = request_id_var.set("req-1")
    try:
        line = json.loads(JsonFormatter().format(record))
    finally:
        request_id_var.reset(token)
    assert line["msg"] == "hola"
    assert line["request_id"] == "req-1"
    assert line["status"] == 200
    assert line["password"] == "[redacted]"


def _client(settings: Settings) -> TestClient:
    app = create_app(settings)
    router = APIRouter()

    @router.get("/_boom")
    def boom() -> None:
        raise RuntimeError("secreto interno")

    @router.get("/_missing")
    def missing() -> None:
        raise NotFound("No such thing")

    @router.get("/_echo/{n}")
    def echo(n: int) -> dict[str, int]:
        return {"n": n}

    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


def test_error_format_is_stable(settings_without_db: Settings) -> None:
    with _client(settings_without_db) as client:
        r = client.get("/_missing", headers={"X-Request-ID": "abcdefgh-1234"})
        assert r.status_code == 404
        assert r.json() == {
            "error": {
                "code": "not_found",
                "message": "No such thing",
                "request_id": "abcdefgh-1234",
            }
        }
        assert r.headers["X-Request-ID"] == "abcdefgh-1234"

        r = client.get("/_echo/not-a-number")
        assert r.status_code == 422
        body = r.json()["error"]
        assert body["code"] == "validation_error"
        assert "not-a-number" not in json.dumps(body)  # nunca se devuelve el valor recibido

        r = client.get("/_boom")
        assert r.status_code == 500
        assert r.json()["error"]["code"] == "internal_error"
        assert "secreto" not in r.text

        r = client.get("/nope")
        assert r.status_code == 404
        assert r.json()["error"]["code"] == "not_found"


def test_request_id_is_generated_and_headers_hardened(settings_without_db: Settings) -> None:
    with _client(settings_without_db) as client:
        r = client.get("/healthz", headers={"X-Request-ID": "bad id with spaces"})
        assert r.status_code == 200
        assert len(r.headers["X-Request-ID"]) == 32  # se ignora el valor inválido
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["Cache-Control"] == "no-store"
        assert "server" not in {k.lower() for k in r.headers}


def test_docs_disabled_in_deployed_environments() -> None:
    deployed = Settings(env=Environment.PRODUCTION, database_url=None)
    with TestClient(create_app(deployed)) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
    local = Settings(env=Environment.DEVELOPMENT, database_url=None)
    with TestClient(create_app(local)) as client:
        assert client.get("/openapi.json").status_code == 200


def test_database_password_overrides_dsn() -> None:
    settings = Settings(
        database_url="postgresql+psycopg://app@db.example:5432/aletheia",  # type: ignore[arg-type]
        database_password="s3cr3t/with:chars@",  # type: ignore[arg-type]
    )
    url = settings.require_database_url()
    assert url.startswith("postgresql+psycopg://app:") and url.endswith("@db.example:5432/aletheia")
    from sqlalchemy.engine import make_url

    assert make_url(url).password == "s3cr3t/with:chars@"
    assert "s3cr3t" not in repr(settings)


@pytest.mark.parametrize(
    ("forwarded_for", "expected"),
    [
        # El ALB agrega la IP real al final: la que pone el cliente al principio no cuenta.
        (b"6.6.6.6, 203.0.113.9", "203.0.113.9"),
        (b"203.0.113.9", "203.0.113.9"),
    ],
)
def test_client_ip_comes_from_the_load_balancer_not_the_client(
    forwarded_for: bytes, expected: str
) -> None:
    import asyncio

    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

    from aletheia.authz.service import network_prefix

    seen: dict[str, str] = {}

    async def app(scope: dict, receive: object, send: object) -> None:
        seen["client"] = scope["client"][0]

    trusted = Settings().forwarded_allow_ips  # por defecto: redes privadas, nunca "*"
    staging = ProxyHeadersMiddleware(app, trusted_hosts=trusted)  # type: ignore[arg-type]

    def client_seen(peer: str, header: bytes) -> str:
        scope = {"type": "http", "client": (peer, 1234), "headers": [(b"x-forwarded-for", header)]}
        asyncio.run(staging(scope, None, None))  # type: ignore[arg-type]
        return seen["client"]

    assert client_seen("10.40.3.7", forwarded_for) == expected
    # Desde fuera de la VPC la cabecera se ignora por completo.
    assert client_seen("198.51.100.4", b"6.6.6.6") == "198.51.100.4"
    assert network_prefix("2001:db8:1:2::5", ipv6_bits=48) == "2001:db8:1::/48"
