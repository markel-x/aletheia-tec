"""``/healthz`` y ``/readyz``."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aletheia import __version__
from aletheia.api import create_app
from aletheia.db.migrations import head_revision
from aletheia.platform.config import Environment, Settings


def test_healthz_without_database(settings_without_db: Settings) -> None:
    with TestClient(create_app(settings_without_db)) as client:
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "version": __version__}


def test_readyz_reports_missing_database(settings_without_db: Settings) -> None:
    with TestClient(create_app(settings_without_db)) as client:
        r = client.get("/readyz")
        assert r.status_code == 503
        assert r.json() == {"status": "database_not_configured"}


def test_readyz_reports_unreachable_database(tmp_path: Path) -> None:
    settings = Settings(
        env=Environment.TEST,
        database_url="postgresql+psycopg://u:p@127.0.0.1:1/nope",  # type: ignore[arg-type]
        db_pool_timeout_seconds=1,
        signing_backend="local_dev",
        dev_keys_dir=tmp_path,
    )
    with TestClient(create_app(settings)) as client:
        r = client.get("/readyz")
        assert r.status_code == 503
        assert r.json() == {"status": "database_unavailable"}


@pytest.mark.db
def test_readyz_ok_when_migrated(db_settings: Settings) -> None:
    with TestClient(create_app(db_settings)) as client:
        r = client.get("/readyz")
        assert r.status_code == 200, r.text
        assert r.json() == {"status": "ok"}


@pytest.mark.db
def test_readyz_detects_schema_out_of_date(db_settings: Settings) -> None:
    from sqlalchemy import create_engine, text

    engine = create_engine(db_settings.require_database_url())
    with engine.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num = '0000'"))
    try:
        with TestClient(create_app(db_settings)) as client:
            r = client.get("/readyz")
            assert r.status_code == 503
            assert r.json() == {"status": "schema_out_of_date"}
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("UPDATE alembic_version SET version_num = :head"), {"head": head_revision()}
            )
        engine.dispose()
