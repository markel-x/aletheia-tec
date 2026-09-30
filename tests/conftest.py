"""Fixtures compartidas.

Las pruebas que necesitan PostgreSQL llevan ``@pytest.mark.db`` y usan
``ALETHEIA_TEST_DATABASE_URL`` (rol propietario; la base se migra y se
revierte). Sin esa variable se omiten, nunca fallan en silencio.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from aletheia.platform.config import Environment, Settings

TEST_DATABASE_URL = os.environ.get("ALETHEIA_TEST_DATABASE_URL")
# Rol de la aplicación sobre la misma base: las pruebas de API corren con RLS activo.
TEST_APP_DATABASE_URL = os.environ.get("ALETHEIA_TEST_APP_DATABASE_URL")
pytest_plugins = ["tests.fixtures_org"]


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if TEST_DATABASE_URL:
        return
    skip = pytest.mark.skip(reason="ALETHEIA_TEST_DATABASE_URL no definida")
    for item in items:
        if "db" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def settings_without_db() -> Settings:
    return Settings(env=Environment.TEST, database_url=None, log_format="text")


@pytest.fixture(scope="session")
def migrated_database_url() -> Iterator[str]:
    """Base de pruebas en ``head``. Se revierte al terminar la sesión."""
    from aletheia.db.migrations import downgrade, upgrade

    assert TEST_DATABASE_URL
    downgrade(TEST_DATABASE_URL, "base")  # estado limpio aunque una sesión anterior fallara
    upgrade(TEST_DATABASE_URL)
    try:
        yield TEST_DATABASE_URL
    finally:
        downgrade(TEST_DATABASE_URL, "base")


@pytest.fixture
def db_settings(migrated_database_url: str, tmp_path: Path) -> Settings:
    return Settings(
        env=Environment.TEST,
        database_url=TEST_APP_DATABASE_URL or migrated_database_url,  # type: ignore[arg-type]
        log_format="text",
        signing_backend="local_dev",
        dev_keys_dir=tmp_path / "dev-keys",
    )
