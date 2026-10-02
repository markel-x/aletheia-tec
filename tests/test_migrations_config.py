"""Configuración de Alembic: la URL de la base llega intacta aunque la contraseña lleve "%"."""

from __future__ import annotations

from aletheia.db.migrations import alembic_config


def test_url_with_percent_encoded_password_survives_configparser() -> None:
    url = "postgresql+psycopg://migrate:a%2A%28b%7C@db.example:5432/aletheia?sslmode=require"
    cfg = alembic_config(url)
    assert cfg.get_main_option("sqlalchemy.url") == url
    assert cfg.get_section(cfg.config_ini_section, {})["sqlalchemy.url"] == url
