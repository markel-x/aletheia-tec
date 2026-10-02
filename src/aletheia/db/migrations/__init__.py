"""Migraciones Alembic empaquetadas con la aplicación.

No hay ``alembic.ini``: la configuración se construye aquí para que
``aletheia migrate`` y las pruebas usen exactamente la misma.
"""

from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

SCRIPT_LOCATION = Path(__file__).parent

# El registro de plugins de Alembic es ruido en cada arranque; las migraciones sí se registran.
logging.getLogger("alembic.runtime.plugins").setLevel(logging.WARNING)


def alembic_config(database_url: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(SCRIPT_LOCATION))
    # configparser interpola "%": una contraseña codificada en la URL (%2A, %28…) lo rompe.
    cfg.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    cfg.set_main_option("file_template", "%%(rev)s_%%(slug)s")
    return cfg


def head_revision() -> str | None:
    cfg = Config()
    cfg.set_main_option("script_location", str(SCRIPT_LOCATION))
    return ScriptDirectory.from_config(cfg).get_current_head()


def upgrade(database_url: str, revision: str = "head") -> None:
    command.upgrade(alembic_config(database_url), revision)


def set_app_role_password(database_url: str, password: str) -> None:
    """Habilita el login del rol ``aletheia_app`` con la contraseña de Secrets Manager.

    La contraseña viaja como parámetro y se cita con ``format(%L)`` dentro de la base:
    nunca se concatena en el SQL del cliente."""
    from sqlalchemy import create_engine, text

    engine = create_engine(database_url)
    try:
        with engine.begin() as conn:
            conn.execute(text("SELECT set_config('aletheia.app_pw', :p, true)"), {"p": password})
            conn.execute(
                text(
                    "DO $$ BEGIN EXECUTE format('ALTER ROLE aletheia_app LOGIN PASSWORD %L', "
                    "current_setting('aletheia.app_pw')); END $$"
                )
            )
    finally:
        engine.dispose()


def downgrade(database_url: str, revision: str) -> None:
    command.downgrade(alembic_config(database_url), revision)
