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
    cfg.set_main_option("sqlalchemy.url", database_url)
    cfg.set_main_option("file_template", "%%(rev)s_%%(slug)s")
    return cfg


def head_revision() -> str | None:
    cfg = Config()
    cfg.set_main_option("script_location", str(SCRIPT_LOCATION))
    return ScriptDirectory.from_config(cfg).get_current_head()


def upgrade(database_url: str, revision: str = "head") -> None:
    command.upgrade(alembic_config(database_url), revision)


def downgrade(database_url: str, revision: str) -> None:
    command.downgrade(alembic_config(database_url), revision)
