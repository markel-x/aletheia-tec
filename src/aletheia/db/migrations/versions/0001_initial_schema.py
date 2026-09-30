"""Esquema inicial (docs/03-modelo-de-datos.md).

Revision ID: 0001
Revises:
Create Date: 2026-09-30

El DDL vive en ``sql/0001_initial_schema.sql`` para conservar tipos
enumerados, restricciones CHECK, índices parciales, triggers y privilegios
tal como se diseñaron; Alembic sólo lo orquesta.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL_DIR = Path(__file__).resolve().parent.parent / "sql"


def upgrade() -> None:
    sql = (_SQL_DIR / "0001_initial_schema.sql").read_text(encoding="utf-8")
    op.execute(sa.text(sql))


def downgrade() -> None:
    # Se elimina todo lo creado: tablas, tipos y funciones. Los roles son del clúster y quedan.
    op.execute(sa.text((_SQL_DIR / "0001_initial_schema.down.sql").read_text(encoding="utf-8")))
