"""Emisores confiables alojados con ``http://`` en desarrollo.

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-30

La restricción original exigía ``https://`` para todo ``trusted_issuer.issuer``.
En desarrollo local el origen público es ``http://127.0.0.1:8008`` y los emisores
alojados heredan ese esquema, así que añadir uno como confiable producía un 500.
La regla de negocio ("https salvo emisor alojado") queda en la aplicación
(``verification.service.add_trusted_issuer``); la base sólo exige una URL http(s).
Detectado por la prueba de interoperabilidad (``interop/run.mjs``).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(sa.text("ALTER TABLE trusted_issuer DROP CONSTRAINT trusted_issuer_issuer_check"))
    op.execute(
        sa.text(
            "ALTER TABLE trusted_issuer ADD CONSTRAINT trusted_issuer_issuer_check "
            "CHECK (issuer ~ '^https?://')"
        )
    )


def downgrade() -> None:
    # NOT VALID: conserva emisores alojados http ya existentes; sólo se validan filas nuevas.
    op.execute(sa.text("ALTER TABLE trusted_issuer DROP CONSTRAINT trusted_issuer_issuer_check"))
    op.execute(
        sa.text(
            "ALTER TABLE trusted_issuer ADD CONSTRAINT trusted_issuer_issuer_check "
            "CHECK (issuer ~ '^https://') NOT VALID"
        )
    )
