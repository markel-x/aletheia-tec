"""Tema del panel por usuario: oscuro, claro o el del sistema.

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-03

``user_account.theme`` (NULL = oscuro, el tema original) sigue al usuario en cualquier dispositivo.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        sa.text(
            "ALTER TABLE user_account ADD COLUMN theme text "
            "CONSTRAINT user_account_theme_check CHECK (theme IN ('dark', 'light', 'system'))"
        )
    )


def downgrade() -> None:
    op.execute(sa.text("ALTER TABLE user_account DROP COLUMN theme"))
