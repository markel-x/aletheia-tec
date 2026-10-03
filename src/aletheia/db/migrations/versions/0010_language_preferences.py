"""Idioma de la interfaz: predeterminado de la organización y preferencia de cada usuario.

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-03

``organization.default_language`` se usa en el panel para quien no eligió idioma y en las
páginas públicas del titular (recibir y verificar). ``user_account.language`` (NULL = el de la
organización) sigue al usuario en cualquier dispositivo.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

LANGUAGES = "('es', 'en')"


def upgrade() -> None:
    op.execute(
        sa.text(
            "ALTER TABLE organization ADD COLUMN default_language text NOT NULL DEFAULT 'es' "
            f"CONSTRAINT organization_default_language_check CHECK (default_language IN {LANGUAGES})"
        )
    )
    op.execute(
        sa.text(
            "ALTER TABLE user_account ADD COLUMN language text "
            f"CONSTRAINT user_account_language_check CHECK (language IN {LANGUAGES})"
        )
    )


def downgrade() -> None:
    op.execute(sa.text("ALTER TABLE user_account DROP COLUMN language"))
    op.execute(sa.text("ALTER TABLE organization DROP COLUMN default_language"))
