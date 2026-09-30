"""``tx_code`` con HMAC-SHA256 y clave del servidor en lugar de Argon2id.

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-30

Ver ADR-0013. Se admiten ambos formatos: las ofertas pendientes creadas con
Argon2id siguen siendo canjeables hasta que expiran (máx. 7 días).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(sa.text("ALTER TABLE issuance DROP CONSTRAINT issuance_tx_code_hash_check"))
    op.execute(
        sa.text(
            "ALTER TABLE issuance ADD CONSTRAINT issuance_tx_code_hash_check CHECK ("
            "tx_code_hash LIKE '$argon2id$%' OR tx_code_hash ~ '^hmac-sha256\\$v1\\$[0-9a-f]{64}$')"
        )
    )


def downgrade() -> None:
    # NOT VALID: las filas con HMAC ya existentes se conservan (el código anterior no podrá
    # canjear esas ofertas; habría que reemitirlas). Sólo las filas nuevas se validan.
    op.execute(sa.text("ALTER TABLE issuance DROP CONSTRAINT issuance_tx_code_hash_check"))
    op.execute(
        sa.text(
            "ALTER TABLE issuance ADD CONSTRAINT issuance_tx_code_hash_check "
            "CHECK (tx_code_hash LIKE '$argon2id$%') NOT VALID"
        )
    )
