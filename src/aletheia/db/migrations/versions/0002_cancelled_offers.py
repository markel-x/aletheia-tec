"""Ofertas canceladas: ``revoked`` sin datos de emisión.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-30

Revocar una oferta pendiente la cancela (doc 02 §3.3): la fila queda en
``revoked`` sin clave de firma, vinculación ni fechas de emisión. La
restricción original exigía esos campos también en ``revoked``; ahora sólo
los exige en ``issued`` (y en ``revoked`` cuando la credencial llegó a
emitirse, es decir, cuando ``issued_at`` no es nulo).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ISSUED_FIELDS = (
    "signing_key_id IS NOT NULL AND holder_key_thumbprint IS NOT NULL AND "
    "status_list_id IS NOT NULL AND status_idx IS NOT NULL AND "
    "issued_at IS NOT NULL AND expires_at IS NOT NULL"
)


def upgrade() -> None:
    op.execute(sa.text("ALTER TABLE issuance DROP CONSTRAINT issuance_check"))
    op.execute(
        sa.text(
            "ALTER TABLE issuance ADD CONSTRAINT issuance_issued_fields_check CHECK ("
            f"(state <> 'issued' AND issued_at IS NULL) OR ({_ISSUED_FIELDS}))"
        )
    )


def downgrade() -> None:
    op.execute(sa.text("ALTER TABLE issuance DROP CONSTRAINT issuance_issued_fields_check"))
    op.execute(
        sa.text(
            "ALTER TABLE issuance ADD CONSTRAINT issuance_check CHECK ("
            f"state NOT IN ('issued', 'revoked') OR ({_ISSUED_FIELDS}))"
        )
    )
