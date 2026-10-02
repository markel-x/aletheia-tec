"""Canal de entrega ``google_pass``: pase de Google Wallet (ADR-0017).

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-02

Como el pase de Apple, no vincula la credencial a una clave del titular, así que la
restricción de campos emitidos de 0008 (``holder_key_thumbprint`` sólo con OID4VCI) ya lo cubre.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(sa.text("ALTER TABLE issuance DROP CONSTRAINT issuance_delivery_check"))
    op.execute(
        sa.text(
            "ALTER TABLE issuance ADD CONSTRAINT issuance_delivery_check "
            "CHECK (delivery IN ('oid4vci', 'apple_pass', 'google_pass'))"
        )
    )


def downgrade() -> None:
    op.execute(sa.text("ALTER TABLE issuance DROP CONSTRAINT issuance_delivery_check"))
    op.execute(
        sa.text(
            "ALTER TABLE issuance ADD CONSTRAINT issuance_delivery_check "
            "CHECK (delivery IN ('oid4vci', 'apple_pass')) NOT VALID"
        )
    )
