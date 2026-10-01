"""Canal de entrega de la emisión: OID4VCI o pase de Apple Wallet (ADR-0016).

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-30

Una credencial entregada como pase no está vinculada a una clave del titular
(Apple Wallet no gestiona claves), así que ``holder_key_thumbprint`` sólo es
obligatorio cuando ``delivery = 'oid4vci'``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COMMON = (
    "signing_key_id IS NOT NULL AND status_list_id IS NOT NULL AND status_idx IS NOT NULL "
    "AND issued_at IS NOT NULL AND expires_at IS NOT NULL"
)


def upgrade() -> None:
    op.execute(
        sa.text(
            "ALTER TABLE issuance ADD COLUMN delivery text NOT NULL DEFAULT 'oid4vci' "
            "CHECK (delivery IN ('oid4vci', 'apple_pass'))"
        )
    )
    op.execute(sa.text("ALTER TABLE issuance DROP CONSTRAINT issuance_issued_fields_check"))
    op.execute(
        sa.text(
            "ALTER TABLE issuance ADD CONSTRAINT issuance_issued_fields_check CHECK ("
            "(state <> 'issued' AND issued_at IS NULL) OR ("
            f"{_COMMON} AND (delivery <> 'oid4vci' OR holder_key_thumbprint IS NOT NULL)))"
        )
    )


def downgrade() -> None:
    op.execute(sa.text("ALTER TABLE issuance DROP CONSTRAINT issuance_issued_fields_check"))
    op.execute(
        sa.text(
            "ALTER TABLE issuance ADD CONSTRAINT issuance_issued_fields_check CHECK ("
            "(state <> 'issued' AND issued_at IS NULL) OR ("
            f"{_COMMON} AND holder_key_thumbprint IS NOT NULL)) NOT VALID"
        )
    )
    op.execute(sa.text("ALTER TABLE issuance DROP COLUMN delivery"))
