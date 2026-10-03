"""Solicitudes de acceso desde la página de inicio (alta revisada, no autoservicio).

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-03

Quien quiere usar CredoSeal deja su organización y contacto; un operador la revisa y, si la
aprueba, crea la organización con ``aletheia bootstrap``. No pertenece a ninguna organización
(sin RLS). Datos personales mínimos; ``maintenance`` los purga (ADR-0009).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        sa.text(
            """
            CREATE TABLE access_request (
              id uuid PRIMARY KEY,
              organization text NOT NULL CHECK (length(organization) BETWEEN 1 AND 200),
              contact_name text NOT NULL CHECK (length(contact_name) BETWEEN 1 AND 200),
              email citext NOT NULL CHECK (length(email) BETWEEN 3 AND 320),
              use_case text NOT NULL CHECK (length(use_case) BETWEEN 1 AND 2000),
              website text CHECK (website IS NULL OR length(website) <= 300),
              language text NOT NULL DEFAULT 'es' CHECK (language IN ('es', 'en')),
              status text NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'approved', 'rejected')),
              created_at timestamptz NOT NULL DEFAULT now(),
              processed_at timestamptz,
              CHECK ((status = 'pending') = (processed_at IS NULL))
            )
            """
        )
    )
    op.execute(
        sa.text(
            "CREATE INDEX access_request_status_created_idx ON access_request (status, created_at)"
        )
    )
    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
              IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aletheia_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON access_request TO aletheia_app;
              END IF;
            END $$
            """
        )
    )


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE access_request"))
