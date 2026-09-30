"""Sesiones OID4VP (presentación desde wallets estándar, ADR-0014).

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-30

Una sesión OID4VP envuelve una ``presentation_request`` (nonce de un uso, ``aud``,
10 minutos) y añade lo que exige el protocolo: ``state`` (sólo su hash), la
consulta DCQL, el estado de la respuesta del wallet y el resultado **cifrado**
para que el verificador lo recoja (se borra a los 10 minutos: ADR-0009).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CONDITION = (
    "current_setting('app.bypass_rls', true) = 'on' OR "
    "organization_id = NULLIF(current_setting('app.current_org', true), '')::uuid"
)


def upgrade() -> None:
    op.execute(
        sa.text(
            """
            CREATE TABLE oid4vp_session (
              id                      uuid PRIMARY KEY,
              organization_id         uuid NOT NULL REFERENCES organization (id),
              presentation_request_id uuid NOT NULL UNIQUE
                                      REFERENCES presentation_request (id) ON DELETE CASCADE,
              state_hash              bytea NOT NULL UNIQUE CHECK (octet_length(state_hash) = 32),
              client_id               text NOT NULL,
              response_uri            text NOT NULL,
              dcql_query              jsonb NOT NULL,
              status                  text NOT NULL DEFAULT 'pending'
                                      CHECK (status IN ('pending', 'completed', 'failed')),
              error                   text CHECK (error IS NULL OR char_length(error) <= 64),
              verification_record_id  uuid REFERENCES verification_record (id) ON DELETE SET NULL,
              result_ciphertext       bytea,
              result_encrypted_key    bytea,
              result_key_ref          text,
              completed_at            timestamptz,
              created_at              timestamptz NOT NULL DEFAULT now(),
              CHECK (status = 'pending' OR completed_at IS NOT NULL),
              CHECK ((result_ciphertext IS NULL) = (result_encrypted_key IS NULL))
            )
            """
        )
    )
    op.execute(
        sa.text(
            "CREATE INDEX oid4vp_session_org_created_idx ON oid4vp_session (organization_id, created_at DESC)"
        )
    )
    op.execute(sa.text("ALTER TABLE oid4vp_session ENABLE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            f"CREATE POLICY tenant_isolation ON oid4vp_session USING ({_CONDITION}) WITH CHECK ({_CONDITION})"
        )
    )
    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
              IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aletheia_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON oid4vp_session TO aletheia_app;
              END IF;
            END $$
            """
        )
    )


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE oid4vp_session"))
