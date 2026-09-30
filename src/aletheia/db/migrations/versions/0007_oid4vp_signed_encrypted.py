"""OID4VP: solicitudes firmadas (x509) y respuestas cifradas (direct_post.jwt).

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-30

Ver ADR-0015. ``request_object`` (JWT firmado, contiene nonce y state) y la clave
privada efímera de la respuesta (cifrada con envelope) se borran al completar la
sesión o a los 15 minutos (``maintenance``).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        sa.text(
            """
            ALTER TABLE oid4vp_session
              ADD COLUMN client_id_scheme text NOT NULL DEFAULT 'redirect_uri'
                CHECK (client_id_scheme IN ('redirect_uri', 'x509_san_dns', 'x509_hash')),
              ADD COLUMN response_mode text NOT NULL DEFAULT 'direct_post'
                CHECK (response_mode IN ('direct_post', 'direct_post.jwt')),
              ADD COLUMN request_ref text UNIQUE
                CHECK (request_ref IS NULL OR request_ref ~ '^[A-Za-z0-9_-]{43}$'),
              ADD COLUMN request_object text,
              ADD COLUMN request_fetched_at timestamptz,
              ADD COLUMN response_kid text UNIQUE,
              ADD COLUMN response_key_ciphertext bytea,
              ADD COLUMN response_key_encrypted_key bytea,
              ADD COLUMN response_key_ref text,
              ADD CONSTRAINT oid4vp_session_signed_has_ref
                CHECK (client_id_scheme = 'redirect_uri' OR request_ref IS NOT NULL),
              ADD CONSTRAINT oid4vp_session_encrypted_has_kid
                CHECK (response_mode = 'direct_post' OR response_kid IS NOT NULL)
            """
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            """
            ALTER TABLE oid4vp_session
              DROP CONSTRAINT oid4vp_session_encrypted_has_kid,
              DROP CONSTRAINT oid4vp_session_signed_has_ref,
              DROP COLUMN response_key_ref,
              DROP COLUMN response_key_encrypted_key,
              DROP COLUMN response_key_ciphertext,
              DROP COLUMN response_kid,
              DROP COLUMN request_fetched_at,
              DROP COLUMN request_object,
              DROP COLUMN request_ref,
              DROP COLUMN response_mode,
              DROP COLUMN client_id_scheme
            """
        )
    )
