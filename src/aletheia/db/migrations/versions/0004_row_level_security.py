"""Row-Level Security por organización (doc 02 §4, defensa en profundidad).

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-30

Cada tabla con ``organization_id`` (y ``organization`` por su ``id``) sólo
muestra y acepta filas de la organización fijada en la transacción:

    SELECT set_config('app.current_org', '<uuid>', true)

La aplicación la fija al autenticar al principal (``api.deps.get_principal``).
Sin organización fijada, el rol de la aplicación **no ve nada** (falla cerrado).

Los flujos sin principal (login, OID4VCI, listas de estado, metadatos
públicos, mantenimiento, alta) activan ``app.bypass_rls`` de forma explícita
y acotada (``platform.db.rls_bypass``). Alcance de la protección: evita que
un filtro olvidado en código autenticado exponga datos de otra organización;
**no** protege frente a quien pueda ejecutar SQL arbitrario con el rol de la
aplicación (podría fijar las mismas variables). Ver ADR-0012.

El propietario del esquema (``aletheia_migrate``) no está sujeto a RLS
(no se usa ``FORCE``): migraciones y tareas de operador lo usan.

Además, el rol de la aplicación deja de poder modificar ``alembic_version``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TENANT_TABLES = (
    "membership",
    "session",
    "api_client",
    "issuer_profile",
    "signing_key",
    "credential_template",
    "template_version",
    "status_list",
    "credential_status",
    "issuance",
    "issuance_pending_claims",
    "trust_policy",
    "trusted_issuer",
    "presentation_request",
    "verification_record",
    "audit_event",
    "usage_event",
    "idempotency_record",
)

_BYPASS = "current_setting('app.bypass_rls', true) = 'on'"
_CURRENT = "NULLIF(current_setting('app.current_org', true), '')::uuid"


def upgrade() -> None:
    for table in TENANT_TABLES:
        condition = f"{_BYPASS} OR organization_id = {_CURRENT}"
        op.execute(sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        op.execute(
            sa.text(
                f"CREATE POLICY tenant_isolation ON {table} "
                f"USING ({condition}) WITH CHECK ({condition})"
            )
        )
    condition = f"{_BYPASS} OR id = {_CURRENT}"
    op.execute(sa.text("ALTER TABLE organization ENABLE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            f"CREATE POLICY tenant_isolation ON organization "
            f"USING ({condition}) WITH CHECK ({condition})"
        )
    )
    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
              IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aletheia_app') THEN
                REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON alembic_version FROM aletheia_app;
              END IF;
            END $$
            """
        )
    )


def downgrade() -> None:
    for table in (*TENANT_TABLES, "organization"):
        op.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {table}"))
        op.execute(sa.text(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"))
