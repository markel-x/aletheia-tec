"""Migraciones, coincidencia ORM ↔ esquema y mantenimiento. Requieren PostgreSQL."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, select, text

from aletheia.db import models
from aletheia.db.migrations import downgrade, head_revision, upgrade
from aletheia.maintenance import run_maintenance
from aletheia.platform.config import Settings
from aletheia.platform.db import Database

pytestmark = pytest.mark.db


def test_head_revision_is_known() -> None:
    assert head_revision() == "0005"


def test_models_match_migrated_schema(migrated_database_url: str) -> None:
    """``autogenerate`` no propone cambios: el ORM refleja exactamente el DDL."""
    engine = create_engine(migrated_database_url)
    try:
        with engine.connect() as conn:
            ctx = MigrationContext.configure(conn, opts={"compare_type": True})
            diffs = compare_metadata(ctx, models.Base.metadata)
    finally:
        engine.dispose()
    assert diffs == [], "\n".join(repr(d) for d in diffs)


def test_upgrade_is_idempotent_and_downgrade_is_clean(migrated_database_url: str) -> None:
    upgrade(migrated_database_url)  # ya en head: no hace nada ni falla
    downgrade(migrated_database_url, "base")
    engine = create_engine(migrated_database_url)
    try:
        with engine.connect() as conn:
            tables = conn.execute(
                text(
                    "SELECT count(*) FROM information_schema.tables "
                    "WHERE table_schema='public' AND table_name <> 'alembic_version'"
                )
            ).scalar()
            types_ = conn.execute(
                text(
                    "SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace "
                    "WHERE n.nspname='public' AND t.typtype='e'"
                )
            ).scalar()
    finally:
        engine.dispose()
        upgrade(migrated_database_url)  # deja la base como la esperan las demás pruebas
    assert tables == 0
    assert types_ == 0


def _org(session: object) -> models.Organization:
    org = models.Organization(
        id=uuid.uuid4(), public_id="org_" + "a" * 22, name="Org", data_retention_days=365
    )
    return org


def test_maintenance_expires_offers_and_purges(db_settings: Settings) -> None:
    db = Database(db_settings)
    now = datetime.now(UTC)
    try:
        with db.session(bypass_rls=True) as s:
            org = _org(s)
            s.add(org)
            s.flush()  # sin relationship(), el orden de inserción no se infiere
            tpl = models.CredentialTemplate(
                id=uuid.uuid4(),
                organization_id=org.id,
                public_id="tpl_" + "a" * 22,
                slug="curso",
                name="Curso",
            )
            s.add(tpl)
            tv = models.TemplateVersion(
                id=uuid.uuid4(),
                organization_id=org.id,
                template_id=tpl.id,
                version=1,
                claims_schema={"type": "object"},
                validity_days=365,
            )
            s.add(tv)
            s.flush()

            def offer(suffix: str, expires: datetime) -> models.Issuance:
                iss = models.Issuance(
                    id=uuid.uuid4(),
                    public_id="cred_" + suffix * 22,
                    organization_id=org.id,
                    template_version_id=tv.id,
                    vct="vct",
                    offer_id=suffix.encode() * 16,
                    pre_auth_code_hash=b"\x01" * 32,
                    tx_code_hash="$argon2id$x",
                    offer_expires_at=expires,
                )
                s.add(iss)
                s.flush()
                s.add(
                    models.IssuancePendingClaims(
                        issuance_id=iss.id,
                        organization_id=org.id,
                        ciphertext=b"c",
                        encrypted_data_key=b"k",
                        key_ref="local",
                    )
                )
                return iss

            stale = offer("b", now - timedelta(hours=1))
            fresh = offer("c", now + timedelta(hours=1))
            minute = timedelta(minutes=1)
            s.add(models.Oid4vciNonce(nonce_hash=b"\x02" * 32, expires_at=now - minute))
            s.add(models.Oid4vciNonce(nonce_hash=b"\x03" * 32, expires_at=now + minute))
            s.add(models.RateLimitBucket(subject="ip", window_start=now - timedelta(hours=2)))
            s.add(
                models.VerificationRecord(
                    id=uuid.uuid4(),
                    organization_id=org.id,
                    result="valid",
                    checks={},
                    created_at=now - timedelta(days=400),
                )
            )
            s.add(
                models.VerificationRecord(
                    id=uuid.uuid4(),
                    organization_id=org.id,
                    result="valid",
                    checks={},
                )
            )

        with db.session(bypass_rls=True) as s:
            counts = run_maintenance(s, now=now)

        assert counts["offers_expired"] == 1
        assert counts["pending_purged"] == 1
        assert counts["oid4vci_nonces"] == 1
        assert counts["rate_limit_buckets"] == 1
        assert counts["verification_records"] == 1

        with db.session(bypass_rls=True) as s:
            states = dict(s.execute(select(models.Issuance.id, models.Issuance.state)).all())
            assert states[stale.id] == "offer_expired"
            assert states[fresh.id] == "offered"
            pending = set(s.scalars(select(models.IssuancePendingClaims.issuance_id)).all())
            assert pending == {fresh.id}
            assert s.scalar(select(models.VerificationRecord).limit(2)) is not None
            # Limpieza: la base de pruebas se comparte entre pruebas.
            for table in (
                "verification_record",
                "issuance_pending_claims",
                "issuance",
                "template_version",
                "credential_template",
                "oid4vci_nonce",
                "rate_limit_bucket",
                "organization",
            ):
                s.execute(text(f"DELETE FROM {table}"))  # noqa: S608 - nombres fijos
    finally:
        db.dispose()
