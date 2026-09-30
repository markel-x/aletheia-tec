"""Entorno de ejecución de Alembic (sólo modo *online* contra PostgreSQL)."""

from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

from aletheia.db.models import Base

config = context.config
target_metadata = Base.metadata


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            transaction_per_migration=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    raise RuntimeError("las migraciones de Aletheia sólo se ejecutan en modo online")
run_migrations_online()
