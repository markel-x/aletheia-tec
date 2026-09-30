"""Motor y sesiones de SQLAlchemy 2 (sync, psycopg 3).

Un ``Database`` por proceso. Las sesiones se abren por petición mediante la
dependencia ``get_session`` de la API o el context manager ``session``.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from .config import Settings


class Database:
    def __init__(self, settings: Settings) -> None:
        self.engine: Engine = create_engine(
            settings.require_database_url(),
            pool_size=settings.db_pool_size,
            pool_timeout=settings.db_pool_timeout_seconds,
            pool_pre_ping=True,
            future=True,
            connect_args={
                "application_name": "aletheia",
                "options": f"-c statement_timeout={settings.db_statement_timeout_ms}",
            },
        )
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self._sessions() as session:
            try:
                yield session
                session.commit()
            except BaseException:
                session.rollback()
                raise

    def ping(self) -> bool:
        with self.engine.connect() as conn:
            return conn.execute(text("SELECT 1")).scalar() == 1

    def schema_revision(self) -> str | None:
        """Revisión Alembic aplicada, o ``None`` si la tabla no existe."""
        with self.engine.connect() as conn:
            exists = conn.execute(text("SELECT to_regclass('public.alembic_version')")).scalar()
            if exists is None:
                return None
            row = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            return str(row) if row is not None else None

    def dispose(self) -> None:
        self.engine.dispose()
