"""Motor y sesiones de SQLAlchemy 2 (sync, psycopg 3).

Un ``Database`` por proceso. Las sesiones se abren por petición mediante la
dependencia ``get_session`` de la API o el context manager ``session``.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from .config import Settings


# ---------------------------------------------------------------------------
# Row-Level Security (migración 0004, ADR-0012). Variables locales a la transacción.
# ---------------------------------------------------------------------------
def set_tenant(session: Session, organization_id: uuid.UUID) -> None:
    session.execute(
        text("SELECT set_config('app.current_org', :org, true)"), {"org": str(organization_id)}
    )


def set_bypass(session: Session, enabled: bool) -> None:
    session.execute(
        text("SELECT set_config('app.bypass_rls', :v, true)"), {"v": "on" if enabled else "off"}
    )


@contextmanager
def rls_bypass(session: Session) -> Iterator[None]:
    """Acceso entre organizaciones acotado a un bloque (p. ej. claves públicas de
    otro emisor al verificar). Vacía los cambios pendientes antes de restaurar,
    para que no se escriban fuera del bloque con otra visibilidad."""
    previous = session.execute(text("SELECT current_setting('app.bypass_rls', true)")).scalar()
    set_bypass(session, True)
    try:
        yield
        session.flush()
    finally:
        set_bypass(session, previous == "on")


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

    def session_factory(self) -> Session:
        return self._sessions()

    @contextmanager
    def session(self, *, bypass_rls: bool = False) -> Iterator[Session]:
        """Sesión con commit/rollback. ``bypass_rls`` sólo para tareas de sistema
        (alta, mantenimiento) y preparación de pruebas."""
        with self._sessions() as session:
            try:
                if bypass_rls:
                    set_bypass(session, True)
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
