"""Rate limiting por ventana fija en PostgreSQL (ADR-0008).

``INSERT … ON CONFLICT DO UPDATE`` sobre ``rate_limit_bucket``: una fila por
(sujeto, inicio de ventana). Sin Redis; ``maintenance`` purga las ventanas
antiguas. El sujeto nunca contiene datos personales en claro (se hashea).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import Engine
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from ..db import models
from .errors import AppError
from .ids import sha256


class RateLimited(AppError):
    status_code = 429
    code = "rate_limited"


def _window_start(now: datetime, window: timedelta) -> datetime:
    epoch = int(now.timestamp())
    size = int(window.total_seconds())
    return datetime.fromtimestamp(epoch - (epoch % size), tz=UTC)


def hit(
    session: Session,
    subject: str,
    *,
    limit: int,
    window: timedelta,
    now: datetime | None = None,
) -> int:
    """Incrementa el contador del sujeto y devuelve el total en la ventana.

    Lanza ``RateLimited`` si supera ``limit``. El incremento se confirma en
    una transacción propia: cuenta aunque la petición termine en error o
    rollback, de modo que insistir no ayuda.
    """
    now = now or datetime.now(UTC)
    key = sha256(subject).hex()
    stmt = (
        insert(models.RateLimitBucket)
        .values(subject=key, window_start=_window_start(now, window), count=1)
        .on_conflict_do_update(
            index_elements=[models.RateLimitBucket.subject, models.RateLimitBucket.window_start],
            set_={"count": models.RateLimitBucket.count + 1},
        )
        .returning(models.RateLimitBucket.count)
    )
    bind = session.get_bind()
    engine = bind if isinstance(bind, Engine) else bind.engine
    with engine.begin() as conn:
        count = int(conn.execute(stmt).scalar_one())
    if count > limit:
        raise RateLimited("Too many attempts; try again later")
    return count
