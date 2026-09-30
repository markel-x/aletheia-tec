"""Registro y agregación de consumo."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import models
from ..platform.ids import uuid7

KINDS = ("credential.offered", "credential.issued", "verification.performed", "status_list.served")


def record(
    session: Session,
    organization_id: uuid.UUID,
    kind: str,
    *,
    api_client_id: uuid.UUID | None = None,
    quantity: int = 1,
) -> None:
    if kind not in KINDS:
        raise ValueError(f"unknown usage kind: {kind}")
    session.add(
        models.UsageEvent(
            id=uuid7(),
            organization_id=organization_id,
            kind=kind,
            api_client_id=api_client_id,
            quantity=quantity,
        )
    )


def monthly_summary(
    session: Session, organization_id: uuid.UUID, *, months: int = 12
) -> list[dict[str, Any]]:
    """Totales por mes (UTC) y tipo, del más reciente al más antiguo."""
    now = datetime.now(UTC)
    start_month = (now.month - months) % 12 + 1
    start_year = now.year + (now.month - months - 1) // 12
    start = datetime(start_year, start_month, 1, tzinfo=UTC)
    month = func.date_trunc("month", models.UsageEvent.occurred_at)
    rows = session.execute(
        select(month.label("month"), models.UsageEvent.kind, func.sum(models.UsageEvent.quantity))
        .where(models.UsageEvent.organization_id == organization_id)
        .where(models.UsageEvent.occurred_at >= start)
        .group_by(month, models.UsageEvent.kind)
        .order_by(month.desc(), models.UsageEvent.kind)
    ).all()
    summary: dict[str, dict[str, int]] = {}
    for month_start, kind, total in rows:
        summary.setdefault(month_start.strftime("%Y-%m"), {})[str(kind)] = int(total)
    return [{"month": m, "totals": t} for m, t in summary.items()]
