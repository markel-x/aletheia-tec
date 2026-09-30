"""Tarea programada ``aletheia maintenance`` (ADR-0008).

Purga datos caducados según la retención documentada en docs/03. Cada paso
es una sentencia acotada e idempotente; el resultado se registra con
recuentos, nunca con contenido.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, Delete, Update, delete, func, select, update
from sqlalchemy.orm import Session

from .db import models

log = logging.getLogger(__name__)


def _affected(session: Session, statement: Delete | Update) -> int:
    result = cast(CursorResult[Any], session.execute(statement))
    return int(result.rowcount)


def run_maintenance(session: Session, now: datetime | None = None) -> dict[str, int]:
    now = now or datetime.now(UTC)
    counts: dict[str, int] = {}

    # Ofertas vencidas: cambian de estado y pierden sus claims pendientes.
    expired_offers = (
        select(models.Issuance.id)
        .where(models.Issuance.state == "offered")
        .where(models.Issuance.offer_expires_at < now)
    )
    counts["pending_purged"] = _affected(
        session,
        delete(models.IssuancePendingClaims).where(
            models.IssuancePendingClaims.issuance_id.in_(expired_offers)
        ),
    )
    counts["offers_expired"] = _affected(
        session,
        update(models.Issuance)
        .where(models.Issuance.id.in_(expired_offers))
        .values(state="offer_expired"),
    )
    # Residuos: claims pendientes de ofertas que ya no están en "offered".
    counts["pending_residual"] = _affected(
        session,
        delete(models.IssuancePendingClaims).where(
            models.IssuancePendingClaims.issuance_id.in_(
                select(models.Issuance.id).where(models.Issuance.state != "offered")
            )
        ),
    )

    counts["oid4vci_nonces"] = _affected(
        session, delete(models.Oid4vciNonce).where(models.Oid4vciNonce.expires_at < now)
    )
    counts["oid4vci_grants"] = _affected(
        session,
        delete(models.Oid4vciAccessToken).where(models.Oid4vciAccessToken.expires_at < now),
    )
    counts["sessions"] = _affected(
        session,
        delete(models.Session).where(models.Session.expires_at < now - timedelta(days=7)),
    )
    counts["presentation_requests"] = _affected(
        session,
        delete(models.PresentationRequest).where(
            models.PresentationRequest.expires_at < now - timedelta(hours=24)
        ),
    )
    counts["idempotency_records"] = _affected(
        session,
        delete(models.IdempotencyRecord).where(models.IdempotencyRecord.expires_at < now),
    )
    counts["rate_limit_buckets"] = _affected(
        session,
        delete(models.RateLimitBucket).where(
            models.RateLimitBucket.window_start < now - timedelta(hours=1)
        ),
    )

    # Retención por organización (verificaciones y consumo; auditoría en un incremento posterior,
    # cuando exista la política de conservación legal).
    beyond_retention = (
        select(models.Organization.id)
        .where(models.Organization.id == models.VerificationRecord.organization_id)
        .where(
            models.VerificationRecord.created_at
            < now - func.make_interval(0, 0, 0, models.Organization.data_retention_days)
        )
        .exists()
    )
    counts["verification_records"] = _affected(
        session, delete(models.VerificationRecord).where(beyond_retention)
    )
    counts["usage_events"] = _affected(
        session,
        delete(models.UsageEvent).where(models.UsageEvent.occurred_at < now - timedelta(days=730)),
    )

    log.info("maintenance finished", extra=counts)
    return counts
