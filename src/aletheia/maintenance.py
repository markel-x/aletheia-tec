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
    # Resultados OID4VP (con claims divulgados, cifrados): 10 minutos tras la respuesta.
    counts["oid4vp_results"] = _affected(
        session,
        update(models.Oid4vpSession)
        .where(models.Oid4vpSession.result_ciphertext.is_not(None))
        .where(models.Oid4vpSession.completed_at < now - timedelta(minutes=10))
        .values(result_ciphertext=None, result_encrypted_key=None, result_key_ref=None),
    )
    # Solicitudes firmadas (nonce/state en claro) y claves de respuesta de sesiones vencidas.
    counts["oid4vp_request_material"] = _affected(
        session,
        update(models.Oid4vpSession)
        .where(models.Oid4vpSession.created_at < now - timedelta(minutes=15))
        .where(
            (models.Oid4vpSession.request_object.is_not(None))
            | (models.Oid4vpSession.response_key_ciphertext.is_not(None))
        )
        .values(
            request_object=None,
            response_key_ciphertext=None,
            response_key_encrypted_key=None,
            response_key_ref=None,
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

    # Solicitudes de acceso (datos de contacto): resueltas, 180 días; sin resolver, 1 año.
    counts["access_requests"] = _affected(
        session,
        delete(models.AccessRequest).where(
            (
                (models.AccessRequest.status != "pending")
                & (models.AccessRequest.processed_at < now - timedelta(days=180))
            )
            | (models.AccessRequest.created_at < now - timedelta(days=365))
        ),
    )

    log.info("maintenance finished", extra=counts)
    return counts
