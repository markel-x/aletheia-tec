"""Solicitudes de acceso: alta revisada en lugar de autoservicio.

Cada organización alojada es un emisor en el que otros confían, así que en esta etapa un operador
revisa quién la pide antes de crearla (``aletheia bootstrap``). El formulario público sólo guarda
la solicitud, con límites por red y por correo contra el abuso.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import models
from ..platform import ids, ratelimit
from ..platform.errors import NotFound

log = logging.getLogger(__name__)

PER_NETWORK_LIMIT = 5
PER_NETWORK_WINDOW = timedelta(hours=1)
PER_EMAIL_LIMIT = 3
PER_EMAIL_WINDOW = timedelta(days=1)


def create_request(
    session: Session,
    *,
    organization: str,
    contact_name: str,
    email: str,
    use_case: str,
    website: str | None,
    language: str,
    network: str | None,
) -> models.AccessRequest:
    if network:
        ratelimit.hit(
            session, f"access:net:{network}", limit=PER_NETWORK_LIMIT, window=PER_NETWORK_WINDOW
        )
    ratelimit.hit(
        session, f"access:email:{email.lower()}", limit=PER_EMAIL_LIMIT, window=PER_EMAIL_WINDOW
    )
    request = models.AccessRequest(
        id=ids.uuid7(),
        organization=organization,
        contact_name=contact_name,
        email=email,
        use_case=use_case,
        website=website or None,
        language=language,
    )
    session.add(request)
    session.flush()
    # Sin datos personales en el registro: sólo el id para buscarla.
    log.info("access request received", extra={"access_request_id": str(request.id)})
    return request


def list_requests(session: Session, status: str = "pending") -> list[models.AccessRequest]:
    return list(
        session.scalars(
            select(models.AccessRequest)
            .where(models.AccessRequest.status == status)
            .order_by(models.AccessRequest.created_at)
        )
    )


def mark(
    session: Session, request_id: str, status: str, now: datetime | None = None
) -> models.AccessRequest:
    if status not in ("approved", "rejected"):
        raise ValueError("status must be approved or rejected")
    request = session.scalar(
        select(models.AccessRequest).where(models.AccessRequest.id == request_id)
    )
    if request is None:
        raise NotFound("Access request not found")
    request.status = status
    request.processed_at = now or datetime.now(UTC)
    return request
