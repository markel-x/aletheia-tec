"""Servicio de auditoría.

Cada acción sensible deja una fila en ``audit_event``. ``metadata`` nunca
lleva datos personales ni secretos: sólo identificadores, códigos y estados.
La tabla es append-only por privilegios y por trigger; el ORM no expone
operaciones de borrado ni actualización sobre ella.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import models
from ..platform.ids import uuid7
from ..platform.logging import request_id_var

SYSTEM_ACTOR_TYPE = "system"


@dataclass(frozen=True)
class Actor:
    type: str  # user | api_client | system | holder
    id: uuid.UUID | None = None

    @classmethod
    def system(cls) -> Actor:
        return cls(SYSTEM_ACTOR_TYPE, None)


def record(
    session: Session,
    *,
    organization_id: uuid.UUID,
    actor: Actor,
    action: str,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    metadata: dict[str, Any] | None = None,
) -> models.AuditEvent:
    event = models.AuditEvent(
        id=uuid7(),
        organization_id=organization_id,
        actor_type=actor.type,
        actor_id=actor.id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        request_id=request_id_var.get(),
        metadata_=metadata or {},
    )
    session.add(event)
    return event


def list_events(
    session: Session,
    organization_id: uuid.UUID,
    *,
    limit: int = 100,
    target_id: uuid.UUID | None = None,
) -> list[models.AuditEvent]:
    stmt = (
        select(models.AuditEvent)
        .where(models.AuditEvent.organization_id == organization_id)
        .order_by(models.AuditEvent.occurred_at.desc(), models.AuditEvent.id.desc())
        .limit(limit)
    )
    if target_id is not None:
        stmt = stmt.where(models.AuditEvent.target_id == target_id)
    return list(session.scalars(stmt).all())
