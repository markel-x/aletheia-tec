"""Listas de estado.

- Una lista ``open`` por organización; 131 072 entradas de 1 bit; índice
  aleatorio sin reutilización (la PK de ``credential_status`` detecta colisiones).
- Revocar = poner el bit a INVALID e incrementar ``status_list.version`` en la
  misma transacción que el resto del cambio.
- El token se construye y firma a demanda con la clave activa de la
  organización; caché en proceso por ``(lista, versión)`` durante ``ttl``.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy import CursorResult, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..db import models
from ..organizations.keys import SignerBackend
from ..organizations.service import active_signing_key, issuer_url
from ..platform import ids
from ..platform.config import Settings
from ..platform.errors import AppError, NotFound
from ..vc.status_list import INVALID, StatusList, StatusReference, build_status_list_token

log = logging.getLogger(__name__)

LIST_SIZE = 131_072
LIST_BITS = 1
TOKEN_TTL = 300
TOKEN_LIFETIME = 86_400
MAX_ALLOCATION_ATTEMPTS = 16


class StatusListFull(AppError):
    status_code = 503
    code = "status_list_unavailable"


def status_list_uri(settings: Settings, public_id: str) -> str:
    return f"{settings.public_base}/status-lists/{public_id}"


def _open_list(session: Session, organization_id: uuid.UUID) -> models.StatusList:
    open_list = session.scalar(
        select(models.StatusList)
        .where(models.StatusList.organization_id == organization_id)
        .where(models.StatusList.state == "open")
        .with_for_update()
    )
    if open_list is not None:
        return open_list
    key = active_signing_key(session, organization_id)
    open_list = models.StatusList(
        id=ids.uuid7(),
        public_id=ids.public_id("sl"),
        organization_id=organization_id,
        bits=LIST_BITS,
        size=LIST_SIZE,
        signing_key_id=key.id,
    )
    session.add(open_list)
    session.flush()
    return open_list


@dataclass(frozen=True)
class Allocation:
    status_list: models.StatusList
    idx: int

    def reference(self, settings: Settings) -> StatusReference:
        return StatusReference(
            idx=self.idx, uri=status_list_uri(settings, self.status_list.public_id)
        )


def allocate(session: Session, organization_id: uuid.UUID) -> Allocation:
    """Reserva un índice aleatorio en la lista abierta de la organización."""
    status_list = _open_list(session, organization_id)
    for _ in range(MAX_ALLOCATION_ATTEMPTS):
        idx = secrets.randbelow(status_list.size)
        try:
            with session.begin_nested():
                session.add(
                    models.CredentialStatus(
                        status_list_id=status_list.id, idx=idx, organization_id=organization_id
                    )
                )
                session.flush()
        except IntegrityError:
            continue  # colisión: el savepoint se revirtió; se prueba otro índice
        status_list.allocated += 1
        if status_list.allocated >= status_list.size:
            status_list.state = "full"
        return Allocation(status_list, idx)
    raise StatusListFull("Could not allocate a status index; retry later")


def mark_invalid(session: Session, status_list_id: uuid.UUID, idx: int) -> None:
    result = session.execute(
        update(models.CredentialStatus)
        .where(models.CredentialStatus.status_list_id == status_list_id)
        .where(models.CredentialStatus.idx == idx)
        .where(models.CredentialStatus.value != INVALID)
        .values(value=INVALID)
    )
    if cast(CursorResult[Any], result).rowcount:
        session.execute(
            update(models.StatusList)
            .where(models.StatusList.id == status_list_id)
            .values(version=models.StatusList.version + 1)
        )


# ---------------------------------------------------------------------------
# Token firmado con caché
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CachedToken:
    token: str
    version: int
    iat: int


_cache: dict[uuid.UUID, CachedToken] = {}
_cache_lock = threading.Lock()


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


@dataclass(frozen=True)
class SignedToken:
    token: str
    from_cache: bool
    status_list: models.StatusList


def signed_token(
    session: Session,
    backend: SignerBackend,
    settings: Settings,
    public_id: str,
    now: int | None = None,
) -> SignedToken:
    now = now or int(time.time())
    status_list = session.scalar(
        select(models.StatusList).where(models.StatusList.public_id == public_id)
    )
    if status_list is None:
        raise NotFound("Status list not found")
    with _cache_lock:
        cached = _cache.get(status_list.id)
    if cached and cached.version == status_list.version and now - cached.iat < TOKEN_TTL:
        return SignedToken(cached.token, True, status_list)

    bitmap = StatusList(size=status_list.size, bits=status_list.bits)
    rows = session.execute(
        select(models.CredentialStatus.idx, models.CredentialStatus.value)
        .where(models.CredentialStatus.status_list_id == status_list.id)
        .where(models.CredentialStatus.value != 0)
    ).all()
    for idx, value in rows:
        bitmap.set(int(idx), int(value))
    org = session.get_one(models.Organization, status_list.organization_id)
    key = active_signing_key(session, org.id)
    if status_list.signing_key_id != key.id:
        status_list.signing_key_id = key.id
    signer = backend.load(key.key_ref, key.public_jwk)
    token = build_status_list_token(
        bitmap,
        uri=status_list_uri(settings, public_id),
        issuer=issuer_url(settings, org.public_id),
        signer=signer,
        iat=now,
        ttl=TOKEN_TTL,
        lifetime=TOKEN_LIFETIME,
    )
    with _cache_lock:
        _cache[status_list.id] = CachedToken(token, status_list.version, now)
    return SignedToken(token, False, status_list)
