"""Endpoints de operación: ``/healthz`` y ``/readyz``.

Públicos y sin detalles internos (doc 02 §1). ``healthz`` responde si el
proceso atiende peticiones; ``readyz`` además comprueba la base de datos y
que el esquema esté en la revisión que espera esta versión del código.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request, Response

from .. import __version__
from ..db.migrations import head_revision
from ..platform.db import Database

log = logging.getLogger(__name__)
router = APIRouter(tags=["operations"])


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@router.get("/readyz")
def readyz(request: Request, response: Response) -> dict[str, str]:
    db: Database | None = request.app.state.db
    status = "ok"
    if db is None:
        status = "database_not_configured"
    else:
        try:
            db.ping()
            applied = db.schema_revision()
            expected = head_revision()
            if applied != expected:
                status = "schema_out_of_date"
                log.warning(
                    "schema revision mismatch", extra={"applied": applied, "head": expected}
                )
        except Exception as exc:  # noqa: BLE001 - cualquier fallo de la BD = no listo
            status = "database_unavailable"
            log.warning("readiness check failed", extra={"exc_class": type(exc).__name__})
    if status != "ok":
        response.status_code = 503
    return {"status": status}
