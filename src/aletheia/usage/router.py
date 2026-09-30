"""``GET /v1/usage``: consumo mensual de la organización."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from ..api.deps import SessionDep, require
from ..api.routing import TransactionalRoute
from ..authz.permissions import Permission
from ..authz.service import Principal
from . import service

router = APIRouter(route_class=TransactionalRoute, prefix="/v1", tags=["usage"])


@router.get("/usage")
def usage_summary(
    principal: Annotated[Principal, Depends(require(Permission.USAGE_READ))],
    session: SessionDep,
    months: Annotated[int, Query(ge=1, le=24)] = 12,
) -> dict[str, Any]:
    return {"months": service.monthly_summary(session, principal.organization_id, months=months)}
