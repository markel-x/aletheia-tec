"""``GET /status-lists/{public_id}``: Token Status List público y cacheable."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

from ..api.deps import BackendDep, SessionDep
from ..api.routing import TransactionalRoute
from ..platform.config import Settings
from ..usage import service as usage
from . import service

router = APIRouter(route_class=TransactionalRoute, tags=["public"])

STATUS_LIST_MEDIA_TYPE = "application/statuslist+jwt"


@router.get("/status-lists/{public_id}", response_class=Response)
def status_list_token(
    public_id: str, request: Request, session: SessionDep, backend: BackendDep
) -> Response:
    settings: Settings = request.app.state.settings
    signed = service.signed_token(session, backend, settings, public_id)
    if not signed.from_cache:
        usage.record(session, signed.status_list.organization_id, "status_list.served")
    return Response(
        content=signed.token,
        media_type=STATUS_LIST_MEDIA_TYPE,
        headers={"Cache-Control": f"public, max-age={service.TOKEN_TTL}"},
    )
