"""Ruta transaccional: la sesión de base de datos de la petición se confirma
**antes** de enviar la respuesta.

Si el ``COMMIT`` falla, el cliente recibe un 500 y no un 200 con datos que
nunca se guardaron. No se depende del orden en que FastAPI ejecute el código
de salida de las dependencias ``yield`` (ha cambiado entre versiones).
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Request, Response
from fastapi.routing import APIRoute, APIRouter
from starlette.concurrency import run_in_threadpool


class TransactionalRoute(APIRoute):
    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        original = super().get_route_handler()

        async def handler(request: Request) -> Response:
            try:
                response = await original(request)
            except BaseException:
                session = getattr(request.state, "db_session", None)
                if session is not None:
                    await run_in_threadpool(session.rollback)
                raise
            session = getattr(request.state, "db_session", None)
            if session is not None:
                await run_in_threadpool(session.commit)
            return response

        return handler


def api_router(**kwargs: Any) -> APIRouter:
    return APIRouter(route_class=TransactionalRoute, **kwargs)
