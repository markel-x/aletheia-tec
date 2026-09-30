"""Fábrica de la aplicación.

``create_app(settings)`` construye una instancia aislada (las pruebas crean
varias). La base de datos se abre en el ``lifespan`` y queda en
``app.state.db``; los routers la obtienen con ``get_db``.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from sqlalchemy.orm import Session

from .. import __version__
from ..platform.config import Settings, get_settings
from ..platform.db import Database
from ..platform.errors import install_error_handlers
from ..platform.logging import configure_logging
from ..platform.middleware import RequestContextMiddleware
from . import operations

log = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = settings
        app.state.db = Database(settings) if settings.database_url is not None else None
        log.info("api starting", extra={"env": settings.env, "version": __version__})
        try:
            yield
        finally:
            if app.state.db is not None:
                app.state.db.dispose()
            log.info("api stopped")

    app = FastAPI(
        title="Aletheia",
        version=__version__,
        lifespan=lifespan,
        # La documentación interactiva sólo en entornos no desplegados.
        docs_url=None if settings.env.is_deployed else "/docs",
        redoc_url=None,
        openapi_url=None if settings.env.is_deployed else "/openapi.json",
    )
    app.add_middleware(RequestContextMiddleware)
    install_error_handlers(app)
    app.include_router(operations.router)
    return app


def get_db(request: Request) -> Database:
    db: Database | None = request.app.state.db
    if db is None:
        raise RuntimeError("la base de datos no está configurada")
    return db


def get_session(db: Database = Depends(get_db)) -> Iterator[Session]:  # noqa: B008
    with db.session() as session:
        yield session
