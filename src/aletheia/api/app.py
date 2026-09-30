"""Fábrica de la aplicación.

``create_app(settings)`` construye una instancia aislada (las pruebas crean
varias). La base de datos y el backend de firma se abren en el ``lifespan``
y quedan en ``app.state``; los routers los obtienen vía ``api.deps``.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from .. import __version__
from ..authz import router as authz_router
from ..organizations import router as organizations_router
from ..organizations.keys import build_backend
from ..platform.config import Settings, get_settings
from ..platform.db import Database
from ..platform.errors import install_error_handlers
from ..platform.logging import configure_logging
from ..platform.middleware import RequestContextMiddleware
from . import operations

log = logging.getLogger(__name__)


def create_app(settings: Settings | None = None, *, kms_client: Any | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = settings
        app.state.db = Database(settings) if settings.database_url is not None else None
        app.state.signer_backend = (
            build_backend(settings, kms_client) if settings.database_url is not None else None
        )
        log.info(
            "api starting",
            extra={
                "env": settings.env,
                "version": __version__,
                "signing_backend": settings.signing_backend,
            },
        )
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
    app.include_router(authz_router.router)
    app.include_router(organizations_router.router)
    app.include_router(organizations_router.public_router)
    return app
