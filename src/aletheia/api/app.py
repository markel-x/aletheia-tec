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
from ..access import router as access_router
from ..admin import router as admin_router
from ..authz import router as authz_router
from ..issuance import oid4vci as oid4vci_router
from ..issuance import router as issuance_router
from ..organizations import router as organizations_router
from ..organizations.keys import build_backend
from ..passes import router as passes_router
from ..passes.google import load_google_wallet
from ..passes.signing import load_pass_signer
from ..platform.config import Settings, get_settings
from ..platform.crypto import build_encryptor, tx_code_key
from ..platform.db import Database
from ..platform.errors import install_error_handlers
from ..platform.logging import configure_logging
from ..platform.middleware import RequestContextMiddleware
from ..platform.site_gate import SiteGateMiddleware
from ..status import router as status_router
from ..usage import router as usage_router
from ..verification import oid4vp as oid4vp_verifier
from ..verification import router as verification_router
from ..verification.identity import load_identity
from . import operations

log = logging.getLogger(__name__)


def create_app(settings: Settings | None = None, *, kms_client: Any | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_format)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = settings
        app.state.db = Database(settings) if settings.database_url is not None else None
        has_db = settings.database_url is not None
        app.state.signer_backend = build_backend(settings, kms_client) if has_db else None
        app.state.encryptor = build_encryptor(settings, kms_client) if has_db else None
        app.state.verifier_identity = load_identity(settings) if has_db else None
        app.state.pass_signer = load_pass_signer(settings) if has_db else None
        app.state.google_wallet = load_google_wallet(settings) if has_db else None
        if has_db:
            tx_code_key(settings)  # falla al arrancar si falta la clave en un entorno desplegado
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
        title="CredoSeal",
        version=__version__,
        lifespan=lifespan,
        # La documentación interactiva sólo en entornos no desplegados.
        docs_url=None if settings.env.is_deployed else "/docs",
        redoc_url=None,
        openapi_url=None if settings.env.is_deployed else "/openapi.json",
    )
    app.add_middleware(RequestContextMiddleware)
    if settings.site_basic_auth is not None:
        # Por fuera de todo: responde 401 antes de tocar la base o los registros de la app.
        app.add_middleware(
            SiteGateMiddleware, credentials=settings.site_basic_auth.get_secret_value()
        )
    install_error_handlers(app)
    app.include_router(operations.router)
    app.include_router(authz_router.router)
    app.include_router(organizations_router.router)
    app.include_router(organizations_router.public_router)
    app.include_router(issuance_router.router)
    app.include_router(oid4vci_router.router)
    app.include_router(status_router.router)
    app.include_router(usage_router.router)
    app.include_router(verification_router.router)
    app.include_router(oid4vp_verifier.router)
    app.include_router(oid4vp_verifier.public_router)
    app.include_router(admin_router.router)
    app.include_router(passes_router.router)
    app.include_router(access_router.router)
    return app
