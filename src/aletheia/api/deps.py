"""Dependencias FastAPI compartidas: base de datos, principal y permisos."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from ..authz.permissions import Permission
from ..authz.service import Principal, authenticate
from ..organizations.keys import SignerBackend
from ..platform.crypto import DataEncryptor
from ..platform.db import Database, rls_bypass, set_bypass, set_tenant
from ..platform.errors import Forbidden, Unauthorized


def get_db(request: Request) -> Database:
    db: Database | None = request.app.state.db
    if db is None:
        raise RuntimeError("la base de datos no está configurada")
    return db


def get_session(request: Request, db: Annotated[Database, Depends(get_db)]) -> Iterator[Session]:
    """Sesión por petición. La confirma ``TransactionalRoute`` antes de responder;
    aquí sólo se garantiza el cierre (y el rollback de lo que quedara)."""
    session = db.session_factory()
    request.state.db_session = session
    try:
        yield session
    finally:
        session.close()


def get_system_session(session: Annotated[Session, Depends(get_session)]) -> Session:
    """Sesión para endpoints sin principal (login, OID4VCI, listas de estado,
    metadatos públicos): opera entre organizaciones de forma explícita."""
    set_bypass(session, True)
    return session


def get_signer_backend(request: Request) -> SignerBackend:
    backend: SignerBackend | None = request.app.state.signer_backend
    if backend is None:
        raise RuntimeError("el backend de firma no está configurado")
    return backend


def get_encryptor(request: Request) -> DataEncryptor:
    encryptor: DataEncryptor | None = request.app.state.encryptor
    if encryptor is None:
        raise RuntimeError("el cifrado de datos no está configurado")
    return encryptor


# auto_error=False: el error lo produce esta capa con el formato estable de la API.
# Declararlo como esquema de seguridad hace que Swagger UI ofrezca "Authorize".
bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="bearer",
    description="Token de sesión (st_…) o clave de API (ak_…)",
)


def get_principal(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None,
) -> Principal:
    if credentials is None or not credentials.credentials.strip():
        raise Unauthorized("Missing bearer token")
    with rls_bypass(session):  # la organización se conoce después de autenticar
        principal = authenticate(session, credentials.credentials.strip())
    set_tenant(session, principal.organization_id)
    request.state.principal = principal
    return principal


def require(*permissions: Permission) -> Callable[..., Principal]:
    """Dependencia que exige **todos** los permisos indicados."""

    def dependency(principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
        missing = [p for p in permissions if not principal.can(p)]
        if missing:
            raise Forbidden("Insufficient permissions", details=sorted(missing))
        return principal

    return dependency


SessionDep = Annotated[Session, Depends(get_session)]
SystemSessionDep = Annotated[Session, Depends(get_system_session)]
PrincipalDep = Annotated[Principal, Depends(get_principal)]
BackendDep = Annotated[SignerBackend, Depends(get_signer_backend)]
EncryptorDep = Annotated[DataEncryptor, Depends(get_encryptor)]
