"""Dependencias FastAPI compartidas: base de datos, principal y permisos."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from ..authz.permissions import Permission
from ..authz.service import Principal, authenticate
from ..organizations.keys import SignerBackend
from ..platform.db import Database
from ..platform.errors import Forbidden, Unauthorized


def get_db(request: Request) -> Database:
    db: Database | None = request.app.state.db
    if db is None:
        raise RuntimeError("la base de datos no está configurada")
    return db


def get_session(db: Annotated[Database, Depends(get_db)]) -> Iterator[Session]:
    with db.session() as session:
        yield session


def get_signer_backend(request: Request) -> SignerBackend:
    backend: SignerBackend | None = request.app.state.signer_backend
    if backend is None:
        raise RuntimeError("el backend de firma no está configurado")
    return backend


def get_principal(request: Request, session: Annotated[Session, Depends(get_session)]) -> Principal:
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise Unauthorized("Missing bearer token")
    principal = authenticate(session, token.strip())
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
PrincipalDep = Annotated[Principal, Depends(get_principal)]
BackendDep = Annotated[SignerBackend, Depends(get_signer_backend)]
