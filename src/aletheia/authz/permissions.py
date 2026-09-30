"""Matriz de permisos (docs/02 §4). Es la única fuente: el código nunca
compara roles, sólo permisos."""

from __future__ import annotations

from enum import StrEnum


class Permission(StrEnum):
    ORG_MANAGE = "org:manage"
    MEMBERS_MANAGE = "members:manage"
    API_CLIENTS_MANAGE = "api_clients:manage"
    TEMPLATES_WRITE = "templates:write"
    TEMPLATES_READ = "templates:read"
    CREDENTIALS_ISSUE = "credentials:issue"
    CREDENTIALS_READ = "credentials:read"
    CREDENTIALS_REVOKE = "credentials:revoke"
    VERIFICATIONS_CREATE = "verifications:create"
    TRUST_POLICIES_WRITE = "trust_policies:write"
    AUDIT_READ = "audit:read"
    USAGE_READ = "usage:read"
    SIGNING_KEYS_COMPROMISE = "signing_keys:compromise"


ROLES: tuple[str, ...] = ("owner", "admin", "issuer", "verifier", "auditor")

_ADMIN = frozenset(
    {
        Permission.ORG_MANAGE,
        Permission.MEMBERS_MANAGE,
        Permission.API_CLIENTS_MANAGE,
        Permission.TEMPLATES_WRITE,
        Permission.TEMPLATES_READ,
        Permission.CREDENTIALS_ISSUE,
        Permission.CREDENTIALS_READ,
        Permission.CREDENTIALS_REVOKE,
        Permission.VERIFICATIONS_CREATE,
        Permission.TRUST_POLICIES_WRITE,
        Permission.AUDIT_READ,
        Permission.USAGE_READ,
    }
)

ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "owner": _ADMIN | {Permission.SIGNING_KEYS_COMPROMISE},
    "admin": _ADMIN,
    "issuer": frozenset(
        {
            Permission.TEMPLATES_READ,
            Permission.CREDENTIALS_ISSUE,
            Permission.CREDENTIALS_READ,
            Permission.CREDENTIALS_REVOKE,
        }
    ),
    "verifier": frozenset({Permission.VERIFICATIONS_CREATE}),
    "auditor": frozenset(
        {
            Permission.TEMPLATES_READ,
            Permission.CREDENTIALS_READ,
            Permission.AUDIT_READ,
            Permission.USAGE_READ,
        }
    ),
}

# Las claves de API nunca gestionan personas ni declaran compromisos de claves.
API_CLIENT_PERMISSIONS: frozenset[Permission] = frozenset(Permission) - {
    Permission.MEMBERS_MANAGE,
    Permission.SIGNING_KEYS_COMPROMISE,
}


def permissions_for_role(role: str) -> frozenset[Permission]:
    return ROLE_PERMISSIONS[role]


def validate_role_name(role: str) -> str:
    if role not in ROLES:
        raise ValueError(f"Unknown role: {role}")
    return role
