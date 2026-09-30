"""Permisos, identificadores y contraseñas: sin base de datos."""

from __future__ import annotations

import uuid

from aletheia.authz.permissions import (
    API_CLIENT_PERMISSIONS,
    ROLE_PERMISSIONS,
    ROLES,
    Permission,
)
from aletheia.authz.service import hash_password, network_prefix, verify_password
from aletheia.platform import ids


def test_permission_matrix_matches_doc_02() -> None:
    assert set(ROLE_PERMISSIONS) == set(ROLES)
    assert ROLE_PERMISSIONS["owner"] == frozenset(Permission)
    assert Permission.SIGNING_KEYS_COMPROMISE not in ROLE_PERMISSIONS["admin"]
    assert ROLE_PERMISSIONS["admin"] == ROLE_PERMISSIONS["owner"] - {
        Permission.SIGNING_KEYS_COMPROMISE
    }
    assert ROLE_PERMISSIONS["issuer"] == {
        Permission.TEMPLATES_READ,
        Permission.CREDENTIALS_ISSUE,
        Permission.CREDENTIALS_READ,
        Permission.CREDENTIALS_REVOKE,
    }
    assert ROLE_PERMISSIONS["verifier"] == {Permission.VERIFICATIONS_CREATE}
    assert ROLE_PERMISSIONS["auditor"] == {
        Permission.TEMPLATES_READ,
        Permission.CREDENTIALS_READ,
        Permission.AUDIT_READ,
        Permission.USAGE_READ,
    }
    assert Permission.MEMBERS_MANAGE not in API_CLIENT_PERMISSIONS
    assert Permission.SIGNING_KEYS_COMPROMISE not in API_CLIENT_PERMISSIONS


def test_uuid7_is_time_ordered_and_versioned() -> None:
    a, b = ids.uuid7(), ids.uuid7()
    assert a.version == 7 and b.version == 7
    assert a.variant == uuid.RFC_4122
    assert a.int >> 80 <= b.int >> 80  # marca de tiempo no decreciente


def test_public_id_format() -> None:
    value = ids.public_id("org")
    assert len(value) == 26 and value.startswith("org_")
    assert value[4:].isalnum()


def test_session_token_roundtrip() -> None:
    token, token_hash = ids.new_session_token()
    assert token.startswith("st_") and len(token) == 46
    assert ids.parse_session_token(token) == token_hash
    assert ids.parse_session_token("st_short") is None
    assert ids.parse_session_token(token + "x") is None


def test_api_key_roundtrip() -> None:
    full, prefix, secret_hash = ids.new_api_key()
    assert full.startswith(prefix + "_") and len(prefix) == 11
    assert ids.parse_api_key(full) == (prefix, secret_hash)
    assert ids.parse_api_key(prefix) is None
    tampered = full[:-1] + ("A" if full[-1] != "A" else "B")
    parsed = ids.parse_api_key(tampered)
    assert parsed is not None and parsed[1] != secret_hash


def test_password_hashing_is_argon2id() -> None:
    h = hash_password("correct horse battery staple")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "correct horse battery staple")
    assert not verify_password(h, "wrong")
    assert not verify_password("not-a-hash", "x")


def test_network_prefix_truncates() -> None:
    assert network_prefix("203.0.113.77") == "203.0.113.0/24"
    assert network_prefix("2001:db8:abcd:1234:5678::1") == "2001:db8:abcd:1234::/64"
    assert network_prefix("not an ip") is None
    assert network_prefix(None) is None
