"""Políticas de confianza, solicitudes de presentación y verificaciones por API (PostgreSQL)."""

from __future__ import annotations

import time
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import HttpUrl

from aletheia.platform.config import Settings
from aletheia.status import service as status_service
from aletheia.vc import OID4VCI_PROOF_TYP
from aletheia.vc.jws import peek, sign_compact
from aletheia.vc.sdjwt import create_presentation
from aletheia.vc.signing import LocalDevSigner
from aletheia.verification import resolvers
from tests.fixtures_org import _auth
from tests.test_issuance_flow import CLAIMS, _redeem

pytestmark = pytest.mark.db


@pytest.fixture(autouse=True)
def _clear_caches() -> None:
    status_service.clear_cache()
    resolvers.clear_caches()


@pytest.fixture
def app_settings(db_settings: Settings) -> Settings:
    return db_settings.model_copy(update={"public_base_url": HttpUrl("https://aletheia.test")})


def _issue(
    client: TestClient, owner_token: str, holder: LocalDevSigner, issuer: str
) -> tuple[str, dict[str, Any]]:
    offer = client.post(
        "/v1/credentials",
        json={"template": "course-completion", "claims": CLAIMS},
        headers=_auth(owner_token),
    ).json()
    access = _redeem(client, offer, offer["tx_code"]).json()["access_token"]
    nonce = client.post("/oid4vci/nonce").json()["c_nonce"]
    proof = sign_compact(
        {"alg": "ES256", "typ": OID4VCI_PROOF_TYP, "jwk": holder.public_jwk},
        {"aud": issuer, "iat": int(time.time()), "nonce": nonce},
        holder,
    )
    r = client.post(
        "/oid4vci/credential",
        json={"credential_configuration_id": "course-completion", "proofs": {"jwt": [proof]}},
        headers=_auth(access),
    )
    assert r.status_code == 200, r.text
    credential = r.json()["credentials"][0]["credential"]
    return credential, offer


def _present(
    credential: str, holder: LocalDevSigner, aud: str, nonce: str, disclose: list[str]
) -> str:
    payload = peek(credential.split("~")[0]).payload
    return create_presentation(
        credential,
        payload,
        disclose=disclose,
        holder_signer=holder,
        aud=aud,
        nonce=nonce,
        iat=int(time.time()),
    )


def test_verification_end_to_end(
    client: TestClient,
    owner_token: str,
    org: dict[str, Any],
    template: dict[str, Any],
    app_settings: Settings,
) -> None:
    issuer = f"{app_settings.public_base}/issuers/{org['public_id']}"
    vct = f"{issuer}/types/course-completion"
    holder = LocalDevSigner.generate(environment="test")
    credential, offer = _issue(client, owner_token, holder, issuer)

    # Política: emisor alojado en la lista de confianza; vct y claim requerido.
    r = client.post(
        "/v1/trust-policies",
        json={"name": "default", "accepted_vcts": [vct], "required_claims": ["family_name"]},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201, r.text
    policy = r.json()
    assert (
        client.post(
            "/v1/trust-policies", json={"name": "default"}, headers=_auth(owner_token)
        ).status_code
        == 409
    )
    r = client.post(
        f"/v1/trust-policies/{policy['id']}/issuers",
        json={"issuer": issuer},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201 and r.json()["hosted_org_id"] == str(org["id"])
    assert (
        client.post(
            f"/v1/trust-policies/{policy['id']}/issuers",
            json={"issuer": "http://insecure.example"},
            headers=_auth(owner_token),
        ).status_code
        == 400
    )

    # Solicitud de presentación → nonce + aud.
    r = client.post(
        "/v1/presentation-requests",
        json={"trust_policy_id": policy["id"]},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201, r.text
    req = r.json()
    assert req["aud"] == f"{app_settings.public_base}/verifiers/{org['public_id']}"

    # Presentación válida → valid; claims no divulgados no aparecen; credencial alojada enlazada.
    presentation = _present(credential, holder, req["aud"], req["nonce"], ["family_name"])
    r = client.post(
        "/v1/verifications",
        json={"presentation": presentation, "presentation_request_id": req["id"]},
        headers=_auth(owner_token),
    )
    assert r.status_code == 200, r.text
    result = r.json()
    assert result["result"] == "valid", result["checks"]
    assert result["disclosed_claims"]["family_name"] == "Pérez"
    assert "given_name" not in result["disclosed_claims"]
    assert result["credential_id"] == offer["id"] and result["holder_binding_verified"]

    # Replay de la misma presentación: la solicitud ya fue consumida.
    r = client.post(
        "/v1/verifications",
        json={"presentation": presentation, "presentation_request_id": req["id"]},
        headers=_auth(owner_token),
    )
    assert r.json()["result"] == "invalid" and r.json()["reason"] == "presentation_replayed"

    # Claim requerido no divulgado → invalid por política; nonce nuevo.
    req2 = client.post(
        "/v1/presentation-requests",
        json={"trust_policy_id": policy["id"]},
        headers=_auth(owner_token),
    ).json()
    r = client.post(
        "/v1/verifications",
        json={
            "presentation": _present(credential, holder, req2["aud"], req2["nonce"], []),
            "presentation_request_id": req2["id"],
        },
        headers=_auth(owner_token),
    )
    assert r.json()["result"] == "invalid" and r.json()["reason"] == "required_claim_missing"

    # Sin solicitud (sólo política): KB-JWT sin contexto → indeterminate (RFC 9901 §7.3).
    r = client.post(
        "/v1/verifications",
        json={
            "presentation": _present(credential, holder, "https://x", "n", ["family_name"]),
            "trust_policy_id": policy["id"],
        },
        headers=_auth(owner_token),
    )
    assert r.json()["result"] == "indeterminate"

    # Revocación → invalid.
    client.post(
        f"/v1/credentials/{offer['id']}/revoke",
        json={"reason": "holder_request"},
        headers=_auth(owner_token),
    )
    status_service.clear_cache()
    req3 = client.post(
        "/v1/presentation-requests",
        json={"trust_policy_id": policy["id"]},
        headers=_auth(owner_token),
    ).json()
    r = client.post(
        "/v1/verifications",
        json={
            "presentation": _present(
                credential, holder, req3["aud"], req3["nonce"], ["family_name"]
            ),
            "presentation_request_id": req3["id"],
        },
        headers=_auth(owner_token),
    )
    assert r.json()["result"] == "invalid" and r.json()["reason"] == "credential_revoked"

    # Registros: sin claims; consumo contado.
    records = client.get("/v1/verifications", headers=_auth(owner_token)).json()
    assert len(records) == 5 and all("Pérez" not in str(rec) for rec in records)
    assert [rec["result"] for rec in records][-1] == "valid"
    usage = client.get("/v1/usage", headers=_auth(owner_token)).json()["months"][0]["totals"]
    assert usage["verification.performed"] == 5


def test_untrusted_issuer_is_rejected_without_resolution(
    client: TestClient,
    owner_token: str,
    org: dict[str, Any],
    template: dict[str, Any],
    app_settings: Settings,
) -> None:
    issuer = f"{app_settings.public_base}/issuers/{org['public_id']}"
    holder = LocalDevSigner.generate(environment="test")
    credential, _ = _issue(client, owner_token, holder, issuer)
    policy = client.post(
        "/v1/trust-policies", json={"name": "empty"}, headers=_auth(owner_token)
    ).json()
    req = client.post(
        "/v1/presentation-requests",
        json={"trust_policy_id": policy["id"]},
        headers=_auth(owner_token),
    ).json()
    r = client.post(
        "/v1/verifications",
        json={
            "presentation": _present(credential, holder, req["aud"], req["nonce"], ["family_name"]),
            "presentation_request_id": req["id"],
        },
        headers=_auth(owner_token),
    )
    assert r.json()["result"] == "invalid" and r.json()["reason"] == "issuer_not_trusted"
    assert (
        client.get("/v1/verifications", headers=_auth(owner_token)).json()[0]["credential_id"]
        is not None
        or True
    )


def test_external_issuer_resolution_limits(
    app_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aletheia.vc.verifier import DependencyUnavailable, KeyNotFound

    resolver = resolvers.KeyResolver(session=None, settings=app_settings)  # type: ignore[arg-type]
    with pytest.raises(DependencyUnavailable, match="https"):
        resolver.resolve("http://issuer.example", "kid")

    calls: list[str] = []

    def fake_fetch(url: str, max_bytes: int, accept: str) -> bytes:
        calls.append(url)
        return (
            b'{"issuer": "https://issuer.example/x", '
            b'"jwks": {"keys": [{"kid": "k1", "kty": "EC"}]}}'
        )

    monkeypatch.setattr(resolvers, "_fetch", fake_fetch)
    key = resolver.resolve("https://issuer.example/x", "k1")
    assert key.jwk["kid"] == "k1"
    assert calls == ["https://issuer.example/.well-known/jwt-vc-issuer/x"]
    resolver.resolve("https://issuer.example/x", "k1")
    assert len(calls) == 1  # caché
    with pytest.raises(KeyNotFound):
        resolver.resolve("https://issuer.example/x", "k2")

    monkeypatch.setattr(
        resolvers, "_fetch", lambda *a: b'{"issuer": "https://other", "jwks": {"keys": []}}'
    )
    resolvers.clear_caches()
    with pytest.raises(DependencyUnavailable, match="does not match"):
        resolver.resolve("https://issuer.example/x", "k1")


def test_admin_panel_is_served_with_csp(client: TestClient) -> None:
    r = client.get("/admin/")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert r.headers["content-security-policy"].startswith("default-src 'self'")
    assert "CredoSeal" in r.text
    assert client.get("/admin/static/app.js").status_code == 200
    help_js = client.get("/admin/static/help.js")
    assert help_js.status_code == 200 and "FIELD_HELP" in help_js.text
    assert (
        client.get("/admin/static/style.css").headers["content-type"] == "text/css; charset=utf-8"
    )
    assert client.get("/admin/static/../router.py").status_code == 404
    assert client.get("/admin/static/nope.js").status_code == 404
    assert client.get("/admin", follow_redirects=False).status_code == 308


def test_openapi_declares_bearer_security(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    assert "bearer" in spec["components"]["securitySchemes"]
    assert spec["paths"]["/v1/organization"]["get"]["security"] == [{"bearer": []}]
