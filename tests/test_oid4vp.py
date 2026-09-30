"""OID4VP 1.0: Aletheia como verificador; las pruebas actúan como wallet (PostgreSQL)."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from aletheia.maintenance import run_maintenance
from aletheia.platform.config import Settings
from aletheia.platform.db import Database
from aletheia.status import service as status_service
from aletheia.vc.jws import peek
from aletheia.vc.sdjwt import create_presentation
from aletheia.vc.signing import LocalDevSigner
from aletheia.verification import resolvers
from tests.fixtures_org import _auth
from tests.test_verification_api import _issue

pytestmark = pytest.mark.db


@pytest.fixture(autouse=True)
def _clear_caches() -> None:
    status_service.clear_cache()
    resolvers.clear_caches()


@pytest.fixture
def setup(
    client: TestClient,
    owner_token: str,
    org: dict[str, Any],
    template: dict[str, Any],
    app_settings: Settings,
) -> dict[str, Any]:
    issuer = f"{app_settings.public_base}/issuers/{org['public_id']}"
    vct = f"{issuer}/types/course-completion"
    holder = LocalDevSigner.generate(environment="test")
    credential, offer = _issue(client, owner_token, holder, issuer)
    policy = client.post(
        "/v1/trust-policies",
        json={"name": "oid4vp", "accepted_vcts": [vct], "required_claims": ["family_name"]},
        headers=_auth(owner_token),
    ).json()
    client.post(
        f"/v1/trust-policies/{policy['id']}/issuers",
        json={"issuer": issuer},
        headers=_auth(owner_token),
    )
    return {
        "credential": credential,
        "holder": holder,
        "offer": offer,
        "policy": policy,
        "vct": vct,
    }


def _open(
    client: TestClient, token: str, body: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, str]]:
    r = client.post("/v1/oid4vp/requests", json=body, headers=_auth(token))
    assert r.status_code == 201, r.text
    created = r.json()
    url = urlparse(created["request_uri"])
    assert url.scheme == "openid4vp"
    params = {k: v[0] for k, v in parse_qs(url.query).items()}
    return created, params


def _present(
    ctx: dict[str, Any], params: dict[str, str], disclose: list[str], aud: str | None = None
) -> str:
    payload = peek(ctx["credential"].split("~")[0]).payload
    presentation = create_presentation(
        ctx["credential"],
        payload,
        disclose=disclose,
        holder_signer=ctx["holder"],
        aud=aud or params["client_id"],
        nonce=params["nonce"],
        iat=int(time.time()),
    )
    return json.dumps({"credential": [presentation]})


def _post(client: TestClient, params: dict[str, str], **form: str) -> Any:
    return client.post(
        urlparse(params["response_uri"]).path, data={"state": params["state"], **form}
    )


def test_oid4vp_cross_device_flow(
    client: TestClient, owner_token: str, setup: dict[str, Any], app_settings: Settings
) -> None:
    created, params = _open(client, owner_token, {"trust_policy_id": setup["policy"]["id"]})

    # Solicitud por valor conforme al perfil (ADR-0014).
    assert params["response_type"] == "vp_token"
    assert params["response_mode"] == "direct_post"
    assert params["client_id"] == f"redirect_uri:{app_settings.public_base}/oid4vp/response"
    assert params["response_uri"] == f"{app_settings.public_base}/oid4vp/response"
    dcql = json.loads(params["dcql_query"])
    assert dcql == created["dcql_query"]
    assert dcql["credentials"][0]["format"] == "dc+sd-jwt"
    assert dcql["credentials"][0]["meta"]["vct_values"] == [setup["vct"]]
    assert dcql["credentials"][0]["claims"] == [{"path": ["family_name"]}]
    meta = json.loads(params["client_metadata"])
    assert meta["vp_formats_supported"]["dc+sd-jwt"]["kb-jwt_alg_values"] == ["ES256"]
    assert created["qr_svg"].startswith("data:image/svg+xml")
    assert (
        client.get(f"/v1/oid4vp/requests/{created['id']}", headers=_auth(owner_token)).json()[
            "status"
        ]
        == "pending"
    )

    # El wallet responde (direct_post) con aud = client_id y el nonce de la solicitud.
    r = _post(client, params, vp_token=_present(setup, params, ["family_name"]))
    assert r.status_code == 200, r.text
    assert r.json() == {} and r.headers["cache-control"] == "no-store"

    status = client.get(f"/v1/oid4vp/requests/{created['id']}", headers=_auth(owner_token)).json()
    assert status["status"] == "completed" and status["verification_id"]
    result = status["result"]
    assert result["result"] == "valid", result["checks"]
    assert result["disclosed_claims"]["family_name"] == "Pérez"
    assert "given_name" not in result["disclosed_claims"]
    assert result["credential_id"] == setup["offer"]["id"]
    assert result["holder_binding_verified"] is True
    assert {"name": "dcql", "outcome": "pass", "code": "ok", "detail": ""} in result["checks"]

    # Replay: el state ya fue respondido.
    r = _post(client, params, vp_token=_present(setup, params, ["family_name"]))
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"

    # El registro de verificación existe y no guarda claims.
    records = client.get("/v1/verifications", headers=_auth(owner_token)).json()
    assert records[0]["id"] == status["verification_id"] and "Pérez" not in json.dumps(records)


def test_requested_claim_not_disclosed_is_invalid(
    client: TestClient, owner_token: str, setup: dict[str, Any]
) -> None:
    created, params = _open(
        client,
        owner_token,
        {
            "trust_policy_id": setup["policy"]["id"],
            "claims": [["family_name"], ["course", "grade"]],
        },
    )
    r = _post(client, params, vp_token=_present(setup, params, ["family_name"]))
    assert r.status_code == 200
    result = client.get(f"/v1/oid4vp/requests/{created['id']}", headers=_auth(owner_token)).json()[
        "result"
    ]
    assert result["result"] == "invalid" and result["reason"] == "requested_claim_missing"
    assert result["disclosed_claims"] is None  # no se entregan claims de un resultado inválido


def test_wallet_decline_wrong_audience_and_bad_input(
    client: TestClient, owner_token: str, setup: dict[str, Any]
) -> None:
    created, params = _open(client, owner_token, {"trust_policy_id": setup["policy"]["id"]})
    assert _post(client, params, error="access_denied").status_code == 200
    status = client.get(f"/v1/oid4vp/requests/{created['id']}", headers=_auth(owner_token)).json()
    assert (
        status["status"] == "failed"
        and status["error"] == "access_denied"
        and status["result"] is None
    )

    # KB-JWT con otro aud (p. ej. reutilizado de otra solicitud) → inválido.
    created, params = _open(client, owner_token, {"trust_policy_id": setup["policy"]["id"]})
    r = _post(client, params, vp_token=_present(setup, params, ["family_name"], aud="https://otro"))
    assert r.status_code == 200
    result = client.get(f"/v1/oid4vp/requests/{created['id']}", headers=_auth(owner_token)).json()[
        "result"
    ]
    assert result["result"] != "valid"

    _, params = _open(client, owner_token, {"trust_policy_id": setup["policy"]["id"]})
    for bad in ("no-json", json.dumps({"other": ["x"]}), json.dumps({"credential": ["a", "b"]})):
        r = _post(client, params, vp_token=bad)
        assert r.status_code == 400 and r.json()["error"] == "invalid_request"
    r = client.post("/oid4vp/response", data={"state": "desconocido", "vp_token": "{}"})
    assert r.status_code == 400
    assert (
        client.get(
            "/v1/oid4vp/requests/00000000-0000-7000-8000-000000000000", headers=_auth(owner_token)
        ).status_code
        == 404
    )


def test_policy_without_vct_is_rejected(
    client: TestClient, owner_token: str, setup: dict[str, Any]
) -> None:
    policy = client.post(
        "/v1/trust-policies", json={"name": "sin-vct"}, headers=_auth(owner_token)
    ).json()
    r = client.post(
        "/v1/oid4vp/requests", json={"trust_policy_id": policy["id"]}, headers=_auth(owner_token)
    )
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_dcql"
    r = client.post(
        "/v1/oid4vp/requests",
        json={"trust_policy_id": policy["id"], "vct_values": [setup["vct"]]},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201


def test_result_is_purged_after_ten_minutes(
    client: TestClient, owner_token: str, setup: dict[str, Any], app_settings: Settings
) -> None:
    created, params = _open(client, owner_token, {"trust_policy_id": setup["policy"]["id"]})
    _post(client, params, vp_token=_present(setup, params, ["family_name"]))
    assert client.get(f"/v1/oid4vp/requests/{created['id']}", headers=_auth(owner_token)).json()[
        "result"
    ]
    db = Database(app_settings)
    try:
        with db.session(bypass_rls=True) as s:
            counts = run_maintenance(s, now=datetime.now(UTC) + timedelta(minutes=11))
    finally:
        db.dispose()
    assert counts["oid4vp_results"] == 1
    status = client.get(f"/v1/oid4vp/requests/{created['id']}", headers=_auth(owner_token)).json()
    assert status["status"] == "completed" and status["result"] is None
