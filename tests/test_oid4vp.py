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

# Perfil de ADR-0014: solicitud por valor sin firma y respuesta en claro.
UNSIGNED: dict[str, Any] = {"client_id_scheme": "redirect_uri", "encrypt_response": False}


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
    created, params = _open(
        client, owner_token, UNSIGNED | {"trust_policy_id": setup["policy"]["id"]}
    )

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
        UNSIGNED
        | {
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
    created, params = _open(
        client, owner_token, UNSIGNED | {"trust_policy_id": setup["policy"]["id"]}
    )
    assert _post(client, params, error="access_denied").status_code == 200
    status = client.get(f"/v1/oid4vp/requests/{created['id']}", headers=_auth(owner_token)).json()
    assert (
        status["status"] == "failed"
        and status["error"] == "access_denied"
        and status["result"] is None
    )

    # KB-JWT con otro aud (p. ej. reutilizado de otra solicitud) → inválido.
    created, params = _open(
        client, owner_token, UNSIGNED | {"trust_policy_id": setup["policy"]["id"]}
    )
    r = _post(client, params, vp_token=_present(setup, params, ["family_name"], aud="https://otro"))
    assert r.status_code == 200
    result = client.get(f"/v1/oid4vp/requests/{created['id']}", headers=_auth(owner_token)).json()[
        "result"
    ]
    assert result["result"] != "valid"

    _, params = _open(client, owner_token, UNSIGNED | {"trust_policy_id": setup["policy"]["id"]})
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
        "/v1/oid4vp/requests",
        json=UNSIGNED | {"trust_policy_id": policy["id"]},
        headers=_auth(owner_token),
    )
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_dcql"
    r = client.post(
        "/v1/oid4vp/requests",
        json=UNSIGNED | {"trust_policy_id": policy["id"], "vct_values": [setup["vct"]]},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201


def test_result_is_purged_after_ten_minutes(
    client: TestClient, owner_token: str, setup: dict[str, Any], app_settings: Settings
) -> None:
    created, params = _open(
        client, owner_token, UNSIGNED | {"trust_policy_id": setup["policy"]["id"]}
    )
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


# ---------------------------------------------------------------------------
# Solicitudes firmadas (x509) y respuestas cifradas (direct_post.jwt), ADR-0015
# ---------------------------------------------------------------------------
def _fetch_signed_request(client: TestClient, link: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Lo que hace un wallet: sólo tiene client_id y request_uri; baja y verifica el JWT."""
    import base64
    import hashlib

    import jwt as pyjwt
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    q = {k: v[0] for k, v in parse_qs(urlparse(link).query).items()}
    assert set(q) == {"client_id", "request_uri"}
    r = client.get(urlparse(q["request_uri"]).path)
    assert r.status_code == 200 and r.headers["content-type"].startswith(
        "application/oauth-authz-req+jwt"
    )
    header = pyjwt.get_unverified_header(r.text)
    assert header["typ"] == "oauth-authz-req+jwt" and header["alg"] == "ES256"
    leaf_der = base64.b64decode(header["x5c"][0])
    leaf = x509.load_der_x509_certificate(leaf_der)
    # Verificación independiente (PyJWT) con la clave pública del certificado x5c.
    claims = pyjwt.decode(
        r.text,
        leaf.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        algorithms=["ES256"],
        audience="https://self-issued.me/v2",
    )
    assert claims["client_id"] == q["client_id"]
    if q["client_id"].startswith("x509_hash:"):
        digest = base64.urlsafe_b64encode(hashlib.sha256(leaf_der).digest()).rstrip(b"=").decode()
        assert q["client_id"] == f"x509_hash:{digest}"
    return q, claims


def _encrypted_answer(claims: dict[str, Any], ctx: dict[str, Any], disclose: list[str]) -> str:
    from aletheia.platform.jwe import encrypt_compact

    jwk = claims["client_metadata"]["jwks"]["keys"][0]
    assert jwk["use"] == "enc" and jwk["alg"] == "ECDH-ES"
    payload = peek(ctx["credential"].split("~")[0]).payload
    presentation = create_presentation(
        ctx["credential"],
        payload,
        disclose=disclose,
        holder_signer=ctx["holder"],
        aud=claims["client_id"],
        nonce=claims["nonce"],
        iat=int(time.time()),
    )
    body = {"vp_token": {"credential": [presentation]}, "state": claims["state"]}
    return encrypt_compact(json.dumps(body).encode(), jwk, enc="A256GCM", kid=jwk["kid"])


def test_signed_request_and_encrypted_response(
    client: TestClient, owner_token: str, setup: dict[str, Any]
) -> None:
    created, _ = _open(
        client, owner_token, {"trust_policy_id": setup["policy"]["id"]}
    )  # por defecto
    assert (
        created["client_id_scheme"] == "x509_hash" and created["response_mode"] == "direct_post.jwt"
    )
    q, claims = _fetch_signed_request(client, created["request_uri"])
    assert claims["response_mode"] == "direct_post.jwt"
    assert claims["client_metadata"]["encrypted_response_enc_values_supported"] == [
        "A128GCM",
        "A256GCM",
    ]
    assert claims["dcql_query"] == created["dcql_query"]
    status = client.get(f"/v1/oid4vp/requests/{created['id']}", headers=_auth(owner_token)).json()
    assert status["request_fetched"] is True and status["status"] == "pending"

    # Respuesta en claro a una sesión que exige cifrado → rechazada (sin rebaja de seguridad).
    plain = client.post("/oid4vp/response", data={"state": claims["state"], "vp_token": "{}"})
    assert plain.status_code == 400 and "encrypted" in plain.json()["error_description"]

    jwe = _encrypted_answer(claims, setup, ["family_name"])
    r = client.post(urlparse(claims["response_uri"]).path, data={"response": jwe})
    assert r.status_code == 200, r.text
    status = client.get(f"/v1/oid4vp/requests/{created['id']}", headers=_auth(owner_token)).json()
    assert status["status"] == "completed"
    assert status["result"]["result"] == "valid", status["result"]["checks"]
    assert status["result"]["disclosed_claims"]["family_name"] == "Pérez"
    assert status["result"]["response_mode"] == "direct_post.jwt"
    # Material de un solo uso eliminado: la solicitud ya no se sirve; replay rechazado.
    assert client.get(urlparse(q["request_uri"]).path).status_code == 404
    assert client.post("/oid4vp/response", data={"response": jwe}).status_code == 400


def test_encrypted_response_rejections(
    client: TestClient, owner_token: str, setup: dict[str, Any]
) -> None:
    from aletheia.platform.jwe import encrypt_compact

    created, _ = _open(client, owner_token, {"trust_policy_id": setup["policy"]["id"]})
    _, claims = _fetch_signed_request(client, created["request_uri"])
    jwk = claims["client_metadata"]["jwks"]["keys"][0]
    # state de otra sesión dentro del JWE → rechazado.
    wrong_state = encrypt_compact(
        json.dumps({"vp_token": {}, "state": "otro"}).encode(), jwk, kid=jwk["kid"]
    )
    assert client.post("/oid4vp/response", data={"response": wrong_state}).status_code == 400
    # JWE cifrado a otra clave con el kid correcto → no se puede descifrar.
    from cryptography.hazmat.primitives.asymmetric import ec

    from aletheia.vc.keys import public_jwk_from_key

    other = public_jwk_from_key(ec.generate_private_key(ec.SECP256R1()).public_key())
    bad = encrypt_compact(json.dumps({"state": claims["state"]}).encode(), other, kid=jwk["kid"])
    r = client.post("/oid4vp/response", data={"response": bad})
    assert r.status_code == 400 and "decrypted" in r.json()["error_description"]
    assert client.post("/oid4vp/response", data={"response": "no.es.un.jwe"}).status_code == 400
    # Rechazo del titular, cifrado.
    declined = encrypt_compact(
        json.dumps({"error": "access_denied", "state": claims["state"]}).encode(),
        jwk,
        kid=jwk["kid"],
    )
    assert client.post("/oid4vp/response", data={"response": declined}).status_code == 200
    status = client.get(f"/v1/oid4vp/requests/{created['id']}", headers=_auth(owner_token)).json()
    assert status["status"] == "failed" and status["error"] == "access_denied"


def test_x509_san_dns_needs_a_dns_host(
    client: TestClient, owner_token: str, setup: dict[str, Any], app_settings: Settings
) -> None:
    # Base de pruebas http://localhost:8000: host DNS "localhost", en el SAN del cert de desarrollo.
    created, _ = _open(
        client,
        owner_token,
        {
            "trust_policy_id": setup["policy"]["id"],
            "client_id_scheme": "x509_san_dns",
            "encrypt_response": False,
        },
    )
    q, claims = _fetch_signed_request(client, created["request_uri"])
    assert q["client_id"] == "x509_san_dns:localhost" and claims["response_mode"] == "direct_post"
    r = client.post(
        urlparse(claims["response_uri"]).path,
        data={"state": claims["state"], "vp_token": _present(setup, claims, ["family_name"])},
    )
    assert r.status_code == 200
    result = client.get(f"/v1/oid4vp/requests/{created['id']}", headers=_auth(owner_token)).json()[
        "result"
    ]
    assert result["result"] == "valid", result["checks"]


def test_signed_schemes_unavailable_without_certificate(
    client: TestClient, owner_token: str, setup: dict[str, Any]
) -> None:
    client.app.state.verifier_identity = None  # type: ignore[attr-defined]  # como en producción sin certificado
    r = client.post(
        "/v1/oid4vp/requests",
        json={"trust_policy_id": setup["policy"]["id"]},
        headers=_auth(owner_token),
    )
    assert r.status_code == 422 and r.json()["error"]["code"] == "verifier_identity_unavailable"
    r = client.post(
        "/v1/oid4vp/requests",
        json=UNSIGNED | {"trust_policy_id": setup["policy"]["id"]},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201
