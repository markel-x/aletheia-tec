"""Emisión de extremo a extremo: plantilla → oferta → OID4VCI → credencial →
verificación con el núcleo → revocación → lista de estado (con PostgreSQL)."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient
from pydantic import HttpUrl

from aletheia.platform.config import Settings
from aletheia.status import service as status_service
from aletheia.vc import OID4VCI_PROOF_TYP
from aletheia.vc.jws import peek, sign_compact
from aletheia.vc.keys import public_key_from_jwk
from aletheia.vc.sdjwt import create_presentation
from aletheia.vc.signing import LocalDevSigner
from aletheia.vc.verifier import (
    FetchedStatusList,
    KeyNotFound,
    KeyState,
    PresentationContext,
    ResolvedKey,
    TrustPolicy,
    verify_presentation,
)
from tests.fixtures_org import _auth
from tests.test_schema import COURSE_SCHEMA

pytestmark = pytest.mark.db

CLAIMS = {
    "course": {"title": "Curso de prueba", "hours": 40, "grade": "A"},
    "given_name": "Ana",
    "family_name": "Pérez",
    "completion_date": "2026-09-30",
}
PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"


@pytest.fixture(autouse=True)
def _clear_status_cache() -> None:
    status_service.clear_cache()


@pytest.fixture
def app_settings(db_settings: Settings) -> Settings:
    # El perfil exige ``iss`` y URIs de estado https; el TestClient acepta cualquier host.
    return db_settings.model_copy(update={"public_base_url": HttpUrl("https://aletheia.test")})


@pytest.fixture
def template(client: TestClient, owner_token: str) -> dict[str, Any]:
    r = client.post(
        "/v1/templates",
        json={"slug": "course-completion", "name": "Certificado"},
        headers=_auth(owner_token),
    )
    assert r.status_code == 201, r.text
    tpl = r.json()
    r = client.post(
        f"/v1/templates/{tpl['id']}/versions",
        json={
            "claims_schema": COURSE_SCHEMA,
            "selective_disclosure": [
                "given_name",
                "family_name",
                "completion_date",
                "course.grade",
                "student_id",
            ],
            "validity_days": 365,
            "display": {"display": [{"name": "Certificado de curso", "locale": "es"}]},
        },
        headers=_auth(owner_token),
    )
    assert r.status_code == 201, r.text
    ver = r.json()
    assert ver["state"] == "draft"
    r = client.post(
        f"/v1/templates/{tpl['id']}/versions/{ver['id']}/publish", headers=_auth(owner_token)
    )
    assert r.status_code == 200 and r.json()["state"] == "published"
    return tpl


class HostedIssuer:
    """Resolvedor y fetcher del verificador del núcleo contra la API real."""

    def __init__(self, client: TestClient, issuer: str) -> None:
        self.client = client
        self.issuer = issuer

    def resolve(self, issuer: str, kid: str) -> ResolvedKey:
        if issuer != self.issuer:
            raise KeyNotFound(kid)
        org = issuer.rsplit("/", 1)[-1]
        jwks = self.client.get(f"/.well-known/jwt-vc-issuer/issuers/{org}").json()["jwks"]["keys"]
        for key in jwks:
            if key["kid"] == kid:
                return ResolvedKey(key, KeyState.ACTIVE)
        raise KeyNotFound(kid)

    def fetch(self, uri: str) -> FetchedStatusList:
        path = urlparse(uri).path
        r = self.client.get(path)
        assert r.status_code == 200, r.text
        assert r.headers["content-type"].startswith("application/statuslist+jwt")
        return FetchedStatusList(token=r.text, fetched_at=int(time.time()))


def _proof(holder: LocalDevSigner, aud: str, nonce: str, iat: int | None = None) -> str:
    header = {"alg": "ES256", "typ": OID4VCI_PROOF_TYP, "jwk": holder.public_jwk}
    return sign_compact(
        header, {"aud": aud, "iat": iat or int(time.time()), "nonce": nonce}, holder
    )


def _code(client: TestClient, offer: dict[str, Any]) -> str:
    doc = client.get(urlparse(offer["credential_offer_uri"]).path).json()
    return str(doc["grants"][PRE_AUTH_GRANT]["pre-authorized_code"])


def _redeem(
    client: TestClient, offer: dict[str, Any], tx_code: str, code: str | None = None
) -> Any:
    code = code or _code(client, offer)
    return client.post(
        "/oid4vci/token",
        data={"grant_type": PRE_AUTH_GRANT, "pre-authorized_code": code, "tx_code": tx_code},
    )


def test_template_validation(
    client: TestClient, owner_token: str, template: dict[str, Any]
) -> None:
    assert (
        client.post(
            "/v1/templates",
            json={"slug": "course-completion", "name": "Otro"},
            headers=_auth(owner_token),
        ).status_code
        == 409
    )
    r = client.post(
        f"/v1/templates/{template['id']}/versions",
        json={
            "claims_schema": {"type": "object", "properties": {"x": {"type": "array"}}},
            "validity_days": 10,
        },
        headers=_auth(owner_token),
    )
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_schema"
    r = client.post(
        f"/v1/templates/{template['id']}/versions",
        json={
            "claims_schema": COURSE_SCHEMA,
            "selective_disclosure": ["nope"],
            "validity_days": 10,
        },
        headers=_auth(owner_token),
    )
    assert r.status_code == 422 and r.json()["error"]["details"] == ["nope"]
    listed = client.get("/v1/templates", headers=_auth(owner_token)).json()
    assert listed[0]["vct"].endswith("/types/course-completion")


def test_full_issuance_flow(
    client: TestClient,
    owner_token: str,
    org: dict[str, Any],
    template: dict[str, Any],
    app_settings: Settings,
) -> None:
    base = app_settings.public_base
    issuer = f"{base}/issuers/{org['public_id']}"

    # Metadatos OID4VCI.
    meta = client.get(f"/.well-known/openid-credential-issuer/issuers/{org['public_id']}").json()
    assert meta["credential_issuer"] == issuer
    cfg = meta["credential_configurations_supported"]["course-completion"]
    assert cfg["format"] == "dc+sd-jwt" and cfg["vct"].endswith("/types/course-completion")
    auth_meta = client.get(
        f"/.well-known/oauth-authorization-server/issuers/{org['public_id']}"
    ).json()
    assert auth_meta["token_endpoint"] == f"{base}/oid4vci/token"

    # Oferta (con idempotencia).
    body = {"template": "course-completion", "claims": CLAIMS, "holder_reference": "student-42"}
    r = client.post(
        "/v1/credentials", json=body, headers={**_auth(owner_token), "Idempotency-Key": "k1"}
    )
    assert r.status_code == 201, r.text
    offer = r.json()
    assert offer["state"] == "offered" and len(offer["tx_code"]) == 6 and offer["tx_code"].isdigit()
    assert offer["offer_uri"].startswith("openid-credential-offer://?credential_offer_uri=")
    assert offer["qr_svg"].startswith("data:image/svg+xml")
    assert "Ana" not in r.text  # los claims nunca vuelven en la respuesta
    replay = client.post(
        "/v1/credentials", json=body, headers={**_auth(owner_token), "Idempotency-Key": "k1"}
    )
    assert (
        replay.status_code == 200
        and replay.json()["id"] == offer["id"]
        and replay.json()["tx_code"] == ""
    )
    other = client.post(
        "/v1/credentials",
        json={**body, "holder_reference": "x"},
        headers={**_auth(owner_token), "Idempotency-Key": "k1"},
    )
    assert other.status_code == 409 and other.json()["error"]["code"] == "idempotency_key_reuse"

    # La oferta se sirve al wallet; el enlace lleva el offer_id, no datos personales.
    offer_path = urlparse(offer["credential_offer_uri"]).path
    doc = client.get(offer_path).json()
    assert doc["credential_issuer"] == issuer and doc["credential_configuration_ids"] == [
        "course-completion"
    ]
    assert (
        "Ana" not in offer["credential_offer_uri"]
        and "student-42" not in offer["credential_offer_uri"]
    )
    assert parse_qs(urlparse(offer["offer_uri"]).query)["credential_offer_uri"] == [
        offer["credential_offer_uri"]
    ]

    # tx_code erróneo → intento contado; el correcto canjea; el segundo canje falla.
    bad = _redeem(client, offer, "000000")
    assert bad.status_code == 400 and bad.json()["error"] == "invalid_grant"
    assert (
        client.get(f"/v1/credentials/{offer['id']}", headers=_auth(owner_token)).json()[
            "tx_code_attempts"
        ]
        == 1
    )
    tok = _redeem(client, offer, offer["tx_code"])
    assert tok.status_code == 200, tok.text
    access_token = tok.json()["access_token"]
    assert _redeem(client, offer, offer["tx_code"]).status_code == 400

    # Proof con nonce del Nonce Endpoint; nonce reutilizado o aud incorrecto → error.
    holder = LocalDevSigner.generate(environment="test")
    nonce = client.post("/oid4vci/nonce").json()["c_nonce"]
    wrong_aud = client.post(
        "/oid4vci/credential",
        json={
            "credential_configuration_id": "course-completion",
            "proofs": {"jwt": [_proof(holder, "https://otro", nonce)]},
        },
        headers=_auth(access_token),
    )
    assert wrong_aud.status_code == 400 and wrong_aud.json()["error"] == "invalid_proof"
    r = client.post(
        "/oid4vci/credential",
        json={
            "credential_configuration_id": "course-completion",
            "proofs": {"jwt": [_proof(holder, issuer, nonce)]},
        },
        headers=_auth(access_token),
    )
    assert r.status_code == 200, r.text
    credential = r.json()["credentials"][0]["credential"]
    reuse = client.post(
        "/oid4vci/credential",
        json={
            "credential_configuration_id": "course-completion",
            "proofs": {"jwt": [_proof(holder, issuer, nonce)]},
        },
        headers=_auth(access_token),
    )
    assert reuse.status_code == 401  # token de acceso consumido

    # Estado: emitida, claims pendientes borrados, sin atributos personales en el registro.
    rec = client.get(f"/v1/credentials/{offer['id']}", headers=_auth(owner_token)).json()
    assert rec["state"] == "issued" and rec["issued_at"] and rec["expires_at"]
    assert "Ana" not in str(rec)

    # La credencial: firmada por la clave publicada, con cnf, status y disclosures.
    issuer_jwt = credential.split("~")[0]
    decoded = peek(issuer_jwt)
    assert decoded.header["kid"] == org["kid"] and decoded.header["typ"] == "dc+sd-jwt"
    payload = decoded.payload
    assert payload["iss"] == issuer and payload["vct"] == cfg["vct"]
    assert payload["cnf"]["jwk"]["x"] == holder.public_jwk["x"]
    assert payload["course"]["title"] == "Curso de prueba" and "grade" not in payload["course"]
    assert "given_name" not in payload and "_sd" in payload
    jwks = client.get(f"/.well-known/jwt-vc-issuer/issuers/{org['public_id']}").json()["jwks"][
        "keys"
    ]
    pyjwt.decode(
        issuer_jwt,
        public_key_from_jwk(jwks[0]),
        algorithms=["ES256"],
        options={"verify_aud": False},
    )

    # Verificación con el núcleo contra la API real (JWKS + Status List).
    host = HostedIssuer(client, issuer)
    policy = TrustPolicy(
        trusted_issuers=frozenset({issuer}),
        accepted_vcts=frozenset({cfg["vct"]}),
        required_claims=frozenset({"family_name"}),
    )
    used: set[str] = set()

    def consume(n: str) -> bool:
        if n in used:
            return False
        used.add(n)
        return True

    def verify() -> Any:
        n = "nonce-" + str(len(used))
        presentation = create_presentation(
            credential,
            payload,
            disclose=["family_name"],
            holder_signer=holder,
            aud="https://verifier",
            nonce=n,
            iat=int(time.time()),
        )
        return verify_presentation(
            presentation,
            policy=policy,
            key_resolver=host,
            status_fetcher=host,
            now=int(time.time()),
            context=PresentationContext("https://verifier", n, consume),
        )

    report = verify()
    assert report.result.value == "valid", [(c.name, c.code) for c in report.checks]
    assert (
        report.disclosed_claims["family_name"] == "Pérez"
        and "given_name" not in report.disclosed_claims
    )

    # Revocación: idempotente; la lista de estado cambia de versión y el núcleo lo ve.
    r = client.post(
        f"/v1/credentials/{offer['id']}/revoke",
        json={"reason": "holder_request"},
        headers=_auth(owner_token),
    )
    assert r.status_code == 200 and r.json()["state"] == "revoked"
    revoked_at = r.json()["revoked_at"]
    again = client.post(
        f"/v1/credentials/{offer['id']}/revoke",
        json={"reason": "other"},
        headers=_auth(owner_token),
    )
    assert (
        again.json()["revoked_at"] == revoked_at
        and again.json()["revocation_reason_code"] == "holder_request"
    )
    status_service.clear_cache()
    report = verify()
    assert report.result.value == "invalid" and report.reason == "credential_revoked"

    # Auditoría y consumo.
    actions = [
        e["action"] for e in client.get("/v1/audit-events", headers=_auth(owner_token)).json()
    ]
    for expected in (
        "credential.offered",
        "offer.code_redeemed",
        "credential.issued",
        "credential.revoked",
    ):
        assert expected in actions
    usage = client.get("/v1/usage", headers=_auth(owner_token)).json()["months"][0]["totals"]
    assert (
        usage["credential.offered"] == 1
        and usage["credential.issued"] == 1
        and usage["status_list.served"] >= 1
    )


def test_offer_lifecycle_reset_cancel_and_lockout(
    client: TestClient, owner_token: str, template: dict[str, Any], app_settings: Settings
) -> None:
    body = {"template": "course-completion", "claims": CLAIMS}
    offer = client.post("/v1/credentials", json=body, headers=_auth(owner_token)).json()
    for _ in range(app_settings.tx_code_max_attempts):
        assert _redeem(client, offer, "999999").status_code == 400
    # Bloqueada: ni siquiera el tx_code correcto sirve.
    assert _redeem(client, offer, offer["tx_code"]).status_code == 400
    # Reset: nuevo enlace y nuevo tx_code; el viejo deja de existir.
    r = client.post(f"/v1/credentials/{offer['id']}/offer:reset", headers=_auth(owner_token))
    assert r.status_code == 200, r.text
    fresh = r.json()
    assert (
        fresh["credential_offer_uri"] != offer["credential_offer_uri"]
        and fresh["tx_code_attempts"] == 0
    )
    assert client.get(urlparse(offer["credential_offer_uri"]).path).status_code == 404
    assert _redeem(client, fresh, fresh["tx_code"]).status_code == 200

    # Cancelar una oferta pendiente: revocación sobre "offered" borra claims y cierra el canje.
    second = client.post("/v1/credentials", json=body, headers=_auth(owner_token)).json()
    second_code = _code(client, second)
    r = client.post(
        f"/v1/credentials/{second['id']}/revoke",
        json={"reason": "issued_in_error"},
        headers=_auth(owner_token),
    )
    assert r.status_code == 200 and r.json()["state"] == "revoked"
    assert client.get(urlparse(second["credential_offer_uri"]).path).status_code == 404
    assert _redeem(client, second, second["tx_code"], code=second_code).status_code == 400
    assert (
        client.post(
            f"/v1/credentials/{second['id']}/offer:reset", headers=_auth(owner_token)
        ).status_code
        == 409
    )

    listed = client.get("/v1/credentials?state=revoked", headers=_auth(owner_token)).json()
    assert [c["id"] for c in listed] == [second["id"]]


def test_issuer_role_and_api_key_can_issue_but_not_manage_templates(
    client: TestClient, owner_token: str, template: dict[str, Any]
) -> None:
    key = client.post(
        "/v1/api-clients",
        json={"name": "SIS", "permissions": ["credentials:issue", "credentials:read"]},
        headers=_auth(owner_token),
    ).json()["key"]
    body = {"template": "course-completion", "claims": CLAIMS}
    assert client.post("/v1/credentials", json=body, headers=_auth(key)).status_code == 201
    assert client.get("/v1/templates", headers=_auth(key)).status_code == 403
    assert (
        client.post(
            "/v1/templates", json={"slug": "x", "name": "x"}, headers=_auth(key)
        ).status_code
        == 403
    )
    bad = client.post(
        "/v1/credentials", json={**body, "claims": {"given_name": "solo"}}, headers=_auth(key)
    )
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "invalid_claims"
    assert "solo" not in bad.text
