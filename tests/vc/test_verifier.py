"""Motor de verificación: criterios de aceptación 2, 3, 4, 5, 8, 9 y 10 a nivel
del núcleo, y vinculación al titular / audiencia / nonce / replay."""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from aletheia.vc.encoding import b64url_decode, b64url_encode, json_compact
from aletheia.vc.jws import peek, sign_compact
from aletheia.vc.sdjwt import create_disclosure, create_presentation
from aletheia.vc.signing import LocalDevSigner
from aletheia.vc.verifier import (
    CHECK_ORDER,
    KeyState,
    Outcome,
    PresentationContext,
    Result,
    VerificationReport,
    verify_presentation,
)

from .conftest import ISS, NOW, Env

AUD = "https://verificador.test"
NONCE = "n-0S6_WzA2Mj"


class NonceStore:
    """Consumo atómico simulado (en la app: UPDATE … WHERE consumed_at IS NULL)."""

    def __init__(self) -> None:
        self.used: set[str] = set()

    def __call__(self, nonce: str) -> bool:
        if nonce in self.used:
            return False
        self.used.add(nonce)
        return True


def ctx(store: NonceStore | None = None) -> PresentationContext:
    return PresentationContext(AUD, NONCE, store if store is not None else NonceStore())


def present(
    env: Env,
    serialized: str,
    *,
    disclose: tuple[str, ...] = ("given_name", "family_name"),
    holder: LocalDevSigner | None = None,
    kb: bool = True,
    aud: str = AUD,
    nonce: str = NONCE,
    iat: int = NOW,
) -> str:
    payload = peek(serialized.split("~")[0]).payload
    return create_presentation(
        serialized,
        payload,
        disclose=disclose,
        holder_signer=(holder or env.holder_signer) if kb else None,
        aud=aud,
        nonce=nonce,
        iat=iat,
    )


def verify(
    env: Env,
    presentation: str,
    *,
    context: PresentationContext | None = None,
    now: int = NOW,
    **policy_overrides: Any,
) -> VerificationReport:
    policy = dataclasses.replace(env.policy, **policy_overrides)
    return verify_presentation(
        presentation,
        policy=policy,
        key_resolver=env.keys,
        status_fetcher=env.status,
        now=now,
        context=context if context is not None else ctx(),
    )


def outcomes(report: VerificationReport) -> dict[str, str]:
    return {c.name: f"{c.outcome.value}:{c.code}" for c in report.checks}


# --- flujo válido -----------------------------------------------------------------


def test_valid_presentation_with_holder_binding(env: Env) -> None:
    report = verify(env, present(env, env.issue().serialized))
    assert report.result is Result.VALID, outcomes(report)
    assert [c.name for c in report.checks] == list(CHECK_ORDER)
    assert all(c.outcome is Outcome.PASS for c in report.checks)
    assert report.holder_binding_verified
    assert report.disclosed_claims is not None
    assert report.disclosed_claims["family_name"] == "Lovelace"
    assert "grade" not in report.disclosed_claims["course"]  # no divulgado
    assert any("identidad" in n for n in report.notes)


def test_credential_only_without_request_when_policy_allows(env: Env) -> None:
    report = verify_presentation(
        present(env, env.issue().serialized, kb=False),
        policy=dataclasses.replace(env.policy, require_holder_binding=False),
        key_resolver=env.keys,
        status_fetcher=env.status,
        now=NOW,
        context=None,
    )
    assert report.result is Result.VALID
    assert report.check("holder_binding").outcome is Outcome.SKIPPED
    assert report.check("presentation_binding").code == "no_request_context"


# --- criterio 3: modificación ---------------------------------------------------


def _tamper_payload(serialized: str, change: dict[str, Any]) -> str:
    jwt_part, rest = serialized.split("~", 1)
    header, _payload, sig = jwt_part.split(".")
    body = peek(jwt_part).payload | change
    return f"{header}.{b64url_encode(json_compact(body))}.{sig}~{rest}"


def test_modified_payload_invalidates_signature(env: Env) -> None:
    presentation = present(env, env.issue().serialized)
    course = peek(presentation.split("~")[0]).payload["course"]
    report = verify(env, _tamper_payload(presentation, {"course": course | {"hours": 900}}))
    assert report.result is Result.INVALID
    assert report.check("signature").code == "signature_invalid"
    assert report.disclosed_claims is None


def test_modified_disclosure_is_detected(env: Env) -> None:
    issued = env.issue()
    fake = create_disclosure("family_name", "Impostor").encoded
    tampered = issued.serialized.replace(
        next(d.encoded for d in issued.disclosures if d.name == "family_name"), fake
    )
    report = verify_presentation(
        tampered,
        policy=dataclasses.replace(env.policy, require_holder_binding=False),
        key_resolver=env.keys,
        status_fetcher=env.status,
        now=NOW,
        context=None,
    )
    assert report.result is Result.INVALID
    assert report.check("disclosures").code == "unreferenced_disclosure"


def test_signature_by_unregistered_key(env: Env) -> None:
    rogue = LocalDevSigner.generate(environment="test")
    report = verify(env, present(env, env.issue(signer=rogue).serialized))
    assert report.check("key_resolution").code == "issuer_key_not_found"
    assert report.result is Result.INVALID


# --- algoritmos -------------------------------------------------------------------


@pytest.mark.parametrize("alg", ["none", "HS256", "RS256", "ES384"])
def test_disallowed_algorithms(env: Env, alg: str) -> None:
    serialized = env.issue().serialized
    jwt_part, rest = serialized.split("~", 1)
    header = peek(jwt_part).header | {"alg": alg}
    _, payload, sig = jwt_part.split(".")
    forged = f"{b64url_encode(json_compact(header))}.{payload}.{sig}~{rest}"
    report = verify(env, present(env, forged))
    assert report.check("algorithm").code == "algorithm_not_allowed"
    assert report.result is Result.INVALID
    assert env.keys.calls == []  # no se resolvió ninguna clave


# --- criterio 4: vigencia ---------------------------------------------------------


def test_expired_credential(env: Env) -> None:
    report = verify(env, present(env, env.issue(exp=NOW - 120).serialized))
    assert report.result is Result.INVALID
    assert report.check("validity_period").code == "credential_expired"


def test_expiry_within_clock_skew_is_tolerated(env: Env) -> None:
    report = verify(env, present(env, env.issue(exp=NOW - 30).serialized))
    assert report.result is Result.VALID


def test_not_yet_valid(env: Env) -> None:
    report = verify(env, present(env, env.issue(extra={"nbf": NOW + 3600}).serialized))
    assert report.check("validity_period").code == "credential_not_yet_valid"


# --- criterio 5: revocación y actualidad del estado --------------------------


def test_revoked_credential(env: Env) -> None:
    serialized = env.issue(idx=42).serialized
    assert verify(env, present(env, serialized)).result is Result.VALID
    env.status.status_list.set(42, 1)
    report = verify(env, present(env, serialized))
    assert report.result is Result.INVALID
    assert report.check("status").code == "credential_revoked"


def test_stale_status_list_is_indeterminate(env: Env) -> None:
    env.status.signed_at = NOW - 3600
    report = verify(env, present(env, env.issue().serialized))
    assert report.result is Result.INDETERMINATE
    assert report.check("status").code == "status_stale"


def test_expired_status_list_is_indeterminate(env: Env) -> None:
    env.status.signed_at = NOW - 90_000
    report = verify(env, present(env, env.issue().serialized), max_status_age_seconds=10**6)
    assert report.check("status").code == "status_list_expired"
    assert report.result is Result.INDETERMINATE


# --- criterio 9: dependencias caídas ---------------------------------------------


def test_status_service_down_is_not_success(env: Env) -> None:
    env.status.unavailable = True
    report = verify(env, present(env, env.issue().serialized))
    assert report.result is Result.INDETERMINATE
    assert report.check("status").code == "status_unavailable"
    assert report.disclosed_claims is None


def test_key_resolution_down_is_not_success(env: Env) -> None:
    env.keys.unavailable = True
    report = verify(env, present(env, env.issue().serialized))
    assert report.result is Result.INDETERMINATE
    assert report.check("key_resolution").code == "key_resolution_unavailable"
    assert report.check("signature").outcome is Outcome.SKIPPED


def test_indeterminate_status_does_not_mask_later_failure(env: Env) -> None:
    env.status.unavailable = True
    report = verify(env, present(env, env.issue().serialized, aud="https://otro"))
    assert report.result is Result.INVALID
    assert report.check("presentation_binding").code == "audience_mismatch"


def test_tampered_status_list_is_indeterminate(env: Env) -> None:
    token = env.status.fetch(env.status.uri).token
    h, _p, s = token.split(".")
    body = peek(token).payload | {"status_list": {"bits": 1, "lst": "eNpjYAAAAAIAAQ"}}
    env.status.override_token = f"{h}.{b64url_encode(json_compact(body))}.{s}"
    report = verify(env, present(env, env.issue().serialized))
    assert report.check("status").code == "status_list_invalid"
    assert report.result is Result.INDETERMINATE


def test_status_list_signed_by_other_issuer_is_rejected(env: Env) -> None:
    env.status.issuer = "https://evil.test/issuers/x"
    report = verify(env, present(env, env.issue().serialized))
    assert report.check("status").code == "status_list_invalid"


# --- criterio 8: emisor desconocido ----------------------------------------------


def test_unknown_issuer_is_not_trusted_and_not_resolved(env: Env) -> None:
    other = "https://unknown.test/issuers/org_x"
    signer = LocalDevSigner.generate(environment="test")
    env.keys.add(other, signer)  # aun si la clave fuera resoluble
    report = verify(env, present(env, env.issue(signer=signer, iss=other).serialized))
    assert report.result is Result.INVALID
    assert report.check("issuer_trust").code == "issuer_not_trusted"
    assert env.keys.calls == []


# --- criterio 10: rotación y compromiso --------------------------------------


def test_retired_key_still_verifies_old_credentials(env: Env) -> None:
    serialized = env.issue().serialized
    env.keys.set_state(ISS, env.issuer_signer.kid, KeyState.RETIRED)
    new_signer = LocalDevSigner.generate(environment="test")
    env.keys.add(ISS, new_signer)
    env.status.signer = new_signer  # la lista ya se firma con la clave nueva
    report = verify(env, present(env, serialized))
    assert report.result is Result.VALID, outcomes(report)
    assert report.check("key_resolution").code == "key_retired"


def test_compromised_key_invalidates_credentials(env: Env) -> None:
    serialized = env.issue().serialized
    env.keys.set_state(ISS, env.issuer_signer.kid, KeyState.COMPROMISED)
    report = verify(env, present(env, serialized))
    assert report.result is Result.INVALID
    assert report.check("key_resolution").code == "issuer_key_compromised"


# --- vinculación con el titular, audiencia, nonce, replay --------------------------


def test_missing_key_binding_when_required(env: Env) -> None:
    report = verify(env, present(env, env.issue().serialized, kb=False))
    assert report.check("holder_binding").code == "holder_binding_missing"


def test_kb_signed_by_someone_else(env: Env) -> None:
    thief = LocalDevSigner.generate(environment="test")
    report = verify(env, present(env, env.issue().serialized, holder=thief))
    assert report.check("holder_binding").code == "holder_binding_invalid"
    assert report.result is Result.INVALID


def test_disclosure_added_after_kb_breaks_sd_hash(env: Env) -> None:
    issued = env.issue()
    presentation = present(env, issued.serialized, disclose=("family_name",))
    base, kb = presentation.rsplit("~", 1)
    extra = next(d.encoded for d in issued.disclosures if d.name == "given_name")
    report = verify(env, f"{base}~{extra}~{kb}")
    assert report.check("holder_binding").code == "kb_sd_hash_mismatch"


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"aud": "https://otro.test"}, "audience_mismatch"),
        ({"nonce": "otro-nonce"}, "nonce_mismatch"),
    ],
)
def test_request_binding(env: Env, kwargs: dict[str, str], code: str) -> None:
    report = verify(env, present(env, env.issue().serialized, **kwargs))
    assert report.check("presentation_binding").code == code
    assert report.result is Result.INVALID


def test_replayed_presentation(env: Env) -> None:
    store = NonceStore()
    presentation = present(env, env.issue().serialized)
    assert verify(env, presentation, context=ctx(store)).result is Result.VALID
    report = verify(env, presentation, context=ctx(store))
    assert report.check("presentation_binding").code == "presentation_replayed"
    assert report.result is Result.INVALID


def test_invalid_presentation_does_not_burn_nonce(env: Env) -> None:
    store = NonceStore()
    thief = LocalDevSigner.generate(environment="test")
    bad = verify(env, present(env, env.issue().serialized, holder=thief), context=ctx(store))
    assert bad.result is Result.INVALID
    assert store.used == set()
    good = verify(env, present(env, env.issue().serialized), context=ctx(store))
    assert good.result is Result.VALID


def test_kb_without_request_context_is_not_valid(env: Env) -> None:
    """RFC 9901 §7.3: sin aud/nonce esperados, un KB-JWT podría ser un replay."""
    report = verify_presentation(
        present(env, env.issue().serialized),
        policy=env.policy,
        key_resolver=env.keys,
        status_fetcher=env.status,
        now=NOW,
        context=None,
    )
    assert report.result is Result.INDETERMINATE
    assert report.check("presentation_binding").code == "request_context_missing"


def test_old_kb_jwt_is_rejected(env: Env) -> None:
    report = verify(env, present(env, env.issue().serialized, iat=NOW - 3600))
    assert report.check("holder_binding").code == "kb_expired"


# --- política -----------------------------------------------------------------------


def test_policy_vct_not_accepted(env: Env) -> None:
    report = verify(env, present(env, env.issue().serialized), accepted_vcts=frozenset({"x"}))
    assert report.check("policy").code == "vct_not_accepted"


def test_policy_required_claim_not_disclosed(env: Env) -> None:
    report = verify(
        env, present(env, env.issue().serialized), required_claims=frozenset({"course.grade"})
    )
    assert report.check("policy").code == "required_claim_missing"
    ok = verify(
        env,
        present(env, env.issue().serialized, disclose=("course.grade",)),
        required_claims=frozenset({"course.grade", "course.title"}),
    )
    assert ok.result is Result.VALID


def test_missing_status_when_required(env: Env) -> None:
    issued = env.issue()
    payload = peek(issued.issuer_jwt).payload
    payload.pop("status")
    from aletheia.vc.sdjwt import issue_sd_jwt_vc

    plain = {k: v for k, v in payload.items() if not k.startswith("_sd")}
    no_status = issue_sd_jwt_vc(plain, selectively_disclosable=[], signer=env.issuer_signer)
    report = verify(env, present(env, no_status.serialized, disclose=()))
    assert report.check("status").code == "status_missing"


# --- formato --------------------------------------------------------------------------


@pytest.mark.parametrize("garbage", ["", "abc~", "a.b.c~", "e30.e30.e30~"])
def test_malformed_input(env: Env, garbage: str) -> None:
    report = verify(env, garbage)
    assert report.result is Result.INVALID
    assert report.check("format").outcome is Outcome.FAIL


def test_legacy_typ_is_rejected(env: Env) -> None:
    serialized = env.issue().serialized
    jwt_part, rest = serialized.split("~", 1)
    header = peek(jwt_part).header | {"typ": "vc+sd-jwt"}
    _, payload, sig = jwt_part.split(".")
    forged = f"{b64url_encode(json_compact(header))}.{payload}.{sig}~{rest}"
    assert verify(env, forged).check("format").code == "unsupported_typ"


def test_report_never_contains_raw_presentation(env: Env) -> None:
    presentation = present(env, env.issue().serialized)
    report = verify(env, presentation)
    serial = repr([c.as_dict() for c in report.checks])
    assert presentation.split("~")[0] not in serial
    assert b64url_decode(presentation.split("~")[1])  # sanity: hay disclosures


# --- robustez (revisión independiente del incremento 1) ---------------------------


def test_deeply_nested_disclosure_does_not_crash(env: Env) -> None:
    base = env.issue().serialized.split("~")[0]
    hostile = b64url_encode(("[" * 40_000 + "]" * 40_000).encode())
    report = verify(env, f"{base}~{hostile}~", context=None, require_holder_binding=False)
    assert report.result is Result.INVALID


def test_deeply_nested_jwt_payload_does_not_crash(env: Env) -> None:
    hostile = b64url_encode(("[" * 30_000 + "]" * 30_000).encode())
    report = verify(env, f"e30.{hostile}.e30~")
    assert report.check("format").outcome is Outcome.FAIL


def test_missing_iat_is_accepted_for_external_issuers(env: Env) -> None:
    issued = env.issue()
    payload = {k: v for k, v in peek(issued.issuer_jwt).payload.items() if k != "iat"}
    jwt_part = sign_compact(
        {"alg": "ES256", "typ": "dc+sd-jwt", "kid": env.issuer_signer.kid},
        payload,
        env.issuer_signer,
    )
    serialized = jwt_part + "~" + issued.serialized.split("~", 1)[1]
    report = verify(env, present(env, serialized))
    assert report.result is Result.VALID, outcomes(report)


def test_status_list_signed_in_future_is_indeterminate(env: Env) -> None:
    env.status.signed_at = NOW + 3600
    report = verify(env, present(env, env.issue().serialized))
    assert report.check("status").code == "status_list_invalid"
    assert report.result is Result.INDETERMINATE


def test_dev_http_origin_is_scoped_to_exact_origin() -> None:
    from aletheia.vc.status_list import is_https_or_dev

    assert is_https_or_dev("https://any.example/x", None)
    assert not is_https_or_dev("http://127.0.0.1:8008/issuers/org_x", None)
    assert is_https_or_dev("http://127.0.0.1:8008/issuers/org_x", "http://127.0.0.1:8008")
    # Otro puerto, otro host o un prefijo engañoso no se aceptan.
    assert not is_https_or_dev("http://127.0.0.1:8009/issuers/org_x", "http://127.0.0.1:8008")
    assert not is_https_or_dev("http://127.0.0.1:8008.evil.example/x", "http://127.0.0.1:8008")
    assert not is_https_or_dev("http://evil.example/x", "http://127.0.0.1:8008")
    # Un origen https configurado no habilita http.
    assert not is_https_or_dev("http://a.example/x", "https://a.example")
