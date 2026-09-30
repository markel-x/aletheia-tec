"""SD-JWT: emisión, reconstrucción y selección de disclosures."""

from __future__ import annotations

import pytest

from aletheia.vc.encoding import b64url_decode
from aletheia.vc.jws import peek
from aletheia.vc.sdjwt import (
    SdJwtError,
    create_disclosure,
    create_presentation,
    issue_sd_jwt_vc,
    parse,
    reconstruct,
)
from aletheia.vc.signing import LocalDevSigner

from .conftest import ISS, NOW, VCT, Env


def test_issue_hides_selective_claims_and_keeps_mandatory_ones(env: Env) -> None:
    issued = env.issue()
    decoded = peek(issued.issuer_jwt)
    assert decoded.header == {"alg": "ES256", "typ": "dc+sd-jwt", "kid": env.issuer_signer.kid}
    payload = decoded.payload
    for hidden in ("given_name", "family_name", "completion_date"):
        assert hidden not in payload
    assert "grade" not in payload["course"] and payload["course"]["title"]
    assert payload["iss"] == ISS and payload["vct"] == VCT and "cnf" in payload
    assert payload["_sd_alg"] == "sha-256"
    # 3 divulgables de primer nivel + 3 señuelos
    assert len(payload["_sd"]) == 6 and payload["_sd"] == sorted(payload["_sd"])
    assert issued.serialized.endswith("~") and issued.serialized.count("~") == 5


def test_full_reconstruction(env: Env) -> None:
    issued = env.issue()
    rec = reconstruct(peek(issued.issuer_jwt).payload, parse(issued.serialized).disclosures)
    assert rec.claims["given_name"] == "Ada"
    assert rec.claims["course"] == {
        "title": "Introducción a la Criptografía",
        "hours": 40,
        "grade": "A",
    }
    assert rec.disclosed_paths == {"given_name", "family_name", "completion_date", "course.grade"}


def test_personal_data_not_visible_in_issuer_jwt(env: Env) -> None:
    issued = env.issue()
    raw_payload = b64url_decode(issued.issuer_jwt.split(".")[1]).decode()
    assert "Lovelace" not in raw_payload and "Ada" not in raw_payload


def test_select_subset_of_disclosures(env: Env) -> None:
    issued = env.issue()
    payload = peek(issued.issuer_jwt).payload
    presentation = create_presentation(
        issued.serialized, payload, disclose=["family_name"], holder_signer=None
    )
    rec = reconstruct(payload, parse(presentation).disclosures)
    assert rec.claims.get("family_name") == "Lovelace"
    assert "given_name" not in rec.claims and "grade" not in rec.claims["course"]


def test_recursive_disclosure_includes_parent() -> None:
    signer = LocalDevSigner.generate(environment="test")
    issued = issue_sd_jwt_vc(
        {"iss": ISS, "vct": VCT, "iat": NOW, "address": {"city": "Rocha", "zip": "27000"}},
        selectively_disclosable=["address", "address.city", "address.zip"],
        signer=signer,
        decoys=0,
    )
    payload = peek(issued.issuer_jwt).payload
    assert "address" not in payload
    presentation = create_presentation(
        issued.serialized, payload, disclose=["address.city"], holder_signer=None
    )
    rec = reconstruct(payload, parse(presentation).disclosures)
    assert rec.claims["address"] == {"city": "Rocha"}


@pytest.mark.parametrize(
    "path", ["iss", "vct", "cnf", "status", "exp", "_sd", "cnf.jwk", "status.status_list"]
)
def test_mandatory_claims_cannot_be_selectively_disclosable(path: str) -> None:
    signer = LocalDevSigner.generate(environment="test")
    with pytest.raises(SdJwtError):
        issue_sd_jwt_vc(
            {"iss": ISS, "vct": VCT, "iat": NOW, "exp": NOW + 1, "cnf": {}, "status": {}},
            selectively_disclosable=[path],
            signer=signer,
        )


def test_foreign_disclosure_is_rejected(env: Env) -> None:
    issued = env.issue()
    payload = peek(issued.issuer_jwt).payload
    forged = create_disclosure("given_name", "Mallory").encoded
    with pytest.raises(SdJwtError) as err:
        reconstruct(payload, [*parse(issued.serialized).disclosures, forged])
    assert err.value.code in {"unreferenced_disclosure", "claim_conflict"}


def test_duplicate_disclosure_is_rejected(env: Env) -> None:
    issued = env.issue()
    parsed = parse(issued.serialized)
    with pytest.raises(SdJwtError) as err:
        reconstruct(peek(issued.issuer_jwt).payload, [*parsed.disclosures, parsed.disclosures[0]])
    assert err.value.code == "duplicate_disclosure"


def test_disclosure_cannot_overwrite_plain_claim() -> None:
    d = create_disclosure("name", "x")
    with pytest.raises(SdJwtError) as err:
        reconstruct({"name": "y", "_sd": [d.digest]}, [d.encoded])
    assert err.value.code == "claim_conflict"


def test_array_element_disclosures_are_processed() -> None:
    fr = create_disclosure(None, "FR")
    rec = reconstruct({"nationalities": [{"...": fr.digest}, "DE"]}, [fr.encoded])
    assert rec.claims["nationalities"] == ["FR", "DE"]


@pytest.mark.parametrize("bad", ["", "~", "abc", "a.b.c~~", "x" * 200_000])
def test_parse_rejects_malformed(bad: str) -> None:
    with pytest.raises(SdJwtError):
        parse(bad)


def test_nested_sd_arrays_are_sorted_and_padded() -> None:
    signer = LocalDevSigner.generate(environment="test")
    issued = issue_sd_jwt_vc(
        {"iss": ISS, "vct": VCT, "iat": NOW, "obj": {"c": 3, "b": 2, "a": 1}},
        selectively_disclosable=["obj", "obj.a", "obj.b", "obj.c"],
        signer=signer,
    )
    parent = next(d for d in issued.disclosures if d.name == "obj")
    inner_sd = parent.value["_sd"]
    assert inner_sd == sorted(inner_sd)
    assert len(inner_sd) == 4  # 3 claims + 1 señuelo anidado


def test_nested_sd_alg_is_rejected() -> None:
    with pytest.raises(SdJwtError):
        reconstruct({"a": {"_sd_alg": "sha-256"}}, [])
