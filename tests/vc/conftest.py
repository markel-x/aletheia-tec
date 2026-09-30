"""Utilidades de prueba para el núcleo ``aletheia.vc``: emisor, resolvedores en memoria."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from aletheia.vc.sdjwt import IssuedSdJwt, issue_sd_jwt_vc
from aletheia.vc.signing import LocalDevSigner
from aletheia.vc.status_list import StatusList, StatusReference, build_status_list_token
from aletheia.vc.verifier import (
    DependencyUnavailable,
    FetchedStatusList,
    KeyNotFound,
    KeyState,
    ResolvedKey,
    TrustPolicy,
)

NOW = 1_790_000_000
ISS = "https://aletheia.test/issuers/org_demo"
VCT = f"{ISS}/types/course-completion"
STATUS_URI = "https://aletheia.test/status-lists/sl_demo"


@dataclass
class KeyRegistry:
    """Resolvedor en memoria: {(iss, kid): ResolvedKey}."""

    keys: dict[tuple[str, str], ResolvedKey] = field(default_factory=dict)
    unavailable: bool = False
    calls: list[tuple[str, str]] = field(default_factory=list)

    def add(self, iss: str, signer: LocalDevSigner, state: KeyState = KeyState.ACTIVE) -> None:
        self.keys[(iss, signer.kid)] = ResolvedKey(signer.public_jwk, state)

    def set_state(self, iss: str, kid: str, state: KeyState) -> None:
        self.keys[(iss, kid)] = ResolvedKey(self.keys[(iss, kid)].jwk, state)

    def resolve(self, issuer: str, kid: str) -> ResolvedKey:
        self.calls.append((issuer, kid))
        if self.unavailable:
            raise DependencyUnavailable("timeout simulado")
        try:
            return self.keys[(issuer, kid)]
        except KeyError:
            raise KeyNotFound(kid) from None


@dataclass
class StatusServer:
    """Simula el endpoint de listas de estado del emisor."""

    signer: LocalDevSigner
    issuer: str = ISS
    uri: str = STATUS_URI
    status_list: StatusList = field(default_factory=lambda: StatusList(size=1024))
    signed_at: int = NOW
    unavailable: bool = False
    override_token: str | None = None

    def fetch(self, uri: str) -> FetchedStatusList:
        if self.unavailable or uri != self.uri:
            raise DependencyUnavailable("servicio de estado no disponible")
        token = self.override_token or build_status_list_token(
            self.status_list,
            uri=self.uri,
            issuer=self.issuer,
            signer=self.signer,
            iat=self.signed_at,
        )
        return FetchedStatusList(token=token, fetched_at=NOW)


@dataclass
class Env:
    issuer_signer: LocalDevSigner
    holder_signer: LocalDevSigner
    keys: KeyRegistry
    status: StatusServer
    policy: TrustPolicy

    def issue(
        self,
        idx: int = 7,
        *,
        exp: int | None = NOW + 86_400,
        extra: dict[str, Any] | None = None,
        signer: LocalDevSigner | None = None,
        iss: str = ISS,
    ) -> IssuedSdJwt:
        payload: dict[str, Any] = {
            "iss": iss,
            "iat": NOW - 3600,
            "nbf": NOW - 3600,
            "vct": VCT,
            "cnf": {"jwk": self.holder_signer.public_jwk},
            "status": StatusReference(idx=idx, uri=STATUS_URI).to_claim(),
            "course": {"title": "Introducción a la Criptografía", "hours": 40, "grade": "A"},
            "given_name": "Ada",
            "family_name": "Lovelace",
            "completion_date": "2026-09-01",
        }
        if exp is not None:
            payload["exp"] = exp
        payload.update(extra or {})
        return issue_sd_jwt_vc(
            payload,
            selectively_disclosable=[
                "given_name",
                "family_name",
                "completion_date",
                "course.grade",
            ],
            signer=signer or self.issuer_signer,
        )


@pytest.fixture
def env() -> Env:
    issuer = LocalDevSigner.generate(environment="test")
    holder = LocalDevSigner.generate(environment="test")
    keys = KeyRegistry()
    keys.add(ISS, issuer)
    return Env(
        issuer_signer=issuer,
        holder_signer=holder,
        keys=keys,
        status=StatusServer(signer=issuer),
        policy=TrustPolicy(trusted_issuers=frozenset({ISS}), accepted_vcts=frozenset({VCT})),
    )
