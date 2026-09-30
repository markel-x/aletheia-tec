"""Prueba de carga de los tres endpoints con objetivo en docs/00 §4.

Uso (contra la pila de compose; ver loadtest/README.md):

    docker compose run --rm -v "$PWD/loadtest:/loadtest:ro" -e ALETHEIA_PASSWORD=... \
        tests python /loadtest/run.py --duration 30 --workers 8

Cada escenario corre ``--workers`` hilos durante ``--duration`` segundos y mide
la latencia de la petición objetivo (no la de las peticiones de preparación):

- ``offer``   : POST /v1/credentials                          objetivo p95 < 300 ms
- ``issue``   : POST /oid4vci/credential (firma incluida)     objetivo p95 < 600 ms
- ``verify``  : POST /v1/verifications (emisor alojado)       objetivo p95 < 300 ms
- ``status``  : GET /status-lists/{id} (caché caliente)       sin objetivo; referencia

El conductor usa el núcleo de Aletheia (``aletheia.vc``) para las claves del
titular y los proofs: el cliente de carga no es independiente, la API sí.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from aletheia.vc import OID4VCI_PROOF_TYP
from aletheia.vc.jws import peek, sign_compact
from aletheia.vc.sdjwt import create_presentation
from aletheia.vc.signing import LocalDevSigner

GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
TARGETS_MS = {"offer": 300, "issue": 600, "verify": 300}
CLAIMS = {
    "course": {"title": "Carga", "grade": "A"},
    "given_name": "Carga",
    "family_name": "Prueba",
}


@dataclass
class Stats:
    latencies: list[float] = field(default_factory=list)
    errors: dict[str, int] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def ok(self, ms: float) -> None:
        with self.lock:
            self.latencies.append(ms)

    def fail(self, key: str) -> None:
        with self.lock:
            self.errors[key] = self.errors.get(key, 0) + 1

    def summary(self, elapsed: float) -> dict[str, Any]:
        lat = sorted(self.latencies)
        if not lat:
            return {"requests": 0, "errors": self.errors}

        def pct(p: float) -> float:
            return round(lat[min(len(lat) - 1, int(p * len(lat)))], 1)

        return {
            "requests": len(lat),
            "errors": self.errors,
            "rps": round(len(lat) / elapsed, 1),
            "p50_ms": pct(0.50),
            "p95_ms": pct(0.95),
            "p99_ms": pct(0.99),
            "max_ms": round(lat[-1], 1),
            "mean_ms": round(statistics.fmean(lat), 1),
        }


class Api:
    def __init__(self, base: str, public: str) -> None:
        self.base = base.rstrip("/")
        self.public = public.rstrip("/")
        self.local = threading.local()

    @property
    def client(self) -> httpx.Client:
        if not hasattr(self.local, "c"):
            self.local.c = httpx.Client(base_url=self.base, timeout=30)
        return self.local.c  # type: ignore[no-any-return]

    def path(self, url: str) -> str:
        return url[len(self.public) :] if url.startswith(self.public) else url

    def call(self, method: str, url: str, **kw: Any) -> httpx.Response:
        token = kw.pop("token", None)
        headers = kw.pop("headers", {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return self.client.request(method, self.path(url), headers=headers, **kw)


def timed(fn: Callable[[], httpx.Response]) -> tuple[httpx.Response, float]:
    start = time.perf_counter()
    r = fn()
    return r, (time.perf_counter() - start) * 1000


def setup(api: Api, email: str, password: str) -> dict[str, Any]:
    token = api.call("POST", "/v1/auth/login", json={"email": email, "password": password}).json()[
        "token"
    ]
    slug = "load-course"
    templates = api.call("GET", "/v1/templates", token=token).json()
    if not any(t["slug"] == slug for t in templates):
        tpl = api.call(
            "POST", "/v1/templates", token=token, json={"slug": slug, "name": "Carga"}
        ).json()
        ver = api.call(
            "POST",
            f"/v1/templates/{tpl['id']}/versions",
            token=token,
            json={
                "claims_schema": {
                    "type": "object",
                    "properties": {
                        "course": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "grade": {"type": "string"},
                            },
                            "required": ["title"],
                        },
                        "given_name": {"type": "string"},
                        "family_name": {"type": "string"},
                    },
                    "required": ["course", "given_name", "family_name"],
                },
                "selective_disclosure": ["given_name", "family_name", "course.grade"],
                "validity_days": 30,
            },
        ).json()
        api.call("POST", f"/v1/templates/{tpl['id']}/versions/{ver['id']}/publish", token=token)
    org = api.call("GET", "/v1/organization", token=token).json()
    policies = api.call("GET", "/v1/trust-policies", token=token).json()
    policy = next((p for p in policies if p["name"] == "load"), None)
    if policy is None:
        policy = api.call(
            "POST",
            "/v1/trust-policies",
            token=token,
            json={"name": "load", "required_claims": ["family_name"]},
        ).json()
        api.call(
            "POST",
            f"/v1/trust-policies/{policy['id']}/issuers",
            token=token,
            json={"issuer": org["issuer"]},
        )
    return {"token": token, "slug": slug, "issuer": org["issuer"], "policy_id": policy["id"]}


def new_offer(api: Api, ctx: dict[str, Any]) -> httpx.Response:
    return api.call(
        "POST",
        "/v1/credentials",
        token=ctx["token"],
        json={"template": ctx["slug"], "claims": CLAIMS},
    )


def issue_one(api: Api, ctx: dict[str, Any], stats: Stats | None) -> tuple[str, LocalDevSigner]:
    offer = new_offer(api, ctx).json()
    doc = api.call("GET", offer["credential_offer_uri"]).json()
    tok = api.call(
        "POST",
        "/oid4vci/token",
        data={
            "grant_type": GRANT,
            "pre-authorized_code": doc["grants"][GRANT]["pre-authorized_code"],
            "tx_code": offer["tx_code"],
        },
    ).json()
    nonce = api.call("POST", "/oid4vci/nonce").json()["c_nonce"]
    holder = LocalDevSigner.generate(environment="test")
    proof = sign_compact(
        {"alg": "ES256", "typ": OID4VCI_PROOF_TYP, "jwk": holder.public_jwk},
        {"aud": ctx["issuer"], "iat": int(time.time()), "nonce": nonce},
        holder,
    )
    r, ms = timed(
        lambda: api.call(
            "POST",
            "/oid4vci/credential",
            token=tok["access_token"],
            json={"credential_configuration_id": ctx["slug"], "proofs": {"jwt": [proof]}},
        )
    )
    if r.status_code != 200:
        if stats:
            stats.fail(f"HTTP {r.status_code}")
        raise RuntimeError(r.text[:200])
    if stats:
        stats.ok(ms)
    return r.json()["credentials"][0]["credential"], holder


def run_scenario(
    name: str, workers: int, duration: float, body: Callable[[Stats], None]
) -> dict[str, Any]:
    stats = Stats()
    stop = time.monotonic() + duration

    def loop() -> None:
        while time.monotonic() < stop:
            try:
                body(stats)
            except Exception as exc:  # noqa: BLE001 - se cuenta y se sigue
                stats.fail(type(exc).__name__)

    start = time.monotonic()
    with ThreadPoolExecutor(workers) as pool:
        for _ in range(workers):
            pool.submit(loop)
    result = stats.summary(time.monotonic() - start)
    target = TARGETS_MS.get(name)
    if target is not None and "p95_ms" in result:
        result["target_p95_ms"] = target
        result["meets_target"] = result["p95_ms"] < target
    print(f"{name:7} {json.dumps(result)}", flush=True)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default=os.environ.get("ALETHEIA_API", "http://api:8000"))
    parser.add_argument(
        "--public", default=os.environ.get("ALETHEIA_PUBLIC_BASE", "http://127.0.0.1:8008")
    )
    parser.add_argument("--email", default=os.environ.get("ALETHEIA_EMAIL", "owner@example.org"))
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--scenarios", default="offer,issue,verify,status")
    args = parser.parse_args()
    password = os.environ.get("ALETHEIA_PASSWORD")
    if not password:
        print("ALETHEIA_PASSWORD es obligatoria", file=sys.stderr)
        return 2

    api = Api(args.api, args.public)
    ctx = setup(api, args.email, password)
    results: dict[str, Any] = {}
    chosen = args.scenarios.split(",")

    if "offer" in chosen:

        def offer_body(stats: Stats) -> None:
            r, ms = timed(lambda: new_offer(api, ctx))
            if r.status_code == 201:
                stats.ok(ms)
            else:
                stats.fail(f"HTTP {r.status_code}")

        results["offer"] = run_scenario("offer", args.workers, args.duration, offer_body)

    if "issue" in chosen:
        results["issue"] = run_scenario(
            "issue", args.workers, args.duration, lambda s: issue_one(api, ctx, s) and None
        )

    if "verify" in chosen or "status" in chosen:
        pool = [issue_one(api, ctx, None) for _ in range(max(4, args.workers))]
    if "verify" in chosen:
        counter = iter(range(10**9))
        lock = threading.Lock()

        def verify_body(stats: Stats) -> None:
            with lock:
                credential, holder = pool[next(counter) % len(pool)]
            req = api.call(
                "POST",
                "/v1/presentation-requests",
                token=ctx["token"],
                json={"trust_policy_id": ctx["policy_id"]},
            ).json()
            payload = peek(credential.split("~")[0]).payload
            presentation = create_presentation(
                credential,
                payload,
                disclose=["family_name"],
                holder_signer=holder,
                aud=req["aud"],
                nonce=req["nonce"],
                iat=int(time.time()),
            )
            r, ms = timed(
                lambda: api.call(
                    "POST",
                    "/v1/verifications",
                    token=ctx["token"],
                    json={"presentation": presentation, "presentation_request_id": req["id"]},
                )
            )
            if r.status_code == 200 and r.json()["result"] == "valid":
                stats.ok(ms)
            else:
                stats.fail(f"{r.status_code}:{r.json().get('reason', r.json().get('error'))}")

        results["verify"] = run_scenario("verify", args.workers, args.duration, verify_body)

    if "status" in chosen:
        status_uri = urlparse(peek(pool[0][0].split("~")[0]).payload["status"]["status_list"]["uri"])

        def status_body(stats: Stats) -> None:
            r, ms = timed(lambda: api.call("GET", status_uri.path))
            if r.status_code == 200:
                stats.ok(ms)
            else:
                stats.fail(f"HTTP {r.status_code}")

        results["status"] = run_scenario("status", args.workers, args.duration, status_body)

    print(json.dumps({"workers": args.workers, "duration_s": args.duration, "results": results}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
