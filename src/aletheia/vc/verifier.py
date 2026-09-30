"""Motor de verificación de SD-JWT VC con resultado desglosado.

Separa: formato, algoritmo, confianza en el emisor, resolución de clave, firma,
disclosures, vigencia, estado, vinculación con el titular, vinculación con la
solicitud y política. El resultado global es ``valid`` (según la política
aplicada), ``invalid`` o ``indeterminate`` (falta evidencia o una dependencia
no respondió). Una verificación válida **no** prueba la identidad de quien
presenta: sólo que controla la clave vinculada, si hubo KB-JWT.

Las dependencias externas (resolución de claves, descarga de listas de
estado, consumo de nonces) se inyectan; este módulo no hace E/S.
"""

from __future__ import annotations

import contextlib
import enum
from dataclasses import dataclass, field
from typing import Any, NoReturn, Protocol, TypeGuard

from . import KB_JWT_TYP, SD_JWT_VC_TYP, STATUS_LIST_TYP
from .jws import JwsFormatError, JwsSignatureError, check_header, peek, verify_compact
from .keys import KeyFormatError, public_key_from_jwk
from .sdjwt import SdJwtError, parse, reconstruct, sd_hash
from .status_list import (
    INVALID,
    VALID,
    StatusList,
    StatusListError,
    StatusReference,
    is_https_or_dev,
)


class Outcome(enum.StrEnum):
    PASS = "pass"  # noqa: S105 (no es una contraseña)
    FAIL = "fail"
    INDETERMINATE = "indeterminate"
    SKIPPED = "skipped"


class Result(enum.StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    INDETERMINATE = "indeterminate"


CHECK_ORDER = (
    "format",
    "algorithm",
    "issuer_trust",
    "key_resolution",
    "signature",
    "disclosures",
    "validity_period",
    "status",
    "holder_binding",
    "presentation_binding",
    "policy",
)


# --- dependencias inyectadas ---------------------------------------------------


class KeyState(enum.StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    COMPROMISED = "compromised"


@dataclass(frozen=True)
class ResolvedKey:
    jwk: dict[str, Any]
    state: KeyState


class KeyNotFound(Exception):
    pass


class DependencyUnavailable(Exception):
    """Red caída, timeout, respuesta 5xx o demasiado grande."""


class KeyResolver(Protocol):
    def resolve(self, issuer: str, kid: str) -> ResolvedKey:
        """Devuelve la clave o lanza ``KeyNotFound`` / ``DependencyUnavailable``."""
        ...


@dataclass(frozen=True)
class FetchedStatusList:
    token: str
    fetched_at: int


class StatusFetcher(Protocol):
    def fetch(self, uri: str) -> FetchedStatusList:
        """Descarga (o toma de caché) el token o lanza ``DependencyUnavailable``."""
        ...


@dataclass(frozen=True)
class TrustPolicy:
    trusted_issuers: frozenset[str]
    accepted_vcts: frozenset[str] | None = None
    required_claims: frozenset[str] = frozenset()
    require_holder_binding: bool = True
    require_status: bool = True
    max_status_age_seconds: int = 900
    clock_skew_seconds: int = 60
    max_kb_age_seconds: int = 300
    dev_http_origin: str | None = None
    """Sólo desarrollo/pruebas locales: acepta ``http://`` para ``iss`` y la URI de estado
    cuando están bajo este origen exacto. ``None`` (por defecto) exige https siempre."""


class NonceConsumer(Protocol):
    def __call__(self, nonce: str) -> bool:
        """Marca el nonce como usado de forma atómica. ``False`` si ya lo estaba."""
        ...


@dataclass(frozen=True)
class PresentationContext:
    """Lo que el verificador pidió: audiencia y nonce de un solo uso.

    ``consume_nonce`` se invoca sólo después de validar firma del emisor,
    KB-JWT y ``sd_hash``, para que una presentación inválida no queme el nonce.
    En la aplicación es un ``UPDATE … WHERE consumed_at IS NULL RETURNING``.
    """

    expected_aud: str
    expected_nonce: str
    consume_nonce: NonceConsumer


# --- resultado --------------------------------------------------------------------


@dataclass
class Check:
    name: str
    outcome: Outcome
    code: str
    detail: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "outcome": self.outcome.value,
            "code": self.code,
            "detail": self.detail,
        }


@dataclass
class VerificationReport:
    result: Result
    checks: list[Check]
    issuer: str | None = None
    vct: str | None = None
    kid: str | None = None
    status_reference: StatusReference | None = None
    holder_binding_verified: bool = False
    disclosed_claims: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def reason(self) -> str | None:
        for check in self.checks:
            if check.outcome in (Outcome.FAIL, Outcome.INDETERMINATE):
                return check.code
        return None

    def check(self, name: str) -> Check:
        return next(c for c in self.checks if c.name == name)


class _Stop(Exception):
    pass


class _Run:
    def __init__(self) -> None:
        self.checks: dict[str, Check] = {}

    def record(self, name: str, outcome: Outcome, code: str, detail: str = "") -> None:
        self.checks[name] = Check(name, outcome, code, detail)

    def ok(self, name: str, code: str = "ok", detail: str = "") -> None:
        self.record(name, Outcome.PASS, code, detail)

    def fail(self, name: str, code: str, detail: str = "") -> NoReturn:
        self.record(name, Outcome.FAIL, code, detail)
        raise _Stop

    def indeterminate(self, name: str, code: str, detail: str = "") -> None:
        self.record(name, Outcome.INDETERMINATE, code, detail)

    def finish(self) -> tuple[Result, list[Check]]:
        ordered = [
            self.checks.get(n) or Check(n, Outcome.SKIPPED, "not_evaluated") for n in CHECK_ORDER
        ]
        outcomes = {c.outcome for c in ordered}
        if Outcome.FAIL in outcomes:
            return Result.INVALID, ordered
        if Outcome.INDETERMINATE in outcomes:
            return Result.INDETERMINATE, ordered
        return Result.VALID, ordered


def _is_int(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


# --- verificación -----------------------------------------------------------------


def verify_presentation(
    presentation: str,
    *,
    policy: TrustPolicy,
    key_resolver: KeyResolver,
    status_fetcher: StatusFetcher,
    now: int,
    context: PresentationContext | None = None,
) -> VerificationReport:
    run = _Run()
    report = VerificationReport(result=Result.INDETERMINATE, checks=[])
    with contextlib.suppress(_Stop):
        _verify(presentation, policy, key_resolver, status_fetcher, now, context, run, report)
    report.result, report.checks = run.finish()
    if report.result is not Result.VALID:
        report.disclosed_claims = None  # nunca devolver datos no confiables
    return report


def _verify(
    presentation: str,
    policy: TrustPolicy,
    key_resolver: KeyResolver,
    status_fetcher: StatusFetcher,
    now: int,
    context: PresentationContext | None,
    run: _Run,
    report: VerificationReport,
) -> None:
    skew = policy.clock_skew_seconds

    # 1. Formato --------------------------------------------------------------------
    try:
        parsed = parse(presentation)
        decoded = peek(parsed.issuer_jwt)
    except (SdJwtError, JwsFormatError) as exc:
        run.fail("format", "malformed", str(exc))
        return
    header, payload = decoded.header, decoded.payload
    iss, vct = payload.get("iss"), payload.get("vct")
    if header.get("typ") != SD_JWT_VC_TYP:
        run.fail("format", "unsupported_typ", f"typ debe ser {SD_JWT_VC_TYP}")
    if not isinstance(iss, str) or not is_https_or_dev(iss, policy.dev_http_origin):
        run.fail("format", "invalid_iss", "iss debe ser una URL https")
    if not isinstance(vct, str) or not vct:
        run.fail("format", "invalid_vct", "vct ausente")
    for claim in ("iat", "exp", "nbf"):  # iat es OPCIONAL en SD-JWT VC §3.2.2
        if claim in payload and not _is_int(payload[claim]):
            run.fail("format", "invalid_time_claim", f"{claim} debe ser entero")
    report.issuer, report.vct = iss, vct
    run.ok("format")

    # 2. Algoritmo (antes de tocar claves) -----------------------------------
    try:
        check_header(header, expected_typ=SD_JWT_VC_TYP, require_kid=True)
    except JwsFormatError as exc:
        run.fail("algorithm", "algorithm_not_allowed", str(exc))
    kid = header["kid"]
    report.kid = kid
    run.ok("algorithm", detail=header["alg"])

    # 3. Confianza en el emisor: no se resuelven claves de emisores no listados
    if iss not in policy.trusted_issuers:
        run.fail(
            "issuer_trust", "issuer_not_trusted", "el emisor no figura en la política de confianza"
        )
    run.ok("issuer_trust")

    # 4. Resolución de clave -----------------------------------------------------------
    try:
        key = key_resolver.resolve(iss, kid)
    except KeyNotFound:
        run.fail("key_resolution", "issuer_key_not_found", "kid desconocido para el emisor")
        return
    except DependencyUnavailable as exc:
        run.indeterminate("key_resolution", "key_resolution_unavailable", str(exc))
        raise _Stop from exc
    if key.state is KeyState.COMPROMISED:
        run.fail(
            "key_resolution",
            "issuer_key_compromised",
            "la clave de firma fue declarada comprometida",
        )
    run.ok("key_resolution", "key_retired" if key.state is KeyState.RETIRED else "ok")

    # 5. Firma --------------------------------------------------------------------------
    try:
        verify_compact(parsed.issuer_jwt, key.jwk, expected_typ=SD_JWT_VC_TYP)
    except JwsSignatureError as exc:
        run.fail("signature", "signature_invalid", str(exc))
    except JwsFormatError as exc:
        run.fail("signature", "signature_invalid", str(exc))
    run.ok("signature")

    # 6. Disclosures --------------------------------------------------------------------
    try:
        rec = reconstruct(payload, parsed.disclosures)
    except SdJwtError as exc:
        run.fail("disclosures", exc.code, str(exc))
        return
    claims = rec.claims
    run.ok("disclosures", detail=f"{len(parsed.disclosures)} divulgadas")

    # 7. Vigencia -----------------------------------------------------------------------
    if _is_int(payload.get("iat")) and payload["iat"] > now + skew:
        run.fail("validity_period", "issued_in_future")
    if _is_int(payload.get("nbf")) and payload["nbf"] > now + skew:
        run.fail("validity_period", "credential_not_yet_valid")
    if _is_int(payload.get("exp")) and payload["exp"] <= now - skew:
        run.fail("validity_period", "credential_expired")
    run.ok("validity_period", "ok" if "exp" in payload else "no_expiry")

    # 8. Estado -------------------------------------------------------------------------
    _check_status(payload, iss, policy, key_resolver, status_fetcher, now, run, report)

    # 9. Vinculación con el titular -----------------------------------------------------
    kb_payload = _check_holder_binding(parsed, payload, policy, now, run, report)

    # 10. Vinculación con la solicitud (audiencia, nonce, replay) ---------------------
    if context is None and kb_payload is not None:
        # RFC 9901 §7.3: aud y nonce DEBEN coincidir con lo esperado; sin
        # solicitud no hay con qué compararlos (posible replay).
        run.indeterminate(
            "presentation_binding",
            "request_context_missing",
            "hay KB-JWT pero no una solicitud contra la cual validar aud y nonce",
        )
    elif context is None:
        run.record("presentation_binding", Outcome.SKIPPED, "no_request_context")
    elif kb_payload is None:
        run.fail(
            "presentation_binding",
            "presentation_binding_missing",
            "la solicitud exige KB-JWT con aud y nonce",
        )
    elif kb_payload.get("aud") != context.expected_aud:
        run.fail("presentation_binding", "audience_mismatch")
    elif kb_payload.get("nonce") != context.expected_nonce:
        run.fail("presentation_binding", "nonce_mismatch")
    elif not context.consume_nonce(context.expected_nonce):
        run.fail(
            "presentation_binding",
            "presentation_replayed",
            "el nonce de la solicitud ya fue utilizado",
        )
    else:
        run.ok("presentation_binding")

    # 11. Política ----------------------------------------------------------------------
    if policy.accepted_vcts is not None and vct not in policy.accepted_vcts:
        run.fail("policy", "vct_not_accepted")
    missing = sorted(
        c
        for c in policy.required_claims
        if c not in rec.disclosed_paths and not _has_path(claims, c)
    )
    if missing:
        run.fail("policy", "required_claim_missing", ", ".join(missing))
    run.ok("policy")

    report.disclosed_claims = {k: v for k, v in claims.items() if k not in ("cnf", "status")}
    report.notes.append(
        "La validez no demuestra la identidad de quien presenta ni la veracidad de lo afirmado."
    )


def _has_path(claims: dict[str, Any], dotted: str) -> bool:
    node: Any = claims
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    return True


def _check_status(
    payload: dict[str, Any],
    iss: str,
    policy: TrustPolicy,
    key_resolver: KeyResolver,
    status_fetcher: StatusFetcher,
    now: int,
    run: _Run,
    report: VerificationReport,
) -> None:
    if "status" not in payload:
        if policy.require_status:
            run.fail("status", "status_missing", "la política exige referencia de estado")
        run.record("status", Outcome.SKIPPED, "status_not_provided")
        return
    try:
        ref = StatusReference.from_claims(payload, dev_http_origin=policy.dev_http_origin)
    except StatusListError as exc:
        run.fail("status", "status_reference_invalid", str(exc))
        return
    report.status_reference = ref
    try:
        fetched = status_fetcher.fetch(ref.uri)
    except DependencyUnavailable as exc:
        run.indeterminate("status", "status_unavailable", str(exc))
        return
    try:
        token = peek(fetched.token)
        slt_iss, kid = token.payload.get("iss"), token.header.get("kid")
        if slt_iss != iss or not isinstance(kid, str):
            raise StatusListError("la lista de estado no fue emitida por el mismo emisor")
        key = key_resolver.resolve(iss, kid)
        if key.state is KeyState.COMPROMISED:
            raise StatusListError("lista firmada con clave comprometida")
        verify_compact(fetched.token, key.jwk, expected_typ=STATUS_LIST_TYP)
        if token.payload.get("sub") != ref.uri:
            raise StatusListError("sub de la lista no coincide con la uri referenciada")
        slt_iat, slt_exp = token.payload.get("iat"), token.payload.get("exp")
        if not isinstance(slt_iat, int) or isinstance(slt_iat, bool):
            raise StatusListError("iat ausente en la lista")
        status_list = StatusList.decode(token.payload.get("status_list"))
    except DependencyUnavailable as exc:
        run.indeterminate("status", "status_unavailable", str(exc))
        return
    except (JwsFormatError, JwsSignatureError, StatusListError, KeyNotFound, KeyFormatError) as exc:
        run.indeterminate("status", "status_list_invalid", str(exc))
        return
    if _is_int(slt_exp) and slt_exp <= now - policy.clock_skew_seconds:
        run.indeterminate("status", "status_list_expired")
        return
    if slt_iat > now + policy.clock_skew_seconds:
        run.indeterminate("status", "status_list_invalid", "iat de la lista en el futuro")
        return
    if now - slt_iat > policy.max_status_age_seconds:
        run.indeterminate(
            "status",
            "status_stale",
            f"antigüedad {now - slt_iat}s > {policy.max_status_age_seconds}s",
        )
        return
    try:
        value = status_list.get(ref.idx)
    except StatusListError:
        run.fail("status", "status_index_invalid")
        return
    if value == INVALID:
        run.fail("status", "credential_revoked")
    elif value == 0x02:
        run.fail("status", "credential_suspended")
    elif value != VALID:
        run.indeterminate("status", "status_unknown_value", str(value))
    else:
        run.ok("status", detail=f"lista de {now - slt_iat}s de antigüedad")


def _check_holder_binding(
    parsed: Any,
    payload: dict[str, Any],
    policy: TrustPolicy,
    now: int,
    run: _Run,
    report: VerificationReport,
) -> dict[str, Any] | None:
    if parsed.kb_jwt is None:
        if policy.require_holder_binding:
            run.fail(
                "holder_binding",
                "holder_binding_missing",
                "la política exige prueba de posesión (KB-JWT)",
            )
        run.record("holder_binding", Outcome.SKIPPED, "holder_binding_not_presented")
        return None
    cnf = payload.get("cnf")
    jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
    if not isinstance(jwk, dict):
        run.fail("holder_binding", "cnf_missing", "la credencial no tiene cnf.jwk")
    try:
        public_key_from_jwk(jwk)
        kb = verify_compact(parsed.kb_jwt, jwk, expected_typ=KB_JWT_TYP, require_kid=False)
    except (KeyFormatError, JwsFormatError, JwsSignatureError) as exc:
        run.fail("holder_binding", "holder_binding_invalid", str(exc))
        return None
    kbp = kb.payload
    if kbp.get("sd_hash") != sd_hash(parsed.without_kb):
        run.fail("holder_binding", "kb_sd_hash_mismatch")
    iat = kbp.get("iat")
    skew = policy.clock_skew_seconds
    if not isinstance(iat, int) or isinstance(iat, bool) or iat > now + skew:
        run.fail("holder_binding", "kb_iat_invalid")
    if now - iat > policy.max_kb_age_seconds + skew:
        run.fail("holder_binding", "kb_expired")
    if not isinstance(kbp.get("aud"), str) or not isinstance(kbp.get("nonce"), str):
        run.fail("holder_binding", "kb_claims_missing")
    report.holder_binding_verified = True
    run.ok("holder_binding")
    return kbp
