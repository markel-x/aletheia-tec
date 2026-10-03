"""Línea de comandos de Aletheia.

Por ahora expone el núcleo ``aletheia.vc``:

- ``aletheia demo``: recorre emisión → presentación → verificación →
  revocación → nueva verificación con datos ficticios y claves efímeras.
  Sólo en ``ALETHEIA_ENV=development`` (usa el firmante local de desarrollo).
- ``aletheia version``.
- ``aletheia api``: servidor HTTP (uvicorn) con la aplicación FastAPI.
- ``aletheia migrate``: aplica las migraciones Alembic hasta ``head``.
- ``aletheia maintenance``: purga de datos caducados (tarea programada, ADR-0008).

Los tres últimos exigen ``ALETHEIA_DATABASE_URL``; la misma imagen ejecuta
los tres roles (ADR-0001).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from . import __version__
from .vc import PROFILE_ID
from .vc.jws import peek
from .vc.sdjwt import create_presentation, issue_sd_jwt_vc
from .vc.signing import LocalDevSigner, SigningError
from .vc.status_list import INVALID, StatusList, StatusReference, build_status_list_token
from .vc.verifier import (
    FetchedStatusList,
    KeyNotFound,
    KeyState,
    PresentationContext,
    ResolvedKey,
    TrustPolicy,
    VerificationReport,
    verify_presentation,
)

DEMO_HOST = "https://aletheia.localhost"
DEMO_ISS = f"{DEMO_HOST}/issuers/org_demo"
DEMO_VCT = f"{DEMO_ISS}/types/course-completion"
DEMO_STATUS_URI = f"{DEMO_HOST}/status-lists/sl_demo"
DEMO_VERIFIER_AUD = "https://verificador.localhost"


@dataclass
class _DemoIssuerHost:
    """Emisor alojado en memoria: claves publicadas y lista de estado."""

    signer: LocalDevSigner
    status_list: StatusList = field(default_factory=lambda: StatusList(size=131_072))

    def resolve(self, issuer: str, kid: str) -> ResolvedKey:
        if issuer == DEMO_ISS and kid == self.signer.kid:
            return ResolvedKey(self.signer.public_jwk, KeyState.ACTIVE)
        raise KeyNotFound(kid)

    def fetch(self, uri: str) -> FetchedStatusList:
        now = int(time.time())
        token = build_status_list_token(
            self.status_list, uri=DEMO_STATUS_URI, issuer=DEMO_ISS, signer=self.signer, iat=now
        )
        return FetchedStatusList(token=token, fetched_at=now)


def _summary(report: VerificationReport) -> dict[str, Any]:
    return {
        "result": report.result.value,
        "reason": report.reason,
        "checks": {c.name: f"{c.outcome.value}:{c.code}" for c in report.checks},
        "disclosed_claims": report.disclosed_claims,
    }


def run_demo(environment: str) -> dict[str, Any]:
    issuer_signer = LocalDevSigner.generate(environment=environment)
    holder_signer = LocalDevSigner.generate(environment=environment)
    host = _DemoIssuerHost(issuer_signer)
    now = int(time.time())
    idx = secrets.randbelow(host.status_list.size)

    issued = issue_sd_jwt_vc(
        {
            "iss": DEMO_ISS,
            "iat": now,
            "nbf": now,
            "exp": now + 5 * 365 * 86_400,
            "vct": DEMO_VCT,
            "cnf": {"jwk": holder_signer.public_jwk},
            "status": StatusReference(idx=idx, uri=DEMO_STATUS_URI).to_claim(),
            "course": {"title": "Curso de demostración", "hours": 40, "grade": "A"},
            "given_name": "Titular",
            "family_name": "Ficticio",
            "completion_date": "2026-09-30",
        },
        selectively_disclosable=["given_name", "family_name", "completion_date", "course.grade"],
        signer=issuer_signer,
    )
    policy = TrustPolicy(
        trusted_issuers=frozenset({DEMO_ISS}),
        accepted_vcts=frozenset({DEMO_VCT}),
        required_claims=frozenset({"family_name"}),
    )
    used_nonces: set[str] = set()

    def consume(nonce: str) -> bool:
        if nonce in used_nonces:
            return False
        used_nonces.add(nonce)
        return True

    def present_and_verify() -> VerificationReport:
        nonce = secrets.token_urlsafe(16)  # lo emitiría POST /v1/presentation-requests
        presentation = create_presentation(
            issued.serialized,
            peek(issued.issuer_jwt).payload,
            disclose=["family_name"],
            holder_signer=holder_signer,
            aud=DEMO_VERIFIER_AUD,
            nonce=nonce,
            iat=int(time.time()),
        )
        return verify_presentation(
            presentation,
            policy=policy,
            key_resolver=host,
            status_fetcher=host,
            now=int(time.time()),
            context=PresentationContext(DEMO_VERIFIER_AUD, nonce, consume),
        )

    before = present_and_verify()
    host.status_list.set(idx, INVALID)  # revocación
    after = present_and_verify()
    return {
        "profile": PROFILE_ID,
        "issuer": DEMO_ISS,
        "issuer_kid": issuer_signer.kid,
        "credential_bytes": len(issued.serialized),
        "disclosures_issued": len(issued.disclosures),
        "verification_before_revocation": _summary(before),
        "verification_after_revocation": _summary(after),
        "note": "Datos y claves ficticios y efímeros; nada se persiste.",
    }


def _run_service_command(args: argparse.Namespace) -> int:
    # Importaciones diferidas: "demo" y "version" no necesitan la pila web ni la BD.
    from .platform.config import get_settings
    from .platform.logging import configure_logging

    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)
    log = logging.getLogger("aletheia.cli")
    try:
        database_url = settings.require_database_url()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.command == "migrate":
        from .db.migrations import head_revision, upgrade

        upgrade(database_url)
        log.info("migrations applied", extra={"head": head_revision()})
        app_password = os.environ.get("ALETHEIA_APP_DB_PASSWORD")
        if app_password:
            from .db.migrations import set_app_role_password

            set_app_role_password(database_url, app_password)
            log.info("application role password set")
        return 0
    if args.command == "maintenance":
        from .maintenance import run_maintenance
        from .platform.db import Database

        db = Database(settings)
        try:
            with db.session(bypass_rls=True) as session:
                run_maintenance(session)
        finally:
            db.dispose()
        return 0
    if args.command == "bootstrap":
        return _bootstrap(args, settings)
    if args.command == "access-requests":
        return _access_requests(args, settings)

    import uvicorn

    from .api import create_app

    uvicorn.run(
        create_app(settings),
        host=args.host,
        port=args.port,
        log_config=None,  # el logging lo configura la aplicación
        proxy_headers=True,
        forwarded_allow_ips="*",  # detrás del ALB; en local no hay proxy
        server_header=False,
        date_header=False,
    )
    return 0


def _access_requests(args: argparse.Namespace, settings: Any) -> int:
    """Solicitudes de la página de inicio: listar (JSON por línea) o marcar como resueltas.

    Aprobar no crea la organización: el operador la crea con ``bootstrap`` y luego la marca."""
    from .access import service as access
    from .platform.db import Database

    db = Database(settings)
    try:
        with db.session(bypass_rls=True) as session:
            if args.mark:
                request_id, status = args.mark
                item = access.mark(session, request_id, status)
                print(json.dumps({"id": str(item.id), "status": item.status}))
                return 0
            for item in access.list_requests(session, args.status):
                print(
                    json.dumps(
                        {
                            "id": str(item.id),
                            "created_at": item.created_at.isoformat(),
                            "organization": item.organization,
                            "contact_name": item.contact_name,
                            "email": item.email,
                            "website": item.website,
                            "language": item.language,
                            "use_case": item.use_case,
                        },
                        ensure_ascii=False,
                    )
                )
    finally:
        db.dispose()
    return 0


def _bootstrap(args: argparse.Namespace, settings: Any) -> int:
    from .organizations.keys import build_backend
    from .organizations.service import bootstrap_organization
    from .platform.db import Database
    from .platform.errors import AppError

    password = os.environ.get(args.owner_password_env)
    if not password:
        print(f"error: defina la contraseña en {args.owner_password_env}", file=sys.stderr)
        return 2
    backend = build_backend(settings)
    db = Database(settings)
    try:
        with db.session(bypass_rls=True) as session:
            org, owner, key = bootstrap_organization(
                session,
                backend,
                name=args.name,
                owner_email=args.owner_email,
                owner_display_name=args.owner_name,
                owner_password=password,
            )
            result = {
                "organization": org.public_id,
                "issuer": f"{settings.public_base}/issuers/{org.public_id}",
                "owner_id": str(owner.id),
                "signing_kid": key.kid,
            }
    except AppError as exc:
        print(f"error: {exc.code}: {exc.message}", file=sys.stderr)
        return 1
    finally:
        db.dispose()
    print(json.dumps(result))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aletheia", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version", help="muestra la versión y el perfil")
    sub.add_parser("demo", help="flujo completo del núcleo con datos ficticios (sólo desarrollo)")
    api = sub.add_parser("api", help="servidor HTTP")
    api.add_argument("--host", default="0.0.0.0")  # noqa: S104 - dentro del contenedor
    api.add_argument("--port", type=int, default=8000)
    sub.add_parser("migrate", help="aplica las migraciones de base de datos")
    sub.add_parser("maintenance", help="purga datos caducados (tarea programada)")
    boot = sub.add_parser(
        "bootstrap", help="crea una organización con su propietario y clave de firma"
    )
    boot.add_argument("--name", required=True, help="nombre de la organización")
    boot.add_argument("--owner-email", required=True)
    boot.add_argument("--owner-name", required=True)
    boot.add_argument(
        "--owner-password-env",
        default="ALETHEIA_BOOTSTRAP_PASSWORD",
        help="variable de entorno con la contraseña (nunca se pasa por argumento)",
    )
    reqs = sub.add_parser(
        "access-requests", help="solicitudes de acceso de la página de inicio (listar o resolver)"
    )
    reqs.add_argument("--status", default="pending", choices=["pending", "approved", "rejected"])
    reqs.add_argument(
        "--mark", nargs=2, metavar=("ID", "STATUS"), help="marca una solicitud: approved | rejected"
    )
    args = parser.parse_args(argv)

    if args.command == "version":
        print(json.dumps({"version": __version__, "profile": PROFILE_ID}))
        return 0
    if args.command in {"api", "migrate", "maintenance", "bootstrap", "access-requests"}:
        return _run_service_command(args)

    environment = os.environ.get("ALETHEIA_ENV", "production")
    try:
        result = run_demo(environment)
    except SigningError as exc:
        print(f"error: {exc}. Ejecute con ALETHEIA_ENV=development.", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    ok = (
        result["verification_before_revocation"]["result"] == "valid"
        and result["verification_after_revocation"]["reason"] == "credential_revoked"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
