"""«Pruébelo ahora»: credencial de muestra desde la página de inicio, sin cuenta.

Emite una oferta en la organización de demostración (``ALETHEIA_DEMO_ORGANIZATION``) con la
plantilla ``demo_template``, como lo haría el panel. El visitante la agrega a su wallet desde el
teléfono y la verifica escaneando el QR del pase.

Contra el abuso:
- límite por red (/24 en IPv4, /48 en IPv6) y un tope diario global, que acota el costo pase lo
  que pase; al alcanzarlo se registra ``demo daily limit reached`` (alarma en CloudWatch);
- un token del formulario firmado con la hora en que se cargó la página: sin él, o si llega en
  menos de ``MIN_FORM_SECONDS``, no se emite (filtra envíos automáticos directos al endpoint);
- el pase dice «DEMO · Credencial de muestra» como título, así una captura no pasa por real.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..authz.service import Principal
from ..db import models
from ..issuance import service as issuance
from ..issuance import templates
from ..platform import ratelimit
from ..platform.config import Settings
from ..platform.crypto import DataEncryptor, tx_code_key
from ..platform.errors import AppError, NotFound

log = logging.getLogger(__name__)

PER_NETWORK_LIMIT = 5
PER_NETWORK_WINDOW = timedelta(hours=1)
DEMO_VALIDITY_DAYS = 7
DEFAULT_NAME = {"es": "Visitante", "en": "Visitor"}
DEMO_TITLE = {"es": "DEMO · Credencial de muestra", "en": "DEMO · Sample credential"}
MIN_FORM_SECONDS = 2
MAX_FORM_SECONDS = 2 * 3600


class InvalidDemoForm(AppError):
    status_code = 400
    code = "invalid_form"


DEMO_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string", "title": "Tipo", "maxLength": 60},
        "given_name": {"type": "string", "title": "Nombre", "minLength": 1, "maxLength": 40},
        "member_id": {"type": "string", "title": "Nº de credencial", "maxLength": 20},
    },
    "required": ["title", "given_name", "member_id"],
}
DEMO_DISPLAY = {
    "display": [
        {"name": "Credencial de muestra", "locale": "es"},
        {"name": "Sample credential", "locale": "en"},
    ]
}


@dataclass(frozen=True)
class DemoOffer:
    offer: issuance.Offer
    member_id: str


def _system(org: models.Organization) -> Principal:
    return Principal(
        organization_id=org.id,
        actor_type="system",
        actor_id=uuid.UUID(int=0),
        permissions=frozenset(),
    )


def setup_demo_template(session: Session, org_public_id: str, slug: str = "demo") -> str:
    """Crea y publica la plantilla de la demo (``aletheia demo-setup``). Idempotente."""
    org = session.scalar(
        select(models.Organization).where(models.Organization.public_id == org_public_id)
    )
    if org is None:
        raise NotFound("Organization not found")
    principal = _system(org)
    template = session.scalar(
        select(models.CredentialTemplate)
        .where(models.CredentialTemplate.organization_id == org.id)
        .where(models.CredentialTemplate.slug == slug)
    )
    if template is None:
        template = templates.create_template(session, principal, slug=slug, name="Demo")
    try:
        current = templates.latest_published(session, template).claims_schema
    except AppError:
        current = None
    if current != DEMO_SCHEMA:  # primera vez, o el esquema de la demo cambió
        version = templates.create_version(
            session,
            principal,
            template.id,
            claims_schema=DEMO_SCHEMA,
            selective_disclosure=["given_name"],
            validity_days=DEMO_VALIDITY_DAYS,
            display=DEMO_DISPLAY,
        )
        templates.publish_version(session, principal, template.id, version.id)
    return template.public_id


def _form_mac(settings: Settings, issued: int) -> str:
    # Clave derivada (no la de los tx_code tal cual): un uso, una clave.
    key = hmac.new(tx_code_key(settings), b"credoseal demo form", hashlib.sha256).digest()
    return hmac.new(key, str(issued).encode(), hashlib.sha256).hexdigest()[:32]


def form_token(settings: Settings, now: float | None = None) -> str:
    issued = int(now if now is not None else time.time())
    return f"{issued}.{_form_mac(settings, issued)}"


def check_form_token(settings: Settings, token: str | None, now: float | None = None) -> None:
    now = now if now is not None else time.time()
    issued_raw, _, mac = (token or "").partition(".")
    if not issued_raw.isdigit() or not hmac.compare_digest(
        mac, _form_mac(settings, int(issued_raw))
    ):
        raise InvalidDemoForm("Invalid form")
    if not MIN_FORM_SECONDS <= now - int(issued_raw) <= MAX_FORM_SECONDS:
        raise InvalidDemoForm("Invalid form")


def demo_organization(session: Session, settings: Settings) -> models.Organization | None:
    if not settings.demo_organization:
        return None
    return session.scalar(
        select(models.Organization).where(
            models.Organization.public_id == settings.demo_organization
        )
    )


def create_demo_offer(
    session: Session,
    settings: Settings,
    encryptor: DataEncryptor,
    *,
    given_name: str | None,
    language: str,
    network: str | None,
) -> DemoOffer:
    org = demo_organization(session, settings)
    if org is None:
        raise NotFound("Demo not available")
    if network:
        ratelimit.hit(
            session, f"demo:net:{network}", limit=PER_NETWORK_LIMIT, window=PER_NETWORK_WINDOW
        )
    try:
        ratelimit.hit(
            session, "demo:global", limit=settings.demo_daily_limit, window=timedelta(days=1)
        )
    except ratelimit.RateLimited:
        log.warning("demo daily limit reached", extra={"limit": settings.demo_daily_limit})
        raise
    member_id = f"DEMO-{secrets.randbelow(10**6):06d}"
    offer = issuance.create_offer(
        session,
        _system(org),
        settings,
        encryptor,
        template_slug=settings.demo_template,
        claims={
            "title": DEMO_TITLE.get(language, DEMO_TITLE["en"]),
            "given_name": given_name or DEFAULT_NAME.get(language, "Visitor"),
            "member_id": member_id,
        },
        holder_reference="demo",
        validity_days=DEMO_VALIDITY_DAYS,
    )
    return DemoOffer(offer, member_id)
