"""Plantillas versionadas de credencial."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..authz.service import Principal
from ..db import models
from ..platform import ids
from ..platform.config import Settings
from ..platform.errors import AppError, Conflict, NotFound
from .schema import InvalidSchema, selectable_paths, validate_schema


def vct_for(settings: Settings, org_public_id: str, slug: str) -> str:
    return f"{settings.public_base}/issuers/{org_public_id}/types/{slug}"


def create_template(
    session: Session, principal: Principal, *, slug: str, name: str
) -> models.CredentialTemplate:
    exists = session.scalar(
        select(models.CredentialTemplate)
        .where(models.CredentialTemplate.organization_id == principal.organization_id)
        .where(models.CredentialTemplate.slug == slug)
    )
    if exists is not None:
        raise Conflict("A template with that slug already exists")
    template = models.CredentialTemplate(
        id=ids.uuid7(),
        organization_id=principal.organization_id,
        public_id=ids.public_id("tpl"),
        slug=slug,
        name=name,
    )
    session.add(template)
    session.flush()
    audit.record(
        session,
        organization_id=principal.organization_id,
        actor=principal.audit_actor,
        action="template.created",
        target_type="credential_template",
        target_id=template.id,
        metadata={"slug": slug},
    )
    return template


def list_templates(session: Session, principal: Principal) -> list[models.CredentialTemplate]:
    return list(
        session.scalars(
            select(models.CredentialTemplate)
            .where(models.CredentialTemplate.organization_id == principal.organization_id)
            .order_by(models.CredentialTemplate.created_at)
        ).all()
    )


def get_template(
    session: Session, organization_id: uuid.UUID, template_id: uuid.UUID
) -> models.CredentialTemplate:
    template = session.get(models.CredentialTemplate, template_id)
    if template is None or template.organization_id != organization_id:
        raise NotFound("Template not found")
    return template


def get_template_by_slug(
    session: Session, organization_id: uuid.UUID, slug: str
) -> models.CredentialTemplate:
    template = session.scalar(
        select(models.CredentialTemplate)
        .where(models.CredentialTemplate.organization_id == organization_id)
        .where(models.CredentialTemplate.slug == slug)
        .where(models.CredentialTemplate.archived_at.is_(None))
    )
    if template is None:
        raise NotFound("Template not found")
    return template


def create_version(
    session: Session,
    principal: Principal,
    template_id: uuid.UUID,
    *,
    claims_schema: dict[str, Any],
    selective_disclosure: list[str],
    validity_days: int,
    display: dict[str, Any],
) -> models.TemplateVersion:
    template = get_template(session, principal.organization_id, template_id)
    validate_schema(claims_schema)
    allowed = selectable_paths(claims_schema)
    unknown = sorted(set(selective_disclosure) - allowed)
    if unknown:
        raise InvalidSchema("selective_disclosure paths not in schema", details=unknown)
    if not 1 <= validity_days <= 3650:
        raise AppError("validity_days must be between 1 and 3650")
    next_version = (
        int(
            session.scalar(
                select(func.coalesce(func.max(models.TemplateVersion.version), 0)).where(
                    models.TemplateVersion.template_id == template.id
                )
            )
            or 0
        )
        + 1
    )
    version = models.TemplateVersion(
        id=ids.uuid7(),
        organization_id=principal.organization_id,
        template_id=template.id,
        version=next_version,
        claims_schema=claims_schema,
        selective_disclosure=sorted(set(selective_disclosure)),
        validity_days=validity_days,
        display=display,
    )
    session.add(version)
    session.flush()
    audit.record(
        session,
        organization_id=principal.organization_id,
        actor=principal.audit_actor,
        action="template_version.created",
        target_type="template_version",
        target_id=version.id,
        metadata={"template_id": str(template.id), "version": next_version},
    )
    return version


def list_versions(
    session: Session, principal: Principal, template_id: uuid.UUID
) -> list[models.TemplateVersion]:
    get_template(session, principal.organization_id, template_id)
    return list(
        session.scalars(
            select(models.TemplateVersion)
            .where(models.TemplateVersion.template_id == template_id)
            .order_by(models.TemplateVersion.version)
        ).all()
    )


def publish_version(
    session: Session, principal: Principal, template_id: uuid.UUID, version_id: uuid.UUID
) -> models.TemplateVersion:
    get_template(session, principal.organization_id, template_id)
    version = session.get(models.TemplateVersion, version_id)
    if version is None or version.template_id != template_id:
        raise NotFound("Template version not found")
    if version.state == "published":
        return version
    version.state = "published"
    version.published_at = datetime.now(UTC)
    audit.record(
        session,
        organization_id=principal.organization_id,
        actor=principal.audit_actor,
        action="template_version.published",
        target_type="template_version",
        target_id=version.id,
        metadata={"version": version.version},
    )
    return version


def latest_published(
    session: Session, template: models.CredentialTemplate
) -> models.TemplateVersion:
    version = session.scalar(
        select(models.TemplateVersion)
        .where(models.TemplateVersion.template_id == template.id)
        .where(models.TemplateVersion.state == "published")
        .order_by(models.TemplateVersion.version.desc())
        .limit(1)
    )
    if version is None:
        raise AppError("The template has no published version", details={"slug": template.slug})
    return version


def published_templates(
    session: Session, organization_id: uuid.UUID
) -> list[tuple[models.CredentialTemplate, models.TemplateVersion]]:
    """Última versión publicada de cada plantilla activa (para los metadatos OID4VCI)."""
    out = []
    for template in session.scalars(
        select(models.CredentialTemplate)
        .where(models.CredentialTemplate.organization_id == organization_id)
        .where(models.CredentialTemplate.archived_at.is_(None))
        .order_by(models.CredentialTemplate.slug)
    ):
        version = session.scalar(
            select(models.TemplateVersion)
            .where(models.TemplateVersion.template_id == template.id)
            .where(models.TemplateVersion.state == "published")
            .order_by(models.TemplateVersion.version.desc())
            .limit(1)
        )
        if version is not None:
            out.append((template, version))
    return out
