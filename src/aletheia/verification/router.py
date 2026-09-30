"""``/v1/trust-policies``, ``/v1/presentation-requests``, ``/v1/verifications``."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BaseModel, Field

from ..api.deps import BackendDep, SessionDep, require
from ..api.routing import TransactionalRoute
from ..authz.permissions import Permission
from ..authz.service import Principal
from ..platform.config import Settings
from . import service

router = APIRouter(route_class=TransactionalRoute, prefix="/v1", tags=["verification"])


def _settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


class PolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    accepted_vcts: list[str] = Field(default_factory=list, max_length=100)
    required_claims: list[str] = Field(default_factory=list, max_length=100)
    require_holder_binding: bool = True
    require_status: bool = True
    max_status_age_seconds: int = Field(default=900, ge=1, le=86_400)
    clock_skew_seconds: int = Field(default=60, ge=0, le=300)
    max_kb_age_seconds: int = Field(default=300, ge=1, le=3600)


class TrustedIssuerResponse(BaseModel):
    id: uuid.UUID
    issuer: str
    hosted_org_id: uuid.UUID | None
    note: str | None
    created_at: datetime


class PolicyResponse(PolicyCreate):
    id: uuid.UUID
    trusted_issuers: list[TrustedIssuerResponse]
    created_at: datetime


class TrustedIssuerCreate(BaseModel):
    issuer: str = Field(min_length=8, max_length=2048)
    note: str | None = Field(default=None, max_length=500)


class PresentationRequestCreate(BaseModel):
    trust_policy_id: uuid.UUID


class PresentationRequestResponse(BaseModel):
    id: uuid.UUID
    trust_policy_id: uuid.UUID
    nonce: str
    aud: str
    expires_at: datetime


class VerificationCreate(BaseModel):
    presentation: str = Field(min_length=1, max_length=65_536)
    presentation_request_id: uuid.UUID | None = None
    trust_policy_id: uuid.UUID | None = None


class VerificationResponse(BaseModel):
    id: uuid.UUID
    result: str
    reason: str | None
    checks: list[dict[str, str]]
    issuer: str | None
    vct: str | None
    kid: str | None
    holder_binding_verified: bool
    disclosed_claims: dict[str, Any] | None
    credential_id: uuid.UUID | None


class VerificationRecordResponse(BaseModel):
    id: uuid.UUID
    presentation_request_id: uuid.UUID | None
    result: str
    checks: list[dict[str, str]]
    issuer: str | None
    vct: str | None
    credential_id: uuid.UUID | None
    created_at: datetime


def _policy(session: SessionDep, policy: Any) -> PolicyResponse:
    issuers = [
        TrustedIssuerResponse.model_validate(t, from_attributes=True)
        for t in service.list_trusted_issuers(session, policy)
    ]
    return PolicyResponse(
        id=policy.id,
        name=policy.name,
        accepted_vcts=policy.accepted_vcts,
        required_claims=policy.required_claims,
        require_holder_binding=policy.require_holder_binding,
        require_status=policy.require_status,
        max_status_age_seconds=policy.max_status_age_seconds,
        clock_skew_seconds=policy.clock_skew_seconds,
        max_kb_age_seconds=policy.max_kb_age_seconds,
        trusted_issuers=issuers,
        created_at=policy.created_at,
    )


@router.get("/trust-policies", response_model=list[PolicyResponse])
def list_policies(
    principal: Annotated[Principal, Depends(require(Permission.VERIFICATIONS_CREATE))],
    session: SessionDep,
) -> list[PolicyResponse]:
    return [_policy(session, p) for p in service.list_policies(session, principal)]


@router.post("/trust-policies", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
def create_policy(
    body: PolicyCreate,
    principal: Annotated[Principal, Depends(require(Permission.TRUST_POLICIES_WRITE))],
    session: SessionDep,
) -> PolicyResponse:
    return _policy(session, service.create_policy(session, principal, body.model_dump()))


@router.get("/trust-policies/{policy_id}", response_model=PolicyResponse)
def get_policy(
    policy_id: uuid.UUID,
    principal: Annotated[Principal, Depends(require(Permission.VERIFICATIONS_CREATE))],
    session: SessionDep,
) -> PolicyResponse:
    return _policy(session, service.get_policy(session, principal, policy_id))


@router.post(
    "/trust-policies/{policy_id}/issuers",
    response_model=TrustedIssuerResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_trusted_issuer(
    policy_id: uuid.UUID,
    body: TrustedIssuerCreate,
    principal: Annotated[Principal, Depends(require(Permission.TRUST_POLICIES_WRITE))],
    session: SessionDep,
    request: Request,
) -> TrustedIssuerResponse:
    trusted = service.add_trusted_issuer(
        session, principal, _settings(request), policy_id, issuer=body.issuer, note=body.note
    )
    return TrustedIssuerResponse.model_validate(trusted, from_attributes=True)


@router.delete(
    "/trust-policies/{policy_id}/issuers/{trusted_id}", status_code=status.HTTP_204_NO_CONTENT
)
def remove_trusted_issuer(
    policy_id: uuid.UUID,
    trusted_id: uuid.UUID,
    principal: Annotated[Principal, Depends(require(Permission.TRUST_POLICIES_WRITE))],
    session: SessionDep,
) -> None:
    service.remove_trusted_issuer(session, principal, policy_id, trusted_id)


@router.post(
    "/presentation-requests",
    response_model=PresentationRequestResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_presentation_request(
    body: PresentationRequestCreate,
    principal: Annotated[Principal, Depends(require(Permission.VERIFICATIONS_CREATE))],
    session: SessionDep,
    request: Request,
) -> PresentationRequestResponse:
    pr, nonce = service.create_presentation_request(
        session, principal, _settings(request), body.trust_policy_id
    )
    return PresentationRequestResponse(
        id=pr.id,
        trust_policy_id=pr.trust_policy_id,
        nonce=nonce,
        aud=pr.aud,
        expires_at=pr.expires_at,
    )


@router.post("/verifications", response_model=VerificationResponse)
def create_verification(
    body: VerificationCreate,
    principal: Annotated[Principal, Depends(require(Permission.VERIFICATIONS_CREATE))],
    session: SessionDep,
    backend: BackendDep,
    request: Request,
) -> VerificationResponse:
    report, record = service.verify(
        session,
        principal,
        _settings(request),
        backend,
        presentation=body.presentation,
        presentation_request_id=body.presentation_request_id,
        policy_id=body.trust_policy_id,
    )
    return VerificationResponse(
        id=record.id,
        result=report.result.value,
        reason=report.reason,
        checks=record.checks,
        issuer=report.issuer,
        vct=report.vct,
        kid=report.kid,
        holder_binding_verified=report.holder_binding_verified,
        disclosed_claims=report.disclosed_claims,
        credential_id=record.credential_ref,
    )


@router.get("/verifications", response_model=list[VerificationRecordResponse])
def list_verifications(
    principal: Annotated[Principal, Depends(require(Permission.VERIFICATIONS_CREATE))],
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[VerificationRecordResponse]:
    return [
        VerificationRecordResponse(
            id=r.id,
            presentation_request_id=r.presentation_request_id,
            result=r.result,
            checks=r.checks,
            issuer=r.issuer,
            vct=r.vct,
            credential_id=r.credential_ref,
            created_at=r.created_at,
        )
        for r in service.list_records(session, principal, limit=limit)
    ]
