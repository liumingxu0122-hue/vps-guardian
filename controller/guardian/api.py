from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from guardian import __version__
from guardian.agent_security import (
    lock_active_agent,
    normalize_certificate_fingerprint,
    normalize_certificate_serial,
    trusted_client_certificate_identity,
    verify_agent_request,
)
from guardian.audit import write_audit
from guardian.backup import (
    RecoveryPointNotFoundError,
    RecoveryPointPromotionConflict,
    RecoveryVerificationAttestation,
    promote_recovery_point,
)
from guardian.config import Settings, get_settings
from guardian.database import get_db
from guardian.events import event_broker
from guardian.models import (
    Agent,
    AgentIdentity,
    AgentIdentityState,
    AgentTask,
    Approval,
    ApprovalStatus,
    AuditLog,
    Host,
    Incident,
    MetricSnapshot,
    RecoveryPoint,
    Role,
    User,
)
from guardian.operations import Window, build_operations_overview
from guardian.reconciliation import reconcile_staging_heartbeat, record_agent_results
from guardian.redaction import redact_structure
from guardian.schemas import (
    AgentEnrollRequest,
    AgentEnrollResponse,
    AgentHeartbeat,
    AgentIdentityActivateRequest,
    AgentIdentityRetireRequest,
    AgentIdentityRevokeRequest,
    AgentIdentityValidateRequest,
    AgentIdentityView,
    AgentRotateRequest,
    AgentView,
    ApprovalDecision,
    ApprovalView,
    AuditView,
    HealthResponse,
    HostCreate,
    HostView,
    IncidentView,
    LoginRequest,
    LoginResponse,
    RecoveryPointPromotionView,
    RecoveryPointVerifyRequest,
    RecoveryPointView,
    UserView,
)
from guardian.security import (
    create_access_token,
    generate_csrf_token,
    login_limiter,
    require_role,
    verify_password,
    verify_totp,
)
from guardian.tasking import serialize_agent_task

router = APIRouter()


def approval_is_expired(approval: Approval, now: datetime) -> bool:
    expires_at = approval.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return expires_at <= now


def expire_pending_approvals(db: Session, *, now: datetime | None = None) -> int:
    checked_at = now or datetime.now(UTC)
    expired = 0
    approvals = db.scalars(
        select(Approval).where(Approval.status == ApprovalStatus.pending.value)
    ).all()
    for approval in approvals:
        if not approval_is_expired(approval, checked_at):
            continue
        approval.status = ApprovalStatus.expired.value
        approval.decided_at = checked_at
        write_audit(
            db,
            actor=None,
            action="approval.expired",
            resource_type="approval",
            resource_id=approval.id,
            outcome="rejected",
            details={"action": approval.action_name, "reason": "approval TTL elapsed"},
        )
        expired += 1
    if expired:
        db.commit()
    return expired
DB = Annotated[Session, Depends(get_db)]
Config = Annotated[Settings, Depends(get_settings)]


@router.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    return HealthResponse(version=__version__)


@router.get("/ready", response_model=HealthResponse, tags=["system"])
def readiness(db: DB) -> HealthResponse:
    """Verify the database connection and the controller's critical read paths."""
    for model in (Host, Agent, AgentIdentity, Incident, Approval, AuditLog, RecoveryPoint):
        db.execute(select(model.id).limit(1)).all()
    return HealthResponse(version=__version__)


@router.post("/api/v1/auth/login", response_model=LoginResponse, tags=["auth"])
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: DB,
    settings: Config,
) -> LoginResponse:
    source_ip = request.client.host if request.client else "unknown"
    limiter_key = f"{source_ip}:{payload.email.lower()}"
    login_limiter.check(limiter_key, settings.login_attempts_per_10m)
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        write_audit(
            db,
            actor=user,
            action="auth.login",
            resource_type="user",
            resource_id=user.id if user else None,
            outcome="denied",
            source_ip=source_ip,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="invalid credentials")
    if not verify_totp(user, payload.totp_code, settings):
        raise HTTPException(status_code=401, detail="TOTP required or invalid")
    token, ttl = create_access_token(user, settings)
    csrf = generate_csrf_token()
    response.set_cookie(
        "guardian_session",
        token,
        max_age=ttl,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        "guardian_csrf",
        csrf,
        max_age=ttl,
        httponly=False,
        secure=settings.secure_cookies,
        samesite="strict",
        path="/",
    )
    write_audit(
        db,
        actor=user,
        action="auth.login",
        resource_type="user",
        resource_id=user.id,
        outcome="success",
        source_ip=source_ip,
    )
    db.commit()
    login_limiter.reset(limiter_key)
    return LoginResponse(access_token=token, csrf_token=csrf, expires_in=ttl)


@router.post("/api/v1/auth/logout", status_code=204, tags=["auth"])
def logout(response: Response, user: Annotated[User, Depends(require_role(Role.viewer))]) -> None:
    response.delete_cookie("guardian_session", path="/")
    response.delete_cookie("guardian_csrf", path="/")


@router.get("/api/v1/auth/me", response_model=UserView, tags=["auth"])
def me(user: Annotated[User, Depends(require_role(Role.viewer))]) -> User:
    return user


@router.get("/api/v1/hosts", response_model=list[HostView], tags=["inventory"])
def list_hosts(db: DB, _: Annotated[User, Depends(require_role(Role.viewer))]) -> list[Host]:
    return list(db.scalars(select(Host).order_by(Host.name)).all())


@router.post("/api/v1/hosts", response_model=HostView, status_code=201, tags=["inventory"])
def create_host(
    payload: HostCreate,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.admin))],
) -> Host:
    if db.scalar(select(Host).where(Host.name == payload.name)):
        raise HTTPException(status_code=409, detail="host name already exists")
    host = Host(**payload.model_dump())
    db.add(host)
    db.flush()
    write_audit(
        db,
        actor=user,
        action="host.create",
        resource_type="host",
        resource_id=host.id,
        outcome="success",
        details={"name": host.name, "address": host.address},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return host


@router.get("/api/v1/overview", tags=["dashboard"])
def overview(
    db: DB,
    settings: Config,
    user: Annotated[User, Depends(require_role(Role.viewer))],
    window: Annotated[Window, Query()] = "24h",
    host_id: Annotated[str | None, Query(max_length=36)] = None,
) -> dict[str, object]:
    expire_pending_approvals(db)
    try:
        return build_operations_overview(
            db, settings=settings, user=user, window=window, host_id=host_id
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/v1/services", tags=["inventory"])
def list_services(
    db: DB, _: Annotated[User, Depends(require_role(Role.viewer))]
) -> list[dict[str, object]]:
    services: list[dict[str, object]] = []
    for host in db.scalars(select(Host).order_by(Host.name)).all():
        snapshot = db.scalar(
            select(MetricSnapshot)
            .where(MetricSnapshot.host_id == host.id)
            .order_by(desc(MetricSnapshot.collected_at))
            .limit(1)
        )
        if not snapshot:
            continue
        raw_services = snapshot.payload.get("_services", [])
        if not isinstance(raw_services, list):
            continue
        for item in raw_services[:100]:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind", "unknown"))[:80]
            summary = str(item.get("summary", ""))[:1000]
            services.append(
                {
                    "host_id": host.id,
                    "host_name": host.name,
                    "kind": kind,
                    "status": "failed" if kind == "systemd_failed" else "observed",
                    "summary": summary,
                    "collected_at": snapshot.collected_at.isoformat(),
                }
            )
    return services


@router.get("/api/v1/hosts/{host_id}/latest", tags=["inventory"])
def latest_host_snapshot(
    host_id: str,
    db: DB,
    _: Annotated[User, Depends(require_role(Role.viewer))],
) -> dict[str, object]:
    host = db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="host not found")
    snapshot = db.scalar(
        select(MetricSnapshot)
        .where(MetricSnapshot.host_id == host.id)
        .order_by(desc(MetricSnapshot.collected_at))
        .limit(1)
    )
    return {
        "host_id": host.id,
        "collected_at": snapshot.collected_at.isoformat() if snapshot else None,
        "payload": snapshot.payload if snapshot else {},
    }


@router.get("/api/v1/incidents", response_model=list[IncidentView], tags=["incidents"])
def list_incidents(
    db: DB, _: Annotated[User, Depends(require_role(Role.viewer))]
) -> list[Incident]:
    return list(
        db.scalars(select(Incident).order_by(desc(Incident.first_seen_at)).limit(200)).all()
    )


@router.get("/api/v1/approvals", response_model=list[ApprovalView], tags=["repairs"])
def list_approvals(
    db: DB, _: Annotated[User, Depends(require_role(Role.operator))]
) -> list[Approval]:
    expire_pending_approvals(db)
    return list(db.scalars(select(Approval).order_by(desc(Approval.requested_at)).limit(200)).all())


@router.post(
    "/api/v1/approvals/{approval_id}/decision", response_model=ApprovalView, tags=["repairs"]
)
async def decide_approval(
    approval_id: str,
    payload: ApprovalDecision,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.admin))],
) -> Approval:
    approval = db.get(Approval, approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="pending approval not found")
    now = datetime.now(UTC)
    if approval.status == ApprovalStatus.pending.value and approval_is_expired(approval, now):
        approval.status = ApprovalStatus.expired.value
        approval.decided_at = now
        write_audit(
            db,
            actor=user,
            action="approval.expired",
            resource_type="approval",
            resource_id=approval.id,
            outcome="rejected",
            details={"action": approval.action_name, "reason": "approval TTL elapsed"},
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        await event_broker.publish({"type": "approval.updated", "id": approval.id})
        raise HTTPException(status_code=409, detail="approval expired")
    if approval.status != ApprovalStatus.pending.value:
        raise HTTPException(status_code=404, detail="pending approval not found")
    approval.status = payload.decision
    approval.decided_at = now
    approval.decided_by = user.id
    write_audit(
        db,
        actor=user,
        action=f"approval.{payload.decision}",
        resource_type="approval",
        resource_id=approval.id,
        outcome="success",
        details={"confirmation": payload.confirmation, "action": approval.action_name},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    await event_broker.publish({"type": "approval.updated", "id": approval.id})
    return approval


@router.get("/api/v1/audit", response_model=list[AuditView], tags=["audit"])
def list_audit(db: DB, _: Annotated[User, Depends(require_role(Role.admin))]) -> list[AuditLog]:
    return list(db.scalars(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(500)).all())


@router.get(
    "/api/v1/recovery-points", response_model=list[RecoveryPointView], tags=["recovery"]
)
def list_recovery_points(
    db: DB, _: Annotated[User, Depends(require_role(Role.operator))]
) -> list[RecoveryPoint]:
    return list(
        db.scalars(
            select(RecoveryPoint).order_by(desc(RecoveryPoint.created_at)).limit(500)
        ).all()
    )


@router.post(
    "/api/v1/recovery-points/{recovery_point_id}/verify",
    response_model=RecoveryPointPromotionView,
    tags=["recovery"],
)
def verify_recovery_point(
    recovery_point_id: str,
    payload: RecoveryPointVerifyRequest,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.owner))],
) -> RecoveryPointPromotionView:
    attestation = RecoveryVerificationAttestation(
        schema_version=payload.attestation.schema_version,
        verifier=payload.attestation.verifier,
        verification_method=payload.attestation.verification_method,
        target_environment=payload.attestation.target_environment,
        completed_at=payload.attestation.completed_at,
        evidence_digest=payload.attestation.evidence_digest,
    )
    try:
        promotion = promote_recovery_point(
            db,
            recovery_point_id=recovery_point_id,
            expected_version=payload.expected_version,
            expected_snapshot_id=payload.expected_snapshot_id,
            expected_checksum=payload.expected_checksum,
            attestation=attestation,
        )
    except RecoveryPointNotFoundError as exc:
        raise HTTPException(status_code=404, detail="recovery point not found") from exc
    except RecoveryPointPromotionConflict as exc:
        write_audit(
            db,
            actor=user,
            action="recovery_point.verification_conflict",
            resource_type="recovery_point",
            resource_id=recovery_point_id,
            outcome="conflict",
            details={
                "expected_version": payload.expected_version,
                "snapshot_id_suffix": payload.expected_snapshot_id[-12:],
                "manifest_checksum": payload.expected_checksum,
                "attestation_digest": exc.attestation_digest,
            },
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=409, detail="recovery point verification conflict") from exc
    write_audit(
        db,
        actor=user,
        action="recovery_point.verification_promoted",
        resource_type="recovery_point",
        resource_id=recovery_point_id,
        outcome="success" if promotion.promoted else "idempotent",
        details={
            "verification_version": promotion.recovery_point.verification_version,
            "snapshot_id_suffix": promotion.recovery_point.snapshot_id[-12:],
            "manifest_checksum": promotion.recovery_point.checksum,
            "attestation_digest": promotion.attestation_digest,
        },
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return RecoveryPointPromotionView(
        recovery_point=RecoveryPointView.model_validate(promotion.recovery_point),
        promoted=promotion.promoted,
        attestation_digest=promotion.attestation_digest,
    )


@router.get("/api/v1/settings/public", tags=["system"])
def public_settings(
    settings: Config,
    _: Annotated[User, Depends(require_role(Role.admin))],
) -> dict[str, object]:
    return {
        "environment": settings.environment,
        "secure_cookies": settings.secure_cookies,
        "auto_create_schema": settings.auto_create_schema,
        "allowed_origins": settings.allowed_origins,
        "max_incident_log_bytes": settings.max_incident_log_bytes,
        "login_attempts_per_10m": settings.login_attempts_per_10m,
        "nonce_ttl_seconds": settings.nonce_ttl_seconds,
        "agent_offline_after_seconds": settings.agent_offline_after_seconds,
        "agent_pending_identity_ttl_minutes": settings.agent_pending_identity_ttl_minutes,
        "approval_ttl_minutes": settings.approval_ttl_minutes,
        "features": {
            "mtls": True,
            "request_signatures": True,
            "totp": True,
            "level2_default_enabled": False,
            "level3_requires_approval": True,
            "arbitrary_shell": False,
        },
    }


@router.get("/api/v1/agents", response_model=list[AgentView], tags=["agent"])
def list_agents(db: DB, _: Annotated[User, Depends(require_role(Role.admin))]) -> list[Agent]:
    return list(db.scalars(select(Agent).order_by(desc(Agent.last_heartbeat_at))).all())


@router.get(
    "/api/v1/agents/{agent_id}/identities",
    response_model=list[AgentIdentityView],
    tags=["agent"],
)
def list_agent_identities(
    agent_id: str,
    db: DB,
    _: Annotated[User, Depends(require_role(Role.admin))],
) -> list[AgentIdentity]:
    if db.get(Agent, agent_id) is None:
        raise HTTPException(status_code=404, detail="agent not found")
    return list(
        db.scalars(
            select(AgentIdentity)
            .where(AgentIdentity.agent_id == agent_id)
            .order_by(desc(AgentIdentity.generation))
        ).all()
    )


def claim_agent_identity_version(db: Session, agent: Agent, expected_version: int) -> int:
    result = cast(
        CursorResult[Any],
        db.execute(
            update(Agent)
            .where(
                Agent.id == agent.id,
                Agent.identity_version == expected_version,
                Agent.revoked_at.is_(None),
            )
            .values(identity_version=Agent.identity_version + 1)
            .execution_options(synchronize_session=False)
        )
    )
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="stale agent identity version")
    db.refresh(agent)
    return agent.identity_version


def pending_identity_is_expired(identity: AgentIdentity, now: datetime) -> bool:
    if identity.expires_at is None:
        return True
    expires_at = identity.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return expires_at <= now


@router.post(
    "/api/v1/agents/{agent_id}/rotate",
    tags=["agent"],
    deprecated=True,
    status_code=status.HTTP_410_GONE,
)
def reject_legacy_agent_rotation(
    agent_id: str,
    _: Annotated[User, Depends(require_role(Role.owner))],
) -> None:
    del agent_id
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail=(
            "single-step rotation is disabled; create, validate, and activate a pending identity"
        ),
    )


@router.post(
    "/api/v1/agents/{agent_id}/identities/pending",
    response_model=AgentIdentityView,
    tags=["agent"],
)
def prepare_agent_identity(
    agent_id: str,
    payload: AgentRotateRequest,
    request: Request,
    db: DB,
    settings: Config,
    user: Annotated[User, Depends(require_role(Role.owner))],
) -> AgentIdentity:
    agent = lock_active_agent(db, agent_id)
    fingerprint = normalize_certificate_fingerprint(payload.certificate_fingerprint)
    certificate_serial = normalize_certificate_serial(payload.certificate_serial)
    existing_rotation = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.agent_id == agent.id,
            AgentIdentity.rotation_id == payload.rotation_id,
        )
    )
    if existing_rotation:
        if (
            existing_rotation.signing_public_key != payload.signing_public_key
            or existing_rotation.certificate_fingerprint != fingerprint
            or existing_rotation.certificate_serial != certificate_serial
        ):
            write_audit(
                db,
                actor=user,
                action="agent.identity_rotation_conflict",
                resource_type="agent_identity",
                resource_id=existing_rotation.id,
                outcome="denied",
                details={
                    "agent_id": agent.id,
                    "rotation_id": payload.rotation_id,
                    "winning_generation": existing_rotation.generation,
                    "reason_code": "rotation_id_payload_mismatch",
                },
                source_ip=request.client.host if request.client else None,
            )
            db.commit()
            raise HTTPException(status_code=409, detail="rotation id payload conflict")
        write_audit(
            db,
            actor=user,
            action="agent.identity_rotation_replayed",
            resource_type="agent_identity",
            resource_id=existing_rotation.id,
            outcome="idempotent",
            details={
                "agent_id": agent.id,
                "rotation_id": payload.rotation_id,
                "generation": existing_rotation.generation,
            },
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        return existing_rotation
    if db.scalar(
        select(AgentIdentity).where(AgentIdentity.certificate_fingerprint == fingerprint)
    ):
        raise HTTPException(status_code=409, detail="certificate already enrolled")
    if db.scalar(
        select(AgentIdentity).where(AgentIdentity.certificate_serial == certificate_serial)
    ):
        raise HTTPException(status_code=409, detail="certificate serial already enrolled")
    existing_pending = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.agent_id == agent.id,
            AgentIdentity.state == AgentIdentityState.pending.value,
        )
    )
    created_at = datetime.now(UTC)
    if existing_pending and not pending_identity_is_expired(existing_pending, created_at):
        write_audit(
            db,
            actor=user,
            action="agent.identity_rotation_conflict",
            resource_type="agent_identity",
            resource_id=existing_pending.id,
            outcome="denied",
            details={
                "agent_id": agent.id,
                "rotation_id": payload.rotation_id,
                "winning_rotation_id": existing_pending.rotation_id,
                "winning_generation": existing_pending.generation,
                "reason_code": "pending_identity_exists",
            },
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=409, detail="agent already has a pending identity")
    try:
        generation = claim_agent_identity_version(db, agent, payload.expected_version)
        if existing_pending:
            existing_pending.state = AgentIdentityState.retired.value
            existing_pending.retired_at = created_at
            write_audit(
                db,
                actor=user,
                action="agent.identity_pending_expired",
                resource_type="agent_identity",
                resource_id=existing_pending.id,
                outcome="expired",
                details={
                    "agent_id": agent.id,
                    "generation": existing_pending.generation,
                    "certificate_fingerprint_suffix": existing_pending.certificate_fingerprint[
                        -12:
                    ],
                },
                source_ip=request.client.host if request.client else None,
            )
            db.flush()
        identity = AgentIdentity(
            agent_id=agent.id,
            generation=generation,
            rotation_id=payload.rotation_id,
            state=AgentIdentityState.pending.value,
            signing_public_key=payload.signing_public_key,
            certificate_fingerprint=fingerprint,
            certificate_serial=certificate_serial,
            expires_at=created_at
            + timedelta(minutes=settings.agent_pending_identity_ttl_minutes),
        )
        db.add(identity)
        db.flush()
        write_audit(
            db,
            actor=user,
            action="agent.identity_pending_created",
            resource_type="agent_identity",
            resource_id=identity.id,
            outcome="success",
            details={
                "agent_id": agent.id,
                "generation": generation,
                "rotation_id": payload.rotation_id,
                "certificate_fingerprint_suffix": fingerprint[-12:],
                "certificate_serial": certificate_serial,
            },
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409, detail="certificate identity already enrolled"
        ) from exc
    return identity


@router.post(
    "/api/v1/agents/{agent_id}/identities/{identity_id}/activate",
    response_model=AgentIdentityView,
    tags=["agent"],
)
def activate_agent_identity(
    agent_id: str,
    identity_id: str,
    payload: AgentIdentityActivateRequest,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.owner))],
) -> AgentIdentity:
    agent = lock_active_agent(db, agent_id)
    identity = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == identity_id,
            AgentIdentity.agent_id == agent.id,
        )
    )
    if not identity:
        raise HTTPException(status_code=404, detail="agent identity not found")
    if identity.state != AgentIdentityState.pending.value:
        raise HTTPException(status_code=409, detail="identity is not pending")
    activated_at = datetime.now(UTC)
    if pending_identity_is_expired(identity, activated_at):
        new_version = claim_agent_identity_version(db, agent, payload.expected_version)
        identity.state = AgentIdentityState.retired.value
        identity.retired_at = activated_at
        write_audit(
            db,
            actor=user,
            action="agent.identity_pending_expired",
            resource_type="agent_identity",
            resource_id=identity.id,
            outcome="expired",
            details={
                "agent_id": agent.id,
                "generation": identity.generation,
                "identity_version": new_version,
                "certificate_fingerprint_suffix": identity.certificate_fingerprint[-12:],
            },
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=409, detail="pending identity expired and was retired")
    if identity.verified_at is None or identity.successful_heartbeats < 2:
        raise HTTPException(
            status_code=409,
            detail="pending identity requires two consecutive authenticated heartbeats",
        )
    active_identity = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.agent_id == agent.id,
            AgentIdentity.state == AgentIdentityState.active.value,
        )
    )
    if not active_identity:
        raise HTTPException(status_code=409, detail="agent has no active identity")
    try:
        new_version = claim_agent_identity_version(db, agent, payload.expected_version)
        active_identity.state = AgentIdentityState.retiring.value
        active_identity.retiring_at = activated_at
        db.flush()
        identity.state = AgentIdentityState.active.value
        identity.activated_at = activated_at
        agent.signing_public_key = identity.signing_public_key
        agent.certificate_fingerprint = identity.certificate_fingerprint
        agent.certificate_serial = identity.certificate_serial
        write_audit(
            db,
            actor=user,
            action="agent.identity_activated",
            resource_type="agent_identity",
            resource_id=identity.id,
            outcome="success",
            details={
                "agent_id": agent.id,
                "generation": identity.generation,
                "identity_version": new_version,
                "previous_identity_id": active_identity.id,
                "previous_fingerprint_suffix": active_identity.certificate_fingerprint[-12:],
                "new_fingerprint_suffix": identity.certificate_fingerprint[-12:],
                "certificate_serial": identity.certificate_serial,
                "successful_heartbeats": identity.successful_heartbeats,
            },
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="identity activation conflict") from exc
    return identity


@router.post(
    "/api/v1/agents/{agent_id}/identities/{identity_id}/revoke",
    response_model=AgentIdentityView,
    tags=["agent"],
)
def revoke_retiring_agent_identity(
    agent_id: str,
    identity_id: str,
    payload: AgentIdentityRevokeRequest,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.owner))],
) -> AgentIdentity:
    agent = lock_active_agent(db, agent_id)
    identity = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == identity_id,
            AgentIdentity.agent_id == agent.id,
        )
    )
    if not identity:
        raise HTTPException(status_code=404, detail="agent identity not found")
    if identity.state == AgentIdentityState.revoked.value:
        return identity
    if identity.state != AgentIdentityState.retiring.value:
        raise HTTPException(status_code=409, detail="only a retiring identity can be revoked")
    new_version = claim_agent_identity_version(db, agent, payload.expected_version)
    identity.state = AgentIdentityState.revoked.value
    identity.revoked_at = datetime.now(UTC)
    write_audit(
        db,
        actor=user,
        action="agent.identity_revoked",
        resource_type="agent_identity",
        resource_id=identity.id,
        outcome="success",
        details={
            "agent_id": agent.id,
            "generation": identity.generation,
            "identity_version": new_version,
            "certificate_serial": identity.certificate_serial,
            "crl_number": payload.crl_number,
            "crl_sha256": payload.crl_sha256,
        },
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return identity


@router.post(
    "/api/v1/agents/{agent_id}/identities/{identity_id}/retire",
    response_model=AgentIdentityView,
    tags=["agent"],
)
def retire_pending_agent_identity(
    agent_id: str,
    identity_id: str,
    payload: AgentIdentityRetireRequest,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.owner))],
) -> AgentIdentity:
    agent = lock_active_agent(db, agent_id)
    identity = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == identity_id,
            AgentIdentity.agent_id == agent.id,
        )
    )
    if not identity:
        raise HTTPException(status_code=404, detail="agent identity not found")
    if identity.state != AgentIdentityState.pending.value:
        raise HTTPException(
            status_code=409,
            detail="only a pending identity can be retired directly",
        )
    retired_at = datetime.now(UTC)
    new_version = claim_agent_identity_version(db, agent, payload.expected_version)
    identity.state = AgentIdentityState.retired.value
    identity.retired_at = retired_at
    write_audit(
        db,
        actor=user,
        action="agent.identity_pending_retired",
        resource_type="agent_identity",
        resource_id=identity.id,
        outcome="success",
        details={
            "agent_id": agent.id,
            "generation": identity.generation,
            "identity_version": new_version,
            "reason_code": payload.reason_code,
            "certificate_fingerprint_suffix": identity.certificate_fingerprint[-12:],
        },
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return identity


@router.post(
    "/api/v1/agents/{agent_id}/identities/{identity_id}/validate",
    response_model=AgentIdentityView,
    tags=["agent"],
)
async def validate_pending_agent_identity(
    agent_id: str,
    identity_id: str,
    payload: AgentIdentityValidateRequest,
    request: Request,
    db: DB,
    settings: Config,
) -> AgentIdentity:
    agent = lock_active_agent(db, agent_id)
    identity = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == identity_id,
            AgentIdentity.agent_id == agent.id,
        )
    )
    if not identity:
        raise HTTPException(status_code=404, detail="agent identity not found")
    if identity.state != AgentIdentityState.pending.value:
        raise HTTPException(status_code=409, detail="identity is not pending")
    if pending_identity_is_expired(identity, datetime.now(UTC)):
        raise HTTPException(status_code=409, detail="pending identity expired")
    if payload.expected_version != agent.identity_version:
        raise HTTPException(status_code=409, detail="stale agent identity version")
    authenticated_identity = verify_agent_request(
        request=request,
        agent=agent,
        payload=await request.body(),
        db=db,
        settings=settings,
    )
    if authenticated_identity.id != identity.id:
        raise HTTPException(status_code=401, detail="pending identity proof mismatch")
    if identity.verified_at is None:
        identity.verified_at = datetime.now(UTC)
        write_audit(
            db,
            actor=None,
            action="agent.identity_possession_verified",
            resource_type="agent_identity",
            resource_id=identity.id,
            outcome="success",
            details={
                "agent_id": agent.id,
                "generation": identity.generation,
                "certificate_fingerprint_suffix": identity.certificate_fingerprint[-12:],
            },
            source_ip=request.client.host if request.client else None,
        )
    db.commit()
    return identity


@router.post("/api/v1/agents/{agent_id}/revoke", status_code=204, tags=["agent"])
def revoke_agent(
    agent_id: str,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.owner))],
) -> None:
    agent = lock_active_agent(db, agent_id)
    agent.revoked_at = datetime.now(UTC)
    write_audit(
        db,
        actor=user,
        action="agent.revoke",
        resource_type="agent",
        resource_id=agent.id,
        outcome="success",
        details={"certificate_fingerprint_suffix": agent.certificate_fingerprint[-12:]},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()


@router.get("/api/v1/events", tags=["events"])
def events(_: Annotated[User, Depends(require_role(Role.viewer))]) -> StreamingResponse:
    return StreamingResponse(event_broker.stream(), media_type="text/event-stream")


@router.post("/api/v1/agents/enroll", response_model=AgentEnrollResponse, tags=["agent"])
def enroll_agent(
    payload: AgentEnrollRequest,
    request: Request,
    db: DB,
    settings: Config,
    enrollment_token: Annotated[str | None, Header(alias="X-Enrollment-Token")] = None,
) -> AgentEnrollResponse:
    expected = settings.agent_enrollment_token.get_secret_value()
    if not enrollment_token or not secrets.compare_digest(enrollment_token, expected):
        raise HTTPException(status_code=401, detail="invalid enrollment token")
    fingerprint = normalize_certificate_fingerprint(payload.certificate_fingerprint)
    certificate_serial = None
    if settings.environment == "production":
        trusted_fingerprint, certificate_serial = trusted_client_certificate_identity(
            request,
            settings,
        )
        if not secrets.compare_digest(fingerprint, trusted_fingerprint):
            raise HTTPException(status_code=401, detail="enrollment certificate mismatch")
    if db.scalar(
        select(AgentIdentity).where(AgentIdentity.certificate_fingerprint == fingerprint)
    ):
        raise HTTPException(status_code=409, detail="certificate already enrolled")
    if certificate_serial and db.scalar(
        select(AgentIdentity).where(AgentIdentity.certificate_serial == certificate_serial)
    ):
        raise HTTPException(status_code=409, detail="certificate serial already enrolled")
    try:
        enrolled_at = datetime.now(UTC)
        host = db.scalar(select(Host).where(Host.name == payload.host.name))
        if not host:
            host = Host(**payload.host.model_dump())
            db.add(host)
            db.flush()
        agent = Agent(
            host_id=host.id,
            signing_public_key=payload.signing_public_key,
            certificate_fingerprint=fingerprint,
            certificate_serial=certificate_serial,
            version=payload.version,
        )
        db.add(agent)
        db.flush()
        db.add(
            AgentIdentity(
                agent_id=agent.id,
                generation=agent.identity_version,
                state=AgentIdentityState.active.value,
                signing_public_key=payload.signing_public_key,
                certificate_fingerprint=fingerprint,
                certificate_serial=certificate_serial,
                verified_at=enrolled_at,
                activated_at=enrolled_at,
            )
        )
        db.flush()
        write_audit(
            db,
            actor=None,
            action="agent.enroll",
            resource_type="agent",
            resource_id=agent.id,
            outcome="success",
            details={
                "host": host.name,
                "certificate_fingerprint_suffix": fingerprint[-12:],
                "certificate_serial": certificate_serial,
            },
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409, detail="certificate identity already enrolled"
        ) from exc
    return AgentEnrollResponse(agent_id=agent.id, host_id=host.id)


@router.post(
    "/api/v1/agents/{agent_id}/heartbeat", status_code=status.HTTP_202_ACCEPTED, tags=["agent"]
)
async def agent_heartbeat(
    agent_id: str,
    payload: AgentHeartbeat,
    request: Request,
    response: Response,
    db: DB,
    settings: Config,
) -> dict[str, object]:
    agent = lock_active_agent(db, agent_id)
    payload_bytes = await request.body()
    authenticated_identity = verify_agent_request(
        request=request,
        agent=agent,
        payload=payload_bytes,
        db=db,
        settings=settings,
    )
    now = datetime.now(UTC)
    if authenticated_identity.state == AgentIdentityState.pending.value:
        authenticated_identity.successful_heartbeats += 1
        authenticated_identity.last_pending_heartbeat_at = now
        if authenticated_identity.verified_at is None:
            authenticated_identity.verified_at = now
            write_audit(
                db,
                actor=None,
                action="agent.identity_possession_verified",
                resource_type="agent_identity",
                resource_id=authenticated_identity.id,
                outcome="success",
                details={
                    "agent_id": agent.id,
                    "generation": authenticated_identity.generation,
                    "certificate_fingerprint_suffix": (
                        authenticated_identity.certificate_fingerprint[-12:]
                    ),
                    "source": "authenticated_heartbeat",
                },
                source_ip=request.client.host if request.client else None,
            )
        if authenticated_identity.successful_heartbeats == 2:
            write_audit(
                db,
                actor=None,
                action="agent.identity_heartbeat_threshold_met",
                resource_type="agent_identity",
                resource_id=authenticated_identity.id,
                outcome="success",
                details={
                    "agent_id": agent.id,
                    "generation": authenticated_identity.generation,
                    "successful_heartbeats": 2,
                },
                source_ip=request.client.host if request.client else None,
            )
        db.commit()
        response.status_code = status.HTTP_425_TOO_EARLY
        return {
            "accepted": False,
            "server_time": now.isoformat(),
            "identity_state": authenticated_identity.state,
            "identity_version": agent.identity_version,
            "tasks": [],
        }
    was_offline = agent.host.status == "offline"
    agent.last_heartbeat_at = now
    agent.version = payload.version
    agent.host.last_seen_at = now
    agent.host.status = "healthy"
    if was_offline:
        write_audit(
            db,
            actor=None,
            action="host.online",
            resource_type="host",
            resource_id=agent.host_id,
            outcome="recovered",
            details={"source": "authenticated_agent_heartbeat"},
            source_ip=request.client.host if request.client else None,
        )
    snapshot_payload: dict[str, object] = dict(payload.metrics)
    snapshot_payload["_services"] = payload.services
    snapshot_payload["_events"] = payload.events
    redacted_payload = redact_structure(snapshot_payload)
    if not isinstance(redacted_payload, dict):
        raise HTTPException(status_code=422, detail="invalid metric payload")
    db.add(
        MetricSnapshot(
            host_id=agent.host_id,
            collected_at=payload.collected_at,
            payload=redacted_payload,
        )
    )
    record_agent_results(db, agent, payload.events)
    reconcile_staging_heartbeat(db, agent=agent, payload=payload, settings=settings)
    tasks = list(
        db.scalars(
            select(AgentTask)
            .where(
                AgentTask.agent_id == agent.id,
                AgentTask.status.in_(["pending", "delivered"]),
                AgentTask.expires_at > now,
            )
            .order_by(AgentTask.created_at)
            .limit(10)
        ).all()
    )
    for task in tasks:
        task.status = "delivered"
    serialized_tasks = [serialize_agent_task(task) for task in tasks]
    db.commit()
    await event_broker.publish({"type": "host.heartbeat", "host_id": agent.host_id})
    return {
        "accepted": True,
        "server_time": now.isoformat(),
        "identity_state": authenticated_identity.state,
        "identity_version": agent.identity_version,
        "tasks": serialized_tasks,
    }
