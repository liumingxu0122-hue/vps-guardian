from __future__ import annotations

import csv
import io
import json
import secrets
import shlex
import time
import uuid
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Annotated, Any, Literal, cast

import pyotp
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, desc, func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from guardian import __version__
from guardian.agent_pki import (
    AgentCertificateError,
    issue_agent_certificate,
    validate_agent_csr,
    validate_agent_gateway_url,
    verify_signing_key_proof,
)
from guardian.agent_security import (
    lock_active_agent,
    normalize_certificate_fingerprint,
    normalize_certificate_serial,
    require_trusted_agent_gateway,
    trusted_client_certificate_identity,
    verify_agent_request,
)
from guardian.alerting import acknowledge_alert, silence_alert
from guardian.audit import write_audit
from guardian.backup import (
    RecoveryPointNotFoundError,
    RecoveryPointPromotionConflict,
    RecoveryVerificationAttestation,
    promote_recovery_point,
)
from guardian.config import Settings, get_settings
from guardian.dashboard import (
    current_resource_summary,
    dashboard_bootstrap,
    security_summary,
    topology_summary,
)
from guardian.database import get_db
from guardian.enrollment import (
    EnrollmentRateLimitError,
    EnrollmentTokenError,
    consume_enrollment_token,
    enrollment_limiter,
    issue_enrollment_token,
    revoke_enrollment_token,
    token_digest,
)
from guardian.events import event_broker
from guardian.identity import (
    active_recovery_code_count,
    consume_recovery_code,
    create_user_session,
    forced_setup_required,
    generate_recovery_code_batch,
    revoke_sessions,
)
from guardian.models import (
    Agent,
    AgentIdentity,
    AgentIdentityState,
    AgentTask,
    AlertInstance,
    AlertRule,
    AlertTransition,
    Approval,
    ApprovalStatus,
    AuditLog,
    Host,
    Incident,
    IncidentStatus,
    MetricSnapshot,
    NotificationChannel,
    NotificationDelivery,
    RecoveryCode,
    RecoveryPoint,
    RepairAttempt,
    Role,
    ServiceCheck,
    ServiceCheckResult,
    User,
    UserSession,
)
from guardian.monitoring import assigned_agent_checks, record_agent_check_results
from guardian.notifications import NotificationConfigurationError, send_test_notification
from guardian.operations import Window, build_operations_overview
from guardian.reconciliation import reconcile_staging_heartbeat, record_agent_results
from guardian.redaction import redact_serialized_text, redact_structure
from guardian.schemas import (
    AgentBootstrapRequest,
    AgentBootstrapResponse,
    AgentEnrollRequest,
    AgentEnrollResponse,
    AgentHeartbeat,
    AgentIdentityActivateRequest,
    AgentIdentityRetireRequest,
    AgentIdentityRevokeRequest,
    AgentIdentityValidateRequest,
    AgentIdentityView,
    AgentRenewRequest,
    AgentRenewResponse,
    AgentRotateRequest,
    AgentView,
    AlertRuleCreate,
    AlertRuleView,
    AlertSilenceRequest,
    AlertUpdateRequest,
    AlertView,
    ApprovalActorView,
    ApprovalDecision,
    ApprovalDetailView,
    ApprovalEvidenceView,
    ApprovalFactView,
    ApprovalStepView,
    ApprovalSummaryView,
    ApprovalTargetView,
    ApprovalTimelineEntryView,
    ApprovalView,
    AuditEvidenceView,
    AuditPresentationView,
    AuditView,
    EnrollmentTokenIssue,
    EnrollmentTokenView,
    HealthResponse,
    HostBatchUpdate,
    HostCreate,
    HostPresentationView,
    HostUpdate,
    HostView,
    IncidentUpdateRequest,
    IncidentView,
    LoginRequest,
    LoginResponse,
    NotificationChannelCreate,
    NotificationChannelView,
    NotificationDeliveryView,
    PasswordChangeRequest,
    ReauthenticationRequest,
    RecoveryCodeBatchView,
    RecoveryCodesConfirmRequest,
    RecoveryCodeStatusView,
    RecoveryPointPromotionView,
    RecoveryPointVerifyRequest,
    RecoveryPointView,
    ServiceCheckCreate,
    ServiceCheckResultView,
    ServiceCheckUpdate,
    ServiceCheckView,
    TotpConfirmRequest,
    TotpSetupView,
    UserCreate,
    UserDeleteRequest,
    UserPasswordReset,
    UserSessionView,
    UserUpdate,
    UserView,
)
from guardian.security import (
    create_access_token,
    decrypt_sensitive,
    encrypt_sensitive,
    generate_csrf_token,
    hash_password,
    login_limiter,
    require_role,
    totp_counter_for_code,
    verify_password,
    verify_totp,
    verify_user_password,
)
from guardian.service_semantics import classify_service_observation
from guardian.stability import StabilityWindow, build_stability_report
from guardian.tasking import create_agent_task, serialize_agent_task

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
    email = payload.email.strip().lower()
    limiter_key = f"{source_ip}:{email}"
    try:
        login_limiter.check(limiter_key, settings.login_attempts_per_10m)
    except HTTPException:
        write_audit(
            db,
            actor=None,
            action="auth.login",
            resource_type="user",
            resource_id=None,
            outcome="denied",
            details={"reason": "rate_limited"},
            source_ip=source_ip,
        )
        db.commit()
        raise
    user = db.scalar(select(User).where(User.email == email).with_for_update())
    password_valid = verify_user_password(payload.password, user)
    if not user or not user.is_active or not password_valid:
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
    if payload.totp_code and payload.recovery_code:
        write_audit(
            db,
            actor=user,
            action="auth.login",
            resource_type="user",
            resource_id=user.id,
            outcome="denied",
            details={"reason": "multiple_second_factors"},
            source_ip=source_ip,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="invalid credentials")

    recovery_remaining: int | None = None
    if payload.recovery_code:
        recovered, recovery_remaining = consume_recovery_code(
            db,
            user=user,
            value=payload.recovery_code,
            settings=settings,
        )
        write_audit(
            db,
            actor=user,
            action="auth.recovery_code",
            resource_type="user",
            resource_id=user.id,
            outcome="success" if recovered else "denied",
            details={
                "remaining": recovery_remaining,
                "security_reminder": recovery_remaining <= 2,
            },
            source_ip=source_ip,
        )
        if not recovered:
            db.commit()
            raise HTTPException(status_code=401, detail="invalid credentials")
    elif user.totp_enabled:
        if not verify_totp(user, payload.totp_code, settings):
            write_audit(
                db,
                actor=user,
                action="auth.login",
                resource_type="user",
                resource_id=user.id,
                outcome="denied",
                details={"reason": "second_factor_invalid"},
                source_ip=source_ip,
            )
            db.commit()
            raise HTTPException(status_code=401, detail="invalid credentials")
        secret = decrypt_sensitive(user.totp_secret_encrypted or "", settings)
        user.last_totp_counter = totp_counter_for_code(secret, payload.totp_code)
    elif payload.totp_code:
        write_audit(
            db,
            actor=user,
            action="auth.login",
            resource_type="user",
            resource_id=user.id,
            outcome="denied",
            details={"reason": "unexpected_second_factor"},
            source_ip=source_ip,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="invalid credentials")

    user.last_login_at = datetime.now(UTC)
    auth_session = create_user_session(
        db,
        user=user,
        request=request,
        settings=settings,
    )
    token, ttl = create_access_token(user, settings, session_id=auth_session.id)
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
    return LoginResponse(
        access_token=token,
        csrf_token=csrf,
        expires_in=ttl,
        identity_setup_required=forced_setup_required(user),
        recovery_codes_remaining=recovery_remaining,
    )


@router.post("/api/v1/auth/logout", status_code=204, tags=["auth"])
def logout(
    request: Request,
    response: Response,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.viewer))],
) -> None:
    auth_session = cast(UserSession, request.state.auth_session)
    auth_session.revoked_at = datetime.now(UTC)
    auth_session.revoked_by = user.id
    auth_session.revoke_reason = "logout"
    write_audit(
        db,
        actor=user,
        action="session.revoke",
        resource_type="session",
        resource_id=auth_session.id,
        outcome="success",
        details={"reason": "logout"},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    response.delete_cookie("guardian_session", path="/")
    response.delete_cookie("guardian_csrf", path="/")


@router.get("/api/v1/auth/me", response_model=UserView, tags=["auth"])
def me(user: Annotated[User, Depends(require_role(Role.viewer))]) -> User:
    return user


def _replace_auth_cookies(
    response: Response,
    *,
    token: str,
    csrf: str,
    ttl: int,
    settings: Settings,
) -> None:
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


@router.post(
    "/api/v1/auth/change-password",
    response_model=LoginResponse,
    tags=["auth"],
)
def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    response: Response,
    db: DB,
    settings: Config,
    user: Annotated[User, Depends(require_role(Role.viewer))],
) -> LoginResponse:
    source_ip = request.client.host if request.client else None
    db.refresh(user, with_for_update=True)
    if not verify_password(payload.current_password, user.password_hash):
        write_audit(
            db,
            actor=user,
            action="user.password_change",
            resource_type="user",
            resource_id=user.id,
            outcome="rejected",
            details={"reason": "reauthentication_failed"},
            source_ip=source_ip,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="current password is invalid")
    if verify_password(payload.new_password, user.password_hash):
        write_audit(
            db,
            actor=user,
            action="user.password_change",
            resource_type="user",
            resource_id=user.id,
            outcome="rejected",
            details={"reason": "password_reuse"},
            source_ip=source_ip,
        )
        db.commit()
        raise HTTPException(status_code=409, detail="new password must be different")
    current = cast(UserSession, request.state.auth_session)
    user.password_hash = hash_password(payload.new_password)
    user.password_changed_at = datetime.now(UTC)
    user.must_change_password = False
    user.session_version += 1
    revoked = revoke_sessions(
        db,
        user_id=user.id,
        actor_id=user.id,
        reason="password_changed",
        except_session_id=current.id,
    )
    current.session_version = user.session_version
    token, ttl = create_access_token(user, settings, session_id=current.id)
    csrf = generate_csrf_token()
    _replace_auth_cookies(response, token=token, csrf=csrf, ttl=ttl, settings=settings)
    write_audit(
        db,
        actor=user,
        action="user.password_change",
        resource_type="user",
        resource_id=user.id,
        outcome="success",
        details={"revoked_other_sessions": revoked, "retained_current_session": True},
        source_ip=source_ip,
    )
    db.commit()
    return LoginResponse(
        access_token=token,
        csrf_token=csrf,
        expires_in=ttl,
        identity_setup_required=forced_setup_required(user),
    )


@router.post(
    "/api/v1/auth/totp/setup",
    response_model=TotpSetupView,
    tags=["auth"],
)
def setup_totp(
    payload: ReauthenticationRequest,
    request: Request,
    db: DB,
    settings: Config,
    user: Annotated[User, Depends(require_role(Role.viewer))],
) -> TotpSetupView:
    _require_reauthentication_audited(
        db, user, payload.current_password, "totp.setup_begin", request
    )
    if user.totp_enabled:
        write_audit(
            db,
            actor=user,
            action="totp.setup_begin",
            resource_type="user",
            resource_id=user.id,
            outcome="rejected",
            details={"reason": "already_enabled"},
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=409, detail="TOTP is already enabled")
    secret = pyotp.random_base32()
    user.totp_pending_secret_encrypted = encrypt_sensitive(secret, settings)
    user.totp_pending_created_at = datetime.now(UTC)
    write_audit(
        db,
        actor=user,
        action="totp.setup_begin",
        resource_type="user",
        resource_id=user.id,
        outcome="success",
        details={"displayed_once": True},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return TotpSetupView(
        secret=secret,
        provisioning_uri=pyotp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name="VPS Guardian",
        ),
    )


@router.post(
    "/api/v1/auth/totp/enable",
    response_model=RecoveryCodeBatchView,
    tags=["auth"],
)
def enable_totp(
    payload: TotpConfirmRequest,
    request: Request,
    db: DB,
    settings: Config,
    user: Annotated[User, Depends(require_role(Role.viewer))],
) -> RecoveryCodeBatchView:
    _require_reauthentication_audited(db, user, payload.current_password, "totp.enable", request)
    if not user.totp_pending_secret_encrypted or not user.totp_pending_created_at:
        write_audit(
            db,
            actor=user,
            action="totp.enable",
            resource_type="user",
            resource_id=user.id,
            outcome="rejected",
            details={"reason": "setup_not_started"},
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=409, detail="start TOTP setup first")
    pending_at = user.totp_pending_created_at
    if pending_at.tzinfo is None:
        pending_at = pending_at.replace(tzinfo=UTC)
    if pending_at < datetime.now(UTC) - timedelta(minutes=10):
        user.totp_pending_secret_encrypted = None
        user.totp_pending_created_at = None
        write_audit(
            db,
            actor=user,
            action="totp.enable",
            resource_type="user",
            resource_id=user.id,
            outcome="rejected",
            details={"reason": "setup_expired"},
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=409, detail="TOTP setup expired")
    secret = decrypt_sensitive(user.totp_pending_secret_encrypted, settings)
    counter = totp_counter_for_code(secret, payload.totp_code)
    if counter is None:
        write_audit(
            db,
            actor=user,
            action="totp.enable",
            resource_type="user",
            resource_id=user.id,
            outcome="rejected",
            details={"reason": "confirmation_code_invalid"},
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="TOTP confirmation is invalid")
    user.totp_secret_encrypted = user.totp_pending_secret_encrypted
    user.totp_pending_secret_encrypted = None
    user.totp_pending_created_at = None
    user.totp_enabled = True
    user.totp_enabled_at = datetime.now(UTC)
    user.last_totp_counter = counter
    user.recovery_codes_confirmed_at = None
    codes = generate_recovery_code_batch(db, user=user, settings=settings)
    write_audit(
        db,
        actor=user,
        action="totp.enable",
        resource_type="user",
        resource_id=user.id,
        outcome="success",
        details={"recovery_code_count": len(codes), "displayed_once": True},
        source_ip=request.client.host if request.client else None,
    )
    write_audit(
        db,
        actor=user,
        action="recovery_codes.generate",
        resource_type="user",
        resource_id=user.id,
        outcome="success",
        details={"recovery_code_count": len(codes), "displayed_once": True},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return RecoveryCodeBatchView(codes=codes, remaining=len(codes))


@router.post(
    "/api/v1/auth/recovery-codes/confirm",
    response_model=RecoveryCodeStatusView,
    tags=["auth"],
)
def confirm_recovery_codes(
    _: RecoveryCodesConfirmRequest,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.viewer))],
) -> RecoveryCodeStatusView:
    remaining = active_recovery_code_count(db, user.id)
    if not user.totp_enabled or remaining == 0:
        write_audit(
            db,
            actor=user,
            action="recovery_codes.confirm_saved",
            resource_type="user",
            resource_id=user.id,
            outcome="rejected",
            details={"reason": "codes_unavailable"},
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=409, detail="recovery codes are not available")
    user.recovery_codes_confirmed_at = datetime.now(UTC)
    write_audit(
        db,
        actor=user,
        action="recovery_codes.confirm_saved",
        resource_type="user",
        resource_id=user.id,
        outcome="success",
        details={"remaining": remaining},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return RecoveryCodeStatusView(remaining=remaining, low=remaining <= 2)


@router.get(
    "/api/v1/auth/recovery-codes",
    response_model=RecoveryCodeStatusView,
    tags=["auth"],
)
def recovery_code_status(
    db: DB,
    user: Annotated[User, Depends(require_role(Role.viewer))],
) -> RecoveryCodeStatusView:
    remaining = active_recovery_code_count(db, user.id)
    return RecoveryCodeStatusView(remaining=remaining, low=remaining <= 2)


@router.post(
    "/api/v1/auth/recovery-codes/regenerate",
    response_model=RecoveryCodeBatchView,
    tags=["auth"],
)
def regenerate_recovery_codes(
    payload: TotpConfirmRequest,
    request: Request,
    db: DB,
    settings: Config,
    user: Annotated[User, Depends(require_role(Role.viewer))],
) -> RecoveryCodeBatchView:
    _require_reauthentication_audited(
        db, user, payload.current_password, "recovery_codes.regenerate", request
    )
    if not verify_totp(user, payload.totp_code, settings):
        write_audit(
            db,
            actor=user,
            action="recovery_codes.regenerate",
            resource_type="user",
            resource_id=user.id,
            outcome="rejected",
            details={"reason": "second_factor_invalid"},
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="TOTP confirmation is invalid")
    secret = decrypt_sensitive(user.totp_secret_encrypted or "", settings)
    user.last_totp_counter = totp_counter_for_code(secret, payload.totp_code)
    codes = generate_recovery_code_batch(db, user=user, settings=settings)
    user.recovery_codes_confirmed_at = None
    write_audit(
        db,
        actor=user,
        action="recovery_codes.regenerate",
        resource_type="user",
        resource_id=user.id,
        outcome="success",
        details={"recovery_code_count": len(codes), "displayed_once": True},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return RecoveryCodeBatchView(codes=codes, remaining=len(codes))


@router.post("/api/v1/auth/totp/disable", status_code=204, tags=["auth"])
def disable_totp(
    payload: TotpConfirmRequest,
    request: Request,
    db: DB,
    settings: Config,
    user: Annotated[User, Depends(require_role(Role.viewer))],
) -> None:
    _require_reauthentication_audited(db, user, payload.current_password, "totp.disable", request)
    if not user.totp_enabled or not verify_totp(user, payload.totp_code, settings):
        write_audit(
            db,
            actor=user,
            action="totp.disable",
            resource_type="user",
            resource_id=user.id,
            outcome="rejected",
            details={"reason": "second_factor_invalid"},
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=401, detail="TOTP confirmation is invalid")
    now = datetime.now(UTC)
    user.totp_enabled = False
    user.totp_enabled_at = None
    user.totp_secret_encrypted = None
    user.last_totp_counter = None
    user.recovery_codes_confirmed_at = None
    db.execute(
        update(RecoveryCode)
        .where(
            RecoveryCode.user_id == user.id,
            RecoveryCode.used_at.is_(None),
            RecoveryCode.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    user.session_version += 1
    revoked = revoke_sessions(
        db,
        user_id=user.id,
        actor_id=user.id,
        reason="totp_disabled",
    )
    write_audit(
        db,
        actor=user,
        action="totp.disable",
        resource_type="user",
        resource_id=user.id,
        outcome="success",
        details={"sessions_revoked": revoked},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()


def _session_view(row: UserSession, current_id: str | None = None) -> UserSessionView:
    return UserSessionView.model_validate(row).model_copy(update={"current": row.id == current_id})


@router.get(
    "/api/v1/auth/sessions",
    response_model=list[UserSessionView],
    tags=["auth"],
)
def own_sessions(
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.viewer))],
) -> list[UserSessionView]:
    current = cast(UserSession, request.state.auth_session)
    rows = db.scalars(
        select(UserSession)
        .where(
            UserSession.user_id == user.id,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > datetime.now(UTC),
        )
        .order_by(desc(UserSession.issued_at))
    ).all()
    return [_session_view(row, current.id) for row in rows]


@router.delete("/api/v1/auth/sessions/{session_id}", status_code=204, tags=["auth"])
def revoke_own_other_session(
    session_id: str,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.viewer))],
) -> None:
    current = cast(UserSession, request.state.auth_session)
    if session_id == current.id:
        raise HTTPException(status_code=409, detail="use logout to revoke the current session")
    target = db.scalar(
        select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == user.id,
        )
    )
    if target is None:
        raise HTTPException(status_code=404, detail="session not found")
    if target.revoked_at is None:
        target.revoked_at = datetime.now(UTC)
        target.revoked_by = user.id
        target.revoke_reason = "user_revoke"
    write_audit(
        db,
        actor=user,
        action="session.revoke",
        resource_type="session",
        resource_id=target.id,
        outcome="success",
        details={"reason": "user_revoke"},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()


@router.get(
    "/api/v1/users/{user_id}/sessions",
    response_model=list[UserSessionView],
    tags=["users"],
)
def list_user_sessions(
    user_id: str,
    db: DB,
    _: Annotated[User, Depends(require_role(Role.admin))],
) -> list[UserSessionView]:
    if db.get(User, user_id) is None:
        raise HTTPException(status_code=404, detail="user not found")
    return [
        _session_view(row)
        for row in db.scalars(
            select(UserSession)
            .where(
                UserSession.user_id == user_id,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > datetime.now(UTC),
            )
            .order_by(desc(UserSession.issued_at))
        ).all()
    ]


@router.delete(
    "/api/v1/users/{user_id}/sessions/{session_id}",
    status_code=204,
    tags=["users"],
)
def revoke_user_session(
    user_id: str,
    session_id: str,
    request: Request,
    db: DB,
    actor: Annotated[User, Depends(require_role(Role.admin))],
) -> None:
    target_user = db.get(User, user_id)
    active_sessions = list(
        db.scalars(
            select(UserSession)
            .where(
                UserSession.user_id == user_id,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > datetime.now(UTC),
            )
            .order_by(UserSession.id)
            .with_for_update()
        ).all()
    )
    target = next((row for row in active_sessions if row.id == session_id), None)
    if target_user is None or target is None:
        raise HTTPException(status_code=404, detail="session not found")
    active_count = len(active_sessions)
    if target_user.role == Role.owner.value and target_user.is_active and active_count <= 1:
        owners = _lock_active_owners(db)
        if not _other_verified_owner_exists(owners, target_user):
            _audit_rejected_owner_operation(
                db,
                actor=actor,
                target=target_user,
                action="session.revoke",
                request=request,
                reason="sole_owner_access",
            )
            raise HTTPException(
                status_code=409,
                detail="cannot revoke the sole Owner's last session",
            )
    target.revoked_at = datetime.now(UTC)
    target.revoked_by = actor.id
    target.revoke_reason = "administrator_revoke"
    write_audit(
        db,
        actor=actor,
        action="session.revoke",
        resource_type="session",
        resource_id=target.id,
        outcome="success",
        details={"target_user_id": user_id, "reason": "administrator_revoke"},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()


@router.get(
    "/api/v1/auth/security-events",
    response_model=list[AuditView],
    tags=["auth"],
)
def own_security_events(
    db: DB,
    user: Annotated[User, Depends(require_role(Role.viewer))],
) -> list[AuditLog]:
    return list(
        db.scalars(
            select(AuditLog)
            .where(
                AuditLog.actor_id == user.id,
                AuditLog.action.in_(
                    [
                        "auth.login",
                        "auth.recovery_code",
                        "user.password_change",
                        "totp.enable",
                        "totp.disable",
                        "recovery_codes.regenerate",
                        "session.revoke",
                    ]
                ),
            )
            .order_by(desc(AuditLog.created_at))
            .limit(50)
        ).all()
    )


def _lock_active_owners(db: Session) -> list[User]:
    return list(
        db.scalars(
            select(User)
            .where(User.role == Role.owner.value, User.is_active.is_(True))
            .order_by(User.id)
            .with_for_update()
        ).all()
    )


def _other_verified_owner_exists(owners: list[User], target: User) -> bool:
    return any(
        owner.id != target.id
        and not owner.must_change_password
        and owner.totp_enabled
        and owner.recovery_codes_confirmed_at is not None
        for owner in owners
    )


def _audit_rejected_owner_operation(
    db: Session,
    *,
    actor: User,
    target: User,
    action: str,
    request: Request,
    reason: str,
) -> None:
    write_audit(
        db,
        actor=actor,
        action=action,
        resource_type="user",
        resource_id=target.id,
        outcome="rejected",
        details={"reason": reason},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()


def _require_reauthentication(actor: User, password: str) -> None:
    if not verify_password(password, actor.password_hash):
        raise HTTPException(status_code=401, detail="current password is invalid")


def _require_reauthentication_audited(
    db: Session,
    actor: User,
    password: str,
    action: str,
    request: Request,
) -> None:
    if verify_password(password, actor.password_hash):
        return
    write_audit(
        db,
        actor=actor,
        action=action,
        resource_type="user",
        resource_id=actor.id,
        outcome="rejected",
        details={"reason": "reauthentication_failed"},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    raise HTTPException(status_code=401, detail="current password is invalid")


@router.get("/api/v1/users", response_model=list[UserView], tags=["users"])
def list_users(db: DB, _: Annotated[User, Depends(require_role(Role.admin))]) -> list[User]:
    return list(db.scalars(select(User).order_by(User.email)).all())


@router.post("/api/v1/users", response_model=UserView, status_code=201, tags=["users"])
def create_user(
    payload: UserCreate,
    request: Request,
    db: DB,
    actor: Annotated[User, Depends(require_role(Role.owner))],
) -> User:
    if db.scalar(select(User).where(User.email == payload.email)):
        write_audit(
            db,
            actor=actor,
            action="user.create",
            resource_type="user",
            resource_id=None,
            outcome="rejected",
            details={"identifier": payload.email, "reason": "duplicate_identifier"},
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=409, detail="user already exists")
    user = User(
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        scopes=payload.scopes,
        must_change_password=True,
        identity_setup_enforced=True,
        created_by=actor.id,
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        actor_id = actor.id
        db.rollback()
        refreshed_actor = db.get(User, actor_id)
        write_audit(
            db,
            actor=refreshed_actor,
            action="user.create",
            resource_type="user",
            resource_id=None,
            outcome="rejected",
            details={"identifier": payload.email, "reason": "duplicate_identifier"},
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=409, detail="user already exists") from exc
    write_audit(
        db,
        actor=actor,
        action="user.create",
        resource_type="user",
        resource_id=user.id,
        outcome="success",
        details={
            "identifier": user.email,
            "role": user.role,
            "scopes": user.scopes,
            "source": "owner_api",
            "must_change_password": True,
        },
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return user


@router.patch("/api/v1/users/{user_id}", response_model=UserView, tags=["users"])
def update_user(
    user_id: str,
    payload: UserUpdate,
    request: Request,
    db: DB,
    actor: Annotated[User, Depends(require_role(Role.owner))],
) -> User:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="user not found")
    try:
        _require_reauthentication(actor, payload.current_password)
    except HTTPException:
        write_audit(
            db,
            actor=actor,
            action="user.update",
            resource_type="user",
            resource_id=target.id,
            outcome="rejected",
            details={"reason": "reauthentication_failed"},
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise
    removing_owner = target.role == Role.owner.value and (
        payload.role not in {None, Role.owner.value} or payload.is_active is False
    )
    owners = _lock_active_owners(db) if removing_owner else []
    if removing_owner and not any(owner.id != target.id for owner in owners):
        _audit_rejected_owner_operation(
            db,
            actor=actor,
            target=target,
            action="user.update",
            request=request,
            reason="last_active_owner",
        )
        raise HTTPException(status_code=409, detail="the last active Owner cannot be removed")
    changes: dict[str, object] = {}
    invalidates_sessions = False
    if payload.role is not None and payload.role != target.role:
        changes["role"] = {"from": target.role, "to": payload.role}
        target.role = payload.role
        invalidates_sessions = True
    if payload.scopes is not None and payload.scopes != target.scopes:
        changes["scopes_changed"] = True
        target.scopes = payload.scopes
        invalidates_sessions = True
    if payload.is_active is not None and payload.is_active != target.is_active:
        changes["is_active"] = payload.is_active
        target.is_active = payload.is_active
        target.disabled_at = None if payload.is_active else datetime.now(UTC)
        target.disabled_by = None if payload.is_active else actor.id
        invalidates_sessions = True
    if invalidates_sessions:
        target.session_version += 1
        revoke_sessions(
            db,
            user_id=target.id,
            actor_id=actor.id,
            reason="identity_authorization_changed",
        )
    write_audit(
        db,
        actor=actor,
        action="user.update",
        resource_type="user",
        resource_id=target.id,
        outcome="success",
        details=changes,
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return target


@router.post("/api/v1/users/{user_id}/revoke-sessions", status_code=204, tags=["users"])
def revoke_user_sessions(
    user_id: str,
    request: Request,
    db: DB,
    actor: Annotated[User, Depends(require_role(Role.admin))],
) -> None:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="user not found")
    owners = _lock_active_owners(db) if target.role == Role.owner.value else []
    if (
        target.role == Role.owner.value
        and target.is_active
        and not _other_verified_owner_exists(owners, target)
    ):
        _audit_rejected_owner_operation(
            db,
            actor=actor,
            target=target,
            action="user.sessions_revoke",
            request=request,
            reason="sole_owner_access",
        )
        raise HTTPException(
            status_code=409,
            detail="another verified Owner is required before revoking all access",
        )
    target.session_version += 1
    revoked = revoke_sessions(
        db,
        user_id=target.id,
        actor_id=actor.id,
        reason="administrator_revoke_all",
    )
    write_audit(
        db,
        actor=actor,
        action="user.sessions_revoke",
        resource_type="user",
        resource_id=target.id,
        outcome="success",
        details={"revoked_count": revoked},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()


@router.post("/api/v1/users/{user_id}/rotate-password", status_code=204, tags=["users"])
def rotate_user_password(
    user_id: str,
    payload: UserPasswordReset,
    request: Request,
    db: DB,
    actor: Annotated[User, Depends(require_role(Role.owner))],
) -> None:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="user not found")
    _require_reauthentication_audited(
        db, actor, payload.current_password, "user.password_rotate", request
    )
    if verify_password(payload.new_password, target.password_hash):
        write_audit(
            db,
            actor=actor,
            action="user.password_rotate",
            resource_type="user",
            resource_id=target.id,
            outcome="rejected",
            details={"reason": "password_reuse"},
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=409, detail="new password must be different")
    target.password_hash = hash_password(payload.new_password)
    target.password_changed_at = datetime.now(UTC)
    target.must_change_password = True
    target.session_version += 1
    revoked = revoke_sessions(
        db,
        user_id=target.id,
        actor_id=actor.id,
        reason="administrator_password_rotation",
    )
    write_audit(
        db,
        actor=actor,
        action="user.password_rotate",
        resource_type="user",
        resource_id=target.id,
        outcome="success",
        details={"sessions_revoked": revoked, "must_change_password": True},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()


@router.delete("/api/v1/users/{user_id}", status_code=204, tags=["users"])
def delete_user(
    user_id: str,
    payload: UserDeleteRequest,
    request: Request,
    db: DB,
    actor: Annotated[User, Depends(require_role(Role.owner))],
) -> None:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="user not found")
    _require_reauthentication_audited(db, actor, payload.current_password, "user.delete", request)
    owners = _lock_active_owners(db) if target.role == Role.owner.value and target.is_active else []
    if owners and not any(owner.id != target.id for owner in owners):
        _audit_rejected_owner_operation(
            db,
            actor=actor,
            target=target,
            action="user.delete",
            request=request,
            reason="last_active_owner",
        )
        raise HTTPException(status_code=409, detail="the last active Owner cannot be deleted")
    write_audit(
        db,
        actor=actor,
        action="user.delete",
        resource_type="user",
        resource_id=target.id,
        outcome="success",
        details={"identifier": target.email, "role": target.role},
        source_ip=request.client.host if request.client else None,
    )
    db.delete(target)
    db.commit()


def _snapshot_metric(snapshot: MetricSnapshot | None, key: str) -> float:
    if snapshot is None:
        return -1.0
    value = snapshot.payload.get(key)
    return float(value) if isinstance(value, int | float) else -1.0


_INTERNAL_HOST_TAGS = frozenset({"komari-import", "pending-enrollment"})


def _host_management(host: Host, agent: Agent | None) -> str:
    tags = set(host.tags)
    if agent is not None and "komari-import" in tags:
        return "guardian_and_komari"
    if agent is not None:
        return "guardian"
    if "komari-import" in tags or host.address.startswith("komari:"):
        return "komari_only"
    return "pending_enrollment"


def _host_agent_state(agent: Agent | None, now: datetime) -> str:
    if agent is None:
        return "not_installed"
    if agent.revoked_at is not None:
        return "revoked"
    if agent.last_heartbeat_at is None:
        return "never_seen"
    heartbeat = agent.last_heartbeat_at
    if heartbeat.tzinfo is None:
        heartbeat = heartbeat.replace(tzinfo=UTC)
    return "online" if heartbeat >= now - timedelta(minutes=5) else "stale"


def _host_data_reason(host: Host, agent: Agent | None) -> str:
    if not host.enabled:
        return "disabled"
    if host.data_state == "stale":
        return "stale"
    if host.data_state == "agent_error":
        return "agent_error"
    if agent is None and _host_management(host, agent) == "pending_enrollment":
        return "pending_enrollment"
    if agent is None:
        return "no_guardian_agent"
    if agent.last_heartbeat_at is None:
        return "never_connected"
    return "available"


def _resource_percent(payload: dict[str, object], key: str) -> float | None:
    value = payload.get(key)
    return float(value) if isinstance(value, int | float) else None


def _host_resource_summary(payload: dict[str, object] | None) -> dict[str, float] | None:
    if payload is None:
        return None
    values = {
        "cpu_percent": _resource_percent(payload, "cpu_percent"),
        "memory_percent": _resource_percent(payload, "memory_percent"),
        "disk_percent": _resource_percent(payload, "disk_percent"),
    }
    return {key: value for key, value in values.items() if value is not None} or None


@router.get(
    "/api/v1/hosts/presentation",
    response_model=list[HostPresentationView],
    tags=["inventory"],
)
def list_host_presentations(
    db: DB,
    _: Annotated[User, Depends(require_role(Role.viewer))],
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[HostPresentationView]:
    """Bounded, single-query host index with an explicit presentation allowlist."""

    rows = db.execute(
        select(Host, Agent)
        .outerjoin(Agent, Agent.host_id == Host.id)
        .order_by(Host.name)
        .limit(limit)
        .offset(offset)
    ).all()
    host_ids = [host.id for host, _agent in rows]
    snapshots: dict[str, dict[str, object]] = {}
    if host_ids:
        ranked_snapshots = (
            select(
                MetricSnapshot.host_id,
                MetricSnapshot.payload,
                func.row_number()
                .over(
                    partition_by=MetricSnapshot.host_id,
                    order_by=desc(MetricSnapshot.collected_at),
                )
                .label("snapshot_rank"),
            )
            .where(MetricSnapshot.host_id.in_(host_ids))
            .subquery()
        )
        snapshots = {
            host_id: cast(dict[str, object], payload)
            for host_id, payload in db.execute(
                select(ranked_snapshots.c.host_id, ranked_snapshots.c.payload).where(
                    ranked_snapshots.c.snapshot_rank == 1
                )
            ).all()
        }
    now = datetime.now(UTC)
    return [
        HostPresentationView(
            id=host.id,
            name=host.name,
            primary_address=host.address,
            os_name=host.os_name,
            region=host.location,
            group=host.group_name,
            provider=host.labels.get("provider"),
            purpose=host.labels.get("purpose"),
            display_tags=[tag for tag in host.tags if tag not in _INTERNAL_HOST_TAGS],
            health=cast(Any, host.status),
            data_state=cast(Any, host.data_state),
            enabled=host.enabled,
            management=cast(Any, _host_management(host, agent)),
            agent_state=cast(Any, _host_agent_state(agent, now)),
            agent_version=agent.version if agent else None,
            last_heartbeat_at=agent.last_heartbeat_at if agent else None,
            last_seen_at=host.last_seen_at,
            enrolled_at=host.enrolled_at,
            data_reason=cast(Any, _host_data_reason(host, agent)),
            resource_summary=_host_resource_summary(snapshots.get(host.id)),
            technical_evidence_available=True,
        )
        for host, agent in rows
    ]


@router.patch("/api/v1/hosts/batch", tags=["inventory"])
def batch_update_hosts(
    payload: HostBatchUpdate,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.admin))],
) -> dict[str, int]:
    if (
        payload.enabled is None
        and payload.group_name is None
        and not payload.add_tags
        and not payload.remove_tags
    ):
        raise HTTPException(status_code=422, detail="at least one batch change is required")
    hosts = list(db.scalars(select(Host).where(Host.id.in_(payload.host_ids))).all())
    if len(hosts) != len(payload.host_ids):
        raise HTTPException(status_code=404, detail="one or more hosts were not found")
    for host in hosts:
        if payload.enabled is not None:
            host.enabled = payload.enabled
            host.disabled_at = None if payload.enabled else datetime.now(UTC)
        if payload.group_name is not None:
            host.group_name = payload.group_name or None
        tags = (set(host.tags) | set(payload.add_tags)) - set(payload.remove_tags)
        host.tags = sorted(tags)
    write_audit(
        db,
        actor=user,
        action="host.batch_update",
        resource_type="host",
        resource_id=None,
        outcome="success",
        details={
            "host_count": len(hosts),
            "enabled_changed": payload.enabled is not None,
            "group_changed": payload.group_name is not None,
            "tags_added": len(payload.add_tags),
            "tags_removed": len(payload.remove_tags),
        },
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return {"updated": len(hosts)}


@router.get("/api/v1/hosts", response_model=list[HostView], tags=["inventory"])
def list_hosts(
    db: DB,
    _: Annotated[User, Depends(require_role(Role.viewer))],
    query: Annotated[str | None, Query(max_length=120)] = None,
    online: bool | None = None,
    enabled: bool | None = None,
    group: Annotated[str | None, Query(max_length=120)] = None,
    tag: Annotated[str | None, Query(max_length=64)] = None,
    sort_by: Literal["name", "status", "cpu", "memory", "disk"] = "name",
    order: Literal["asc", "desc"] = "asc",
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Host]:
    hosts = list(db.scalars(select(Host)).all())
    if query:
        needle = query.casefold()
        hosts = [
            host
            for host in hosts
            if needle in host.name.casefold()
            or needle in host.address.casefold()
            or any(needle in item.casefold() for item in host.tags)
        ]
    if online is not None:
        hosts = [host for host in hosts if (host.status != "offline") is online]
    if enabled is not None:
        hosts = [host for host in hosts if host.enabled is enabled]
    if group is not None:
        hosts = [host for host in hosts if host.group_name == group]
    if tag is not None:
        hosts = [host for host in hosts if tag in host.tags]

    snapshots = {
        host.id: db.scalar(
            select(MetricSnapshot)
            .where(MetricSnapshot.host_id == host.id)
            .order_by(desc(MetricSnapshot.collected_at))
            .limit(1)
        )
        for host in hosts
    }
    keys = {"cpu": "cpu_percent", "memory": "memory_percent", "disk": "disk_percent"}
    if sort_by in keys:
        hosts.sort(
            key=lambda host: (_snapshot_metric(snapshots[host.id], keys[sort_by]), host.name),
            reverse=order == "desc",
        )
    elif sort_by == "status":
        hosts.sort(key=lambda host: (host.data_state, host.name), reverse=order == "desc")
    else:
        hosts.sort(key=lambda host: host.name.casefold(), reverse=order == "desc")
    return hosts[offset : offset + limit]


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


@router.patch("/api/v1/hosts/{host_id}", response_model=HostView, tags=["inventory"])
def update_host(
    host_id: str,
    payload: HostUpdate,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.admin))],
) -> Host:
    host = db.get(Host, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")
    changes = payload.model_dump(exclude_unset=True)
    if changes.get("name") and db.scalar(
        select(Host).where(Host.name == changes["name"], Host.id != host.id)
    ):
        raise HTTPException(status_code=409, detail="host name already exists")
    if changes.get("enabled") is False and host.enabled:
        changes["disabled_at"] = datetime.now(UTC)
    elif changes.get("enabled") is True:
        changes["disabled_at"] = None
    for key, value in changes.items():
        setattr(host, key, value)
    write_audit(
        db,
        actor=user,
        action="host.update",
        resource_type="host",
        resource_id=host.id,
        outcome="success",
        details={"changed_fields": sorted(changes)},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return host


@router.delete("/api/v1/hosts/{host_id}", status_code=204, tags=["inventory"])
def delete_inactive_host(
    host_id: str,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.admin))],
) -> None:
    host = db.get(Host, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")
    if host.agent is not None or host.enrolled_at is not None:
        raise HTTPException(status_code=409, detail="only never-enrolled hosts can be deleted")
    name = host.name
    db.delete(host)
    write_audit(
        db,
        actor=user,
        action="host.delete_inactive",
        resource_type="host",
        resource_id=host_id,
        outcome="success",
        details={"name": name},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()


@router.post(
    "/api/v1/hosts/{host_id}/enrollment-token",
    response_model=EnrollmentTokenView,
    status_code=201,
    tags=["agent"],
)
def create_enrollment_token(
    host_id: str,
    payload: EnrollmentTokenIssue,
    request: Request,
    db: DB,
    settings: Config,
    user: Annotated[User, Depends(require_role(Role.admin))],
) -> EnrollmentTokenView:
    host = db.get(Host, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")
    try:
        issued = issue_enrollment_token(
            db,
            host=host,
            actor=user,
            ttl=timedelta(minutes=payload.expires_in_minutes),
        )
    except EnrollmentTokenError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    write_audit(
        db,
        actor=user,
        action="agent.enrollment_token.issue",
        resource_type="host",
        resource_id=host.id,
        outcome="success",
        details={"expires_at": issued.expires_at.isoformat()},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    controller_url = validate_agent_gateway_url(settings.agent_gateway_url)
    command = (
        "sudo ./scripts/install-agent.sh "
        "--binary ./agent-bundle/vps-guardian-agent "
        ' --sha256 "$(cat ./agent-bundle/vps-guardian-agent.sha256)" '
        f"--controller-url {shlex.quote(controller_url)} "
        f"--host-id {shlex.quote(host.id)} "
        "--server-ca ./agent-bundle/controller-ca.crt "
        ' --controller-public-key "$(cat ./agent-bundle/controller-public-key.txt)" '
        "--enrollment-token-file ./agent-bundle/enrollment-token"
    )
    return EnrollmentTokenView(
        id=issued.id,
        token=issued.value,
        expires_at=issued.expires_at,
        install_command=command,
    )


@router.post(
    "/api/v1/hosts/{host_id}/enrollment-tokens/{token_id}/revoke",
    status_code=204,
    tags=["agent"],
)
def revoke_host_enrollment_token(
    host_id: str,
    token_id: str,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.admin))],
) -> None:
    try:
        token = revoke_enrollment_token(db, token_id=token_id, host_id=host_id)
    except EnrollmentTokenError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    write_audit(
        db,
        actor=user,
        action="agent.enrollment_token.revoke",
        resource_type="enrollment_token",
        resource_id=token.id,
        outcome="success",
        details={"host_id": host_id, "reason_code": "operator_revoked"},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()


def _record_bootstrap_failure(
    db: Session,
    *,
    request: Request,
    host_id: str | None,
    reason_code: str,
) -> None:
    db.rollback()
    write_audit(
        db,
        actor=None,
        action="agent.csr_bootstrap",
        resource_type="host",
        resource_id=host_id,
        outcome="denied",
        details={"reason_code": reason_code},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()


@router.post(
    "/api/v1/agents/bootstrap",
    response_model=AgentBootstrapResponse,
    tags=["agent"],
)
def bootstrap_agent(
    payload: AgentBootstrapRequest,
    request: Request,
    db: DB,
    settings: Config,
    enrollment_token: Annotated[str | None, Header(alias="X-Enrollment-Token")] = None,
) -> AgentBootstrapResponse:
    if settings.environment == "production":
        try:
            require_trusted_agent_gateway(request, settings)
        except HTTPException:
            _record_bootstrap_failure(
                db,
                request=request,
                host_id=payload.host_id,
                reason_code="gateway_rejected",
            )
            raise
    if not enrollment_token:
        _record_bootstrap_failure(
            db, request=request, host_id=payload.host_id, reason_code="token_missing"
        )
        raise HTTPException(status_code=401, detail="invalid enrollment token")
    source = request.client.host if request.client else "unknown"
    limiter_key = f"{source}:{token_digest(enrollment_token)[:16]}"
    try:
        enrollment_limiter.check(limiter_key, settings.enrollment_attempts_per_10m)
    except EnrollmentRateLimitError as exc:
        _record_bootstrap_failure(
            db, request=request, host_id=payload.host_id, reason_code="rate_limited"
        )
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    try:
        validate_agent_csr(payload.csr_pem)
    except AgentCertificateError as exc:
        _record_bootstrap_failure(
            db, request=request, host_id=payload.host_id, reason_code="csr_rejected"
        )
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        token, host = consume_enrollment_token(
            db,
            value=enrollment_token,
            expected_host_id=payload.host_id,
        )
    except EnrollmentTokenError as exc:
        _record_bootstrap_failure(
            db, request=request, host_id=payload.host_id, reason_code="token_rejected"
        )
        raise HTTPException(status_code=401, detail="invalid enrollment token") from exc

    existing_agent = db.scalar(select(Agent).where(Agent.host_id == host.id).with_for_update())
    if existing_agent is not None and existing_agent.revoked_at is None:
        _record_bootstrap_failure(
            db, request=request, host_id=host.id, reason_code="active_agent_exists"
        )
        raise HTTPException(status_code=409, detail="host already has an active agent")
    agent_id = existing_agent.id if existing_agent is not None else str(uuid.uuid4())
    try:
        issued = issue_agent_certificate(
            csr_pem=payload.csr_pem,
            agent_id=agent_id,
            host_id=host.id,
            settings=settings,
        )
        gateway_endpoint = validate_agent_gateway_url(settings.agent_gateway_url)
    except AgentCertificateError as exc:
        _record_bootstrap_failure(
            db, request=request, host_id=host.id, reason_code="certificate_issuance_failed"
        )
        raise HTTPException(status_code=503, detail="certificate issuance unavailable") from exc

    enrolled_at = datetime.now(UTC)
    try:
        if existing_agent is None:
            agent = Agent(
                id=agent_id,
                host_id=host.id,
                signing_public_key=payload.signing_public_key,
                certificate_fingerprint=issued.fingerprint,
                certificate_serial=issued.serial,
                version=payload.version,
            )
            db.add(agent)
        else:
            agent = existing_agent
            agent.identity_version += 1
            agent.signing_public_key = payload.signing_public_key
            agent.certificate_fingerprint = issued.fingerprint
            agent.certificate_serial = issued.serial
            agent.version = payload.version
            agent.revoked_at = None
        db.flush()
        identity = AgentIdentity(
            agent_id=agent.id,
            generation=agent.identity_version,
            state=AgentIdentityState.active.value,
            signing_public_key=payload.signing_public_key,
            certificate_fingerprint=issued.fingerprint,
            certificate_serial=issued.serial,
            expires_at=issued.expires_at,
            verified_at=enrolled_at,
            activated_at=enrolled_at,
        )
        db.add(identity)
        host.enrolled_at = enrolled_at
        write_audit(
            db,
            actor=None,
            action="agent.csr_bootstrap",
            resource_type="agent",
            resource_id=agent.id,
            outcome="success",
            details={
                "host_id": host.id,
                "token_id": token.id,
                "certificate_serial": issued.serial,
                "certificate_fingerprint_suffix": issued.fingerprint[-12:],
                "certificate_expires_at": issued.expires_at.isoformat(),
            },
            source_ip=source,
        )
        db.commit()
    except IntegrityError as exc:
        _record_bootstrap_failure(
            db, request=request, host_id=host.id, reason_code="identity_conflict"
        )
        raise HTTPException(status_code=409, detail="certificate identity conflict") from exc
    enrollment_limiter.reset(limiter_key)
    return AgentBootstrapResponse(
        agent_id=agent.id,
        host_id=host.id,
        certificate_pem=issued.certificate_pem,
        ca_bundle_pem=issued.ca_bundle_pem,
        certificate_serial=issued.serial,
        certificate_expires_at=issued.expires_at,
        agent_gateway_endpoint=gateway_endpoint,
    )


@router.get("/api/v1/hosts/{host_id}/metrics", tags=["inventory"])
def host_metric_trends(
    host_id: str,
    db: DB,
    _: Annotated[User, Depends(require_role(Role.viewer))],
    window: Literal["1h", "24h", "7d"] = "24h",
) -> dict[str, object]:
    if db.get(Host, host_id) is None:
        raise HTTPException(status_code=404, detail="host not found")
    durations = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7)}
    cutoff = datetime.now(UTC) - durations[window]
    snapshots = db.scalars(
        select(MetricSnapshot)
        .where(MetricSnapshot.host_id == host_id, MetricSnapshot.collected_at >= cutoff)
        .order_by(MetricSnapshot.collected_at)
        .limit(10_080)
    ).all()
    return {
        "host_id": host_id,
        "window": window,
        "points": [
            {"collected_at": item.collected_at.isoformat(), "metrics": item.payload}
            for item in snapshots
        ],
    }


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


@router.get("/api/v1/dashboard/bootstrap", tags=["dashboard"], response_model=None)
def bootstrap_dashboard(
    response: Response,
    db: DB,
    settings: Config,
    user: Annotated[User, Depends(require_role(Role.viewer))],
    if_none_match: Annotated[str | None, Header()] = None,
) -> dict[str, object] | Response:
    started = time.perf_counter()
    payload, etag, cache_hit, db_ms, serialization_ms = dashboard_bootstrap(
        db,
        settings=settings,
        user=user,
    )
    total_ms = (time.perf_counter() - started) * 1000
    headers = {
        "Cache-Control": "private, max-age=0, must-revalidate",
        "ETag": etag,
        "Server-Timing": (
            f'db;dur={db_ms:.2f}, cache;desc="{"hit" if cache_hit else "miss"}";dur=0, '
            f"serialization;dur={serialization_ms:.2f}, total;dur={total_ms:.2f}"
        ),
        "Vary": "Authorization, Cookie",
    }
    if if_none_match == etag:
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)
    for key, value in headers.items():
        response.headers[key] = value
    return payload


@router.get("/api/v1/dashboard/resources/current", tags=["dashboard"])
def dashboard_resources_current(
    response: Response,
    db: DB,
    _: Annotated[User, Depends(require_role(Role.viewer))],
) -> dict[str, object]:
    started = time.perf_counter()
    payload = current_resource_summary(db)
    response.headers["Cache-Control"] = "private, max-age=15"
    response.headers["Server-Timing"] = f"total;dur={(time.perf_counter() - started) * 1000:.2f}"
    response.headers["Vary"] = "Authorization, Cookie"
    return payload


@router.get("/api/v1/dashboard/topology", tags=["dashboard"])
def dashboard_topology(
    response: Response,
    db: DB,
    _: Annotated[User, Depends(require_role(Role.viewer))],
) -> dict[str, object]:
    started = time.perf_counter()
    payload = topology_summary(db)
    response.headers["Cache-Control"] = "private, max-age=15"
    response.headers["Server-Timing"] = f"total;dur={(time.perf_counter() - started) * 1000:.2f}"
    response.headers["Vary"] = "Authorization, Cookie"
    return payload


@router.get("/api/v1/dashboard/security", tags=["dashboard"])
def dashboard_security(
    response: Response,
    db: DB,
    settings: Config,
    _: Annotated[User, Depends(require_role(Role.admin))],
) -> dict[str, object]:
    started = time.perf_counter()
    payload = security_summary(db, settings=settings)
    response.headers["Cache-Control"] = "private, max-age=15"
    response.headers["Server-Timing"] = f"total;dur={(time.perf_counter() - started) * 1000:.2f}"
    response.headers["Vary"] = "Authorization, Cookie"
    return payload


@router.get("/api/v1/attention", tags=["dashboard"])
def attention(
    db: DB,
    settings: Config,
    user: Annotated[User, Depends(require_role(Role.viewer))],
) -> dict[str, object]:
    payload = build_operations_overview(
        db, settings=settings, user=user, window="24h", host_id=None
    )
    return {
        "generated_at": payload["generated_at"],
        "global_health": payload["global_health"],
        "health_reasons": payload["health_reasons"],
        "items": payload["attention"],
    }


@router.get("/api/v1/stability", tags=["dashboard"])
def stability(
    db: DB,
    settings: Config,
    _: Annotated[User, Depends(require_role(Role.viewer))],
    window: Annotated[StabilityWindow, Query()] = "24h",
    group: Annotated[str | None, Query(max_length=120)] = None,
    location: Annotated[str | None, Query(max_length=120)] = None,
) -> dict[str, object]:
    return build_stability_report(
        db,
        settings=settings,
        window=window,
        group=group,
        location=location,
    )


@router.get("/api/v1/services", tags=["inventory"])
def list_services(
    db: DB, _: Annotated[User, Depends(require_role(Role.viewer))]
) -> list[dict[str, object]]:
    services: list[dict[str, object]] = []
    latest_times = (
        select(
            MetricSnapshot.host_id,
            func.max(MetricSnapshot.collected_at).label("collected_at"),
        )
        .group_by(MetricSnapshot.host_id)
        .subquery()
    )
    rows = db.execute(
        select(
            Host.id,
            Host.name,
            MetricSnapshot.collected_at,
            MetricSnapshot.payload,
        )
        .join(latest_times, latest_times.c.host_id == Host.id)
        .join(
            MetricSnapshot,
            and_(
                MetricSnapshot.host_id == latest_times.c.host_id,
                MetricSnapshot.collected_at == latest_times.c.collected_at,
            ),
        )
        .order_by(Host.name)
    ).all()
    for host_id, host_name, collected_at, payload in rows:
        raw_services = payload.get("_services", [])
        if not isinstance(raw_services, list):
            continue
        for item in raw_services[:100]:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind", "unknown"))[:80]
            raw_summary = str(item.get("summary", ""))[:1000]
            classification = classify_service_observation(kind, raw_summary)
            summary = redact_serialized_text(raw_summary)
            services.append(
                {
                    "host_id": host_id,
                    "host_name": host_name,
                    "kind": kind,
                    **classification,
                    "summary": summary,
                    "evidence_available": bool(summary),
                    "collected_at": collected_at.isoformat(),
                }
            )
    return services


@router.get("/api/v1/service-checks", response_model=list[ServiceCheckView], tags=["monitoring"])
def list_service_checks(
    db: DB,
    _: Annotated[User, Depends(require_role(Role.viewer))],
    enabled: bool | None = None,
    kind: Annotated[str | None, Query(max_length=24)] = None,
) -> list[ServiceCheck]:
    statement = select(ServiceCheck)
    if enabled is not None:
        statement = statement.where(ServiceCheck.enabled.is_(enabled))
    if kind is not None:
        statement = statement.where(ServiceCheck.kind == kind)
    return list(db.scalars(statement.order_by(ServiceCheck.name)).all())


@router.get(
    "/api/v1/service-check-results",
    response_model=list[ServiceCheckResultView],
    tags=["monitoring"],
)
def list_service_check_results(
    db: DB,
    _: Annotated[User, Depends(require_role(Role.viewer))],
    check_id: Annotated[str | None, Query(max_length=36)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ServiceCheckResult]:
    statement = select(ServiceCheckResult)
    if check_id is not None:
        statement = statement.where(ServiceCheckResult.check_id == check_id)
    return list(
        db.scalars(
            statement.order_by(desc(ServiceCheckResult.checked_at)).limit(limit).offset(offset)
        ).all()
    )


@router.post(
    "/api/v1/service-checks",
    response_model=ServiceCheckView,
    status_code=201,
    tags=["monitoring"],
)
def create_service_check(
    payload: ServiceCheckCreate,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.admin))],
) -> ServiceCheck:
    if db.scalar(select(ServiceCheck).where(ServiceCheck.name == payload.name)):
        raise HTTPException(status_code=409, detail="service check name already exists")
    if payload.host_id and db.get(Host, payload.host_id) is None:
        raise HTTPException(status_code=404, detail="target host not found")
    runner = db.get(Agent, payload.runner_agent_id) if payload.runner_agent_id else None
    if payload.runner_agent_id and runner is None:
        raise HTTPException(status_code=404, detail="runner agent not found")
    if payload.kind in {"docker", "systemd"} and (not payload.host_id or runner is None):
        raise HTTPException(
            status_code=422,
            detail="Docker and systemd checks require a target host and runner agent",
        )
    check = ServiceCheck(**payload.model_dump())
    db.add(check)
    db.flush()
    db.add(
        AlertRule(
            name=f"service-{check.name}",
            source_type="service_check",
            source_id=check.id,
            severity=check.severity,
            group_key=check.group_name or "services",
            failure_threshold=check.failure_threshold,
            recovery_threshold=check.recovery_threshold,
        )
    )
    write_audit(
        db,
        actor=user,
        action="service_check.create",
        resource_type="service_check",
        resource_id=check.id,
        outcome="success",
        details={"name": check.name, "kind": check.kind, "runner_agent_id": check.runner_agent_id},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return check


@router.patch(
    "/api/v1/service-checks/{check_id}",
    response_model=ServiceCheckView,
    tags=["monitoring"],
)
def update_service_check(
    check_id: str,
    payload: ServiceCheckUpdate,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.admin))],
) -> ServiceCheck:
    check = db.get(ServiceCheck, check_id)
    if check is None:
        raise HTTPException(status_code=404, detail="service check not found")
    changes = payload.model_dump(exclude_none=True)
    if not changes:
        return check
    previous = {key: getattr(check, key) for key in changes}
    for key, value in changes.items():
        setattr(check, key, value)
    check.updated_at = datetime.now(UTC)
    write_audit(
        db,
        actor=user,
        action="service_check.update",
        resource_type="service_check",
        resource_id=check.id,
        outcome="success",
        details={
            "fields": sorted(changes),
            "previous": previous,
            "current": changes,
        },
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    db.refresh(check)
    return check


@router.delete("/api/v1/service-checks/{check_id}", status_code=204, tags=["monitoring"])
def delete_service_check(
    check_id: str,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.admin))],
) -> None:
    check = db.get(ServiceCheck, check_id)
    if check is None:
        raise HTTPException(status_code=404, detail="service check not found")
    rules = db.scalars(
        select(AlertRule).where(
            AlertRule.source_type == "service_check", AlertRule.source_id == check.id
        )
    ).all()
    for rule in rules:
        db.delete(rule)
    db.delete(check)
    write_audit(
        db,
        actor=user,
        action="service_check.delete",
        resource_type="service_check",
        resource_id=check_id,
        outcome="success",
        details={"name": check.name},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()


@router.get("/api/v1/alert-rules", response_model=list[AlertRuleView], tags=["alerts"])
def list_alert_rules(
    db: DB, _: Annotated[User, Depends(require_role(Role.viewer))]
) -> list[AlertRule]:
    return list(db.scalars(select(AlertRule).order_by(AlertRule.name)).all())


@router.post(
    "/api/v1/alert-rules",
    response_model=AlertRuleView,
    status_code=201,
    tags=["alerts"],
)
def create_alert_rule(
    payload: AlertRuleCreate,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.admin))],
) -> AlertRule:
    if db.scalar(select(AlertRule).where(AlertRule.name == payload.name)):
        raise HTTPException(status_code=409, detail="alert rule name already exists")
    if payload.source_type == "service_check" and db.get(ServiceCheck, payload.source_id) is None:
        raise HTTPException(status_code=404, detail="service check not found")
    if payload.source_type != "service_check" and db.get(Host, payload.source_id) is None:
        raise HTTPException(status_code=404, detail="host not found")
    rule = AlertRule(**payload.model_dump())
    db.add(rule)
    db.flush()
    write_audit(
        db,
        actor=user,
        action="alert_rule.create",
        resource_type="alert_rule",
        resource_id=rule.id,
        outcome="success",
        details={"name": rule.name, "source_type": rule.source_type},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return rule


@router.get("/api/v1/alerts", response_model=list[AlertView], tags=["alerts"])
def list_alerts(
    db: DB,
    _: Annotated[User, Depends(require_role(Role.viewer))],
    state: Annotated[str | None, Query(max_length=24)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AlertInstance]:
    statement = select(AlertInstance)
    if state:
        statement = statement.where(AlertInstance.state == state)
    return list(
        db.scalars(
            statement.order_by(desc(AlertInstance.last_observed_at)).limit(limit).offset(offset)
        ).all()
    )


@router.post("/api/v1/alerts/{alert_id}/acknowledge", response_model=AlertView, tags=["alerts"])
def acknowledge_alert_api(
    alert_id: str,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.operator))],
) -> AlertInstance:
    alert = db.get(AlertInstance, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    if not acknowledge_alert(db, alert=alert, actor=user):
        raise HTTPException(
            status_code=409, detail="alert cannot be acknowledged in its current state"
        )
    write_audit(
        db,
        actor=user,
        action="alert.acknowledge",
        resource_type="alert",
        resource_id=alert.id,
        outcome="success",
        details={"state": alert.state},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return alert


@router.post("/api/v1/alerts/{alert_id}/silence", response_model=AlertView, tags=["alerts"])
def silence_alert_api(
    alert_id: str,
    payload: AlertSilenceRequest,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.operator))],
) -> AlertInstance:
    alert = db.get(AlertInstance, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    try:
        silence_alert(db, alert=alert, actor=user, reason=payload.reason, until=payload.until)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    write_audit(
        db,
        actor=user,
        action="alert.silence",
        resource_type="alert",
        resource_id=alert.id,
        outcome="success",
        details={"until": payload.until.isoformat(), "reason": payload.reason},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return alert


@router.patch("/api/v1/alerts/{alert_id}", response_model=AlertView, tags=["alerts"])
def update_alert_api(
    alert_id: str,
    payload: AlertUpdateRequest,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.operator))],
) -> AlertInstance:
    alert = db.get(AlertInstance, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    if payload.assigned_to:
        assignee = db.get(User, payload.assigned_to)
        if assignee is None or not assignee.is_active:
            raise HTTPException(status_code=422, detail="assignee is unavailable")
    alert.assigned_to = payload.assigned_to
    previous_state = alert.state
    if payload.close:
        if alert.state not in {"acknowledged", "resolved"}:
            raise HTTPException(
                status_code=409,
                detail="only acknowledged or recovered alerts can be closed",
            )
        alert.state = "closed"
        alert.closed_at = datetime.now(UTC)
        db.add(
            AlertTransition(
                alert_id=alert.id,
                previous_state=previous_state,
                current_state="closed",
                reason=payload.note or "closed by operator",
            )
        )
    write_audit(
        db,
        actor=user,
        action="alert.close" if payload.close else "alert.assign",
        resource_type="alert",
        resource_id=alert.id,
        outcome="success",
        details={
            "assigned_to": alert.assigned_to,
            "state": alert.state,
            "note_present": bool(payload.note),
        },
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return alert


@router.get(
    "/api/v1/notification-channels",
    response_model=list[NotificationChannelView],
    tags=["notifications"],
)
def list_notification_channels(
    db: DB, _: Annotated[User, Depends(require_role(Role.admin))]
) -> list[NotificationChannel]:
    return list(db.scalars(select(NotificationChannel).order_by(NotificationChannel.name)).all())


@router.post(
    "/api/v1/notification-channels",
    response_model=NotificationChannelView,
    status_code=201,
    tags=["notifications"],
)
def create_notification_channel(
    payload: NotificationChannelCreate,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.admin))],
) -> NotificationChannel:
    if db.scalar(select(NotificationChannel).where(NotificationChannel.name == payload.name)):
        raise HTTPException(status_code=409, detail="notification channel name already exists")
    channel = NotificationChannel(**payload.model_dump())
    db.add(channel)
    db.flush()
    write_audit(
        db,
        actor=user,
        action="notification_channel.create",
        resource_type="notification_channel",
        resource_id=channel.id,
        outcome="success",
        details={"name": channel.name, "kind": channel.kind},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return channel


@router.post(
    "/api/v1/notification-channels/{channel_id}/test",
    tags=["notifications"],
)
async def test_notification_channel(
    channel_id: str,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.admin))],
) -> dict[str, object]:
    channel = db.get(NotificationChannel, channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="notification channel not found")
    try:
        response_code = await send_test_notification(channel)
    except NotificationConfigurationError as exc:
        write_audit(
            db,
            actor=user,
            action="notification_channel.test",
            resource_type="notification_channel",
            resource_id=channel.id,
            outcome="rejected",
            details={"reason": str(exc)},
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - never expose endpoint or credential details.
        write_audit(
            db,
            actor=user,
            action="notification_channel.test",
            resource_type="notification_channel",
            resource_id=channel.id,
            outcome="failed",
            details={"error_type": type(exc).__name__},
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=502, detail="notification test failed") from exc
    write_audit(
        db,
        actor=user,
        action="notification_channel.test",
        resource_type="notification_channel",
        resource_id=channel.id,
        outcome="success",
        details={"response_code": response_code},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return {"delivered": True, "response_code": response_code, "scope": "local_mock_only"}


@router.get(
    "/api/v1/notification-deliveries",
    response_model=list[NotificationDeliveryView],
    tags=["notifications"],
)
def list_notification_deliveries(
    db: DB,
    _: Annotated[User, Depends(require_role(Role.admin))],
    delivery_status: Annotated[str | None, Query(max_length=24)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> list[NotificationDelivery]:
    statement = select(NotificationDelivery)
    if delivery_status:
        statement = statement.where(NotificationDelivery.status == delivery_status)
    return list(
        db.scalars(statement.order_by(desc(NotificationDelivery.created_at)).limit(limit)).all()
    )


@router.post(
    "/api/v1/notification-deliveries/{delivery_id}/retry",
    response_model=NotificationDeliveryView,
    tags=["notifications"],
)
def retry_notification_delivery(
    delivery_id: str,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.admin))],
) -> NotificationDelivery:
    delivery = db.get(NotificationDelivery, delivery_id)
    if delivery is None:
        raise HTTPException(status_code=404, detail="notification delivery not found")
    if delivery.status not in {"failed", "dead_letter"}:
        raise HTTPException(status_code=409, detail="delivery is not in a terminal failure state")
    delivery.status = "pending"
    delivery.next_attempt_at = datetime.now(UTC)
    delivery.error_summary = None
    write_audit(
        db,
        actor=user,
        action="notification_delivery.retry",
        resource_type="notification_delivery",
        resource_id=delivery.id,
        outcome="success",
        details={"attempt_count": delivery.attempt_count},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return delivery


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
    db: DB,
    _: Annotated[User, Depends(require_role(Role.viewer))],
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Incident]:
    return list(
        db.scalars(
            select(Incident).order_by(desc(Incident.first_seen_at)).limit(limit).offset(offset)
        ).all()
    )


INCIDENT_TRANSITIONS: dict[str, set[str]] = {
    "open": {"acknowledged", "investigating"},
    "acknowledged": {"investigating"},
    "investigating": {"mitigating", "resolved"},
    "mitigating": {"investigating", "resolved"},
    "resolved": set(),
}


@router.patch("/api/v1/incidents/{incident_id}", response_model=IncidentView, tags=["incidents"])
def update_incident(
    incident_id: str,
    payload: IncidentUpdateRequest,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.operator))],
) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    if payload.assigned_to:
        assignee = db.get(User, payload.assigned_to)
        if assignee is None or not assignee.is_active:
            raise HTTPException(status_code=422, detail="assignee is unavailable")
    previous_status = incident.status
    if payload.status and payload.status != previous_status:
        allowed = INCIDENT_TRANSITIONS.get(previous_status, set())
        if payload.status not in allowed:
            raise HTTPException(status_code=409, detail="invalid incident status transition")
        if payload.status == IncidentStatus.resolved.value and not payload.resolution_summary:
            raise HTTPException(status_code=422, detail="resolution summary is required")
        incident.status = payload.status
        if payload.status == IncidentStatus.acknowledged.value:
            incident.acknowledged_at = datetime.now(UTC)
        if payload.status == IncidentStatus.resolved.value:
            incident.resolved_at = datetime.now(UTC)
    incident.assigned_to = payload.assigned_to
    if payload.resolution_summary is not None:
        incident.resolution_summary = payload.resolution_summary
    if payload.postmortem is not None:
        incident.postmortem = payload.postmortem
    incident.updated_at = datetime.now(UTC)
    timeline_entry: dict[str, object] = {
        "at": incident.updated_at.isoformat(),
        "actor_id": user.id,
        "from": previous_status,
        "to": incident.status,
        "note": payload.note,
    }
    incident.timeline = [
        *incident.timeline,
        timeline_entry,
    ][-500:]
    write_audit(
        db,
        actor=user,
        action="incident.update",
        resource_type="incident",
        resource_id=incident.id,
        outcome="success",
        details={
            "from": previous_status,
            "to": incident.status,
            "assigned_to": incident.assigned_to,
            "note_present": bool(payload.note),
            "resolution_present": bool(payload.resolution_summary),
            "postmortem_present": bool(payload.postmortem),
        },
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return incident


def _approval_actor(user: User | None) -> ApprovalActorView | None:
    if user is None:
        return None
    local_part = user.email.partition("@")[0]
    return ApprovalActorView(label=local_part or "operator", role=user.role)


def _approval_target(approval: Approval, host: Host | None) -> ApprovalTargetView:
    impact = approval.impact if isinstance(approval.impact, dict) else {}
    return ApprovalTargetView(
        host=host.name if host else None,
        service=str(impact["service"])[:120]
        if isinstance(impact.get("service"), str | int | float)
        else None,
        scope=str(impact["scope"])[:160]
        if isinstance(impact.get("scope"), str | int | float)
        else None,
    )


def _approval_task_state(tasks: list[AgentTask]) -> str | None:
    if not tasks:
        return None
    states = {task.status for task in tasks}
    if any(state in {"failed", "error"} for state in states):
        return "failed"
    if any(state in {"running", "executing"} for state in states):
        return "executing"
    if states <= {"completed", "succeeded"}:
        return "completed"
    return "queued"


def _approval_summary(
    approval: Approval,
    *,
    requester: User | None,
    host: Host | None,
    tasks: list[AgentTask],
) -> ApprovalSummaryView:
    progress = {
        ApprovalStatus.pending.value: "awaiting_decision",
        ApprovalStatus.approved.value: "decision_recorded",
        ApprovalStatus.partially_approved.value: "decision_recorded",
        ApprovalStatus.approved_with_conditions.value: "decision_recorded",
        ApprovalStatus.changes_requested.value: "changes_requested",
        ApprovalStatus.rejected.value: "closed",
        ApprovalStatus.dry_run_only.value: "dry_run_requested",
        ApprovalStatus.executing.value: "executing",
        ApprovalStatus.executed.value: "completed",
        ApprovalStatus.failed.value: "failed",
        ApprovalStatus.rolled_back.value: "rolled_back",
        ApprovalStatus.expired.value: "expired",
        ApprovalStatus.withdrawn.value: "withdrawn",
    }.get(approval.status, approval.status)
    return ApprovalSummaryView(
        id=approval.id,
        incident_id=approval.incident_id,
        action_name=approval.action_name,
        status=approval.status,
        risk_level=approval.risk_level,
        target=_approval_target(approval, host),
        requester=_approval_actor(requester),
        requested_at=approval.requested_at,
        expires_at=approval.expires_at,
        progress_label=progress,
        execution_status=_approval_task_state(tasks),
    )


_APPROVAL_IMPACT_FIELDS: tuple[tuple[str, str], ...] = (
    ("service", "service"),
    ("scope", "scope"),
    ("downtime", "downtime"),
    ("affected_hosts", "affected_hosts"),
    ("affected_services", "affected_services"),
    ("estimated_duration", "estimated_duration"),
)


def _approval_impact_facts(approval: Approval) -> list[ApprovalFactView]:
    impact = approval.impact if isinstance(approval.impact, dict) else {}
    facts: list[ApprovalFactView] = []
    for source, key in _APPROVAL_IMPACT_FIELDS:
        value = impact.get(source)
        if isinstance(value, str | int | float | bool):
            facts.append(ApprovalFactView(key=key, value=str(value)[:240]))
        elif isinstance(value, list):
            safe_items = [
                str(item)[:80] for item in value[:20] if isinstance(item, str | int | float)
            ]
            if safe_items:
                facts.append(ApprovalFactView(key=key, value=", ".join(safe_items)[:500]))
    return facts


def _approval_steps(approval: Approval) -> list[ApprovalStepView]:
    parameters = approval.parameters if isinstance(approval.parameters, dict) else {}
    raw_actions = parameters.get("actions")
    if not isinstance(raw_actions, list):
        return []
    steps: list[ApprovalStepView] = []
    for index, raw_action in enumerate(raw_actions[:50], start=1):
        if not isinstance(raw_action, dict):
            continue
        action = raw_action.get("type")
        action_parameters = raw_action.get("parameters")
        if not isinstance(action, str) or not isinstance(action_parameters, dict):
            continue
        target = action_parameters.get("target")
        dry_run = action_parameters.get("dry_run")
        steps.append(
            ApprovalStepView(
                order=index,
                action=action[:120],
                target=str(target)[:240] if isinstance(target, str | int | float) else None,
                dry_run=str(dry_run).casefold() == "true" if dry_run is not None else False,
            )
        )
    return steps


@router.get(
    "/api/v1/approvals/presentation",
    response_model=list[ApprovalSummaryView],
    tags=["repairs"],
)
def list_approval_summaries(
    db: DB,
    _: Annotated[User, Depends(require_role(Role.operator))],
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ApprovalSummaryView]:
    expire_pending_approvals(db)
    approvals = list(
        db.scalars(
            select(Approval).order_by(desc(Approval.requested_at)).limit(limit).offset(offset)
        ).all()
    )
    requester_ids = {item.requested_by for item in approvals if item.requested_by}
    host_ids = {item.target_host_id for item in approvals if item.target_host_id}
    approval_ids = {item.id for item in approvals}
    users = (
        {item.id: item for item in db.scalars(select(User).where(User.id.in_(requester_ids))).all()}
        if requester_ids
        else {}
    )
    hosts = (
        {item.id: item for item in db.scalars(select(Host).where(Host.id.in_(host_ids))).all()}
        if host_ids
        else {}
    )
    tasks_by_approval: dict[str, list[AgentTask]] = {}
    if approval_ids:
        for task in db.scalars(
            select(AgentTask).where(AgentTask.approval_id.in_(approval_ids))
        ).all():
            if task.approval_id:
                tasks_by_approval.setdefault(task.approval_id, []).append(task)
    return [
        _approval_summary(
            approval,
            requester=users.get(approval.requested_by) if approval.requested_by else None,
            host=hosts.get(approval.target_host_id) if approval.target_host_id else None,
            tasks=tasks_by_approval.get(approval.id, []),
        )
        for approval in approvals
    ]


@router.get(
    "/api/v1/approvals/{approval_id}/presentation",
    response_model=ApprovalDetailView,
    tags=["repairs"],
)
def get_approval_presentation(
    approval_id: str,
    db: DB,
    _: Annotated[User, Depends(require_role(Role.operator))],
) -> ApprovalDetailView:
    approval = db.get(Approval, approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="approval not found")
    requester = db.get(User, approval.requested_by) if approval.requested_by else None
    approver = db.get(User, approval.decided_by) if approval.decided_by else None
    host = db.get(Host, approval.target_host_id) if approval.target_host_id else None
    tasks = list(
        db.scalars(
            select(AgentTask)
            .where(AgentTask.approval_id == approval.id)
            .order_by(AgentTask.created_at)
            .limit(100)
        ).all()
    )
    audit_entries = list(
        db.scalars(
            select(AuditLog)
            .where(
                AuditLog.resource_type == "approval",
                AuditLog.resource_id == approval.id,
            )
            .order_by(AuditLog.created_at)
            .limit(100)
        ).all()
    )
    audit_actor_ids = {entry.actor_id for entry in audit_entries if entry.actor_id}
    audit_actors = (
        {
            actor.id: actor
            for actor in db.scalars(select(User).where(User.id.in_(audit_actor_ids))).all()
        }
        if audit_actor_ids
        else {}
    )
    requester_actor = _approval_actor(requester)
    timeline = [
        ApprovalTimelineEntryView(
            at=approval.requested_at,
            event="requested",
            actor=requester_actor.label if requester_actor else None,
            outcome="pending",
        )
    ]
    for entry in audit_entries:
        entry_actor = _approval_actor(audit_actors.get(entry.actor_id)) if entry.actor_id else None
        timeline.append(
            ApprovalTimelineEntryView(
                at=entry.created_at,
                event=entry.action,
                actor=entry_actor.label if entry_actor else None,
                outcome=entry.outcome,
            )
        )
    completed_times = [task.completed_at for task in tasks if task.completed_at is not None]
    summary = _approval_summary(approval, requester=requester, host=host, tasks=tasks)
    impact = approval.impact if isinstance(approval.impact, dict) else {}
    risk_reason = impact.get("risk_reason")
    return ApprovalDetailView(
        **summary.model_dump(),
        risk_reason=str(risk_reason)[:500]
        if isinstance(risk_reason, str | int | float)
        else f"level_{approval.risk_level}_operational_change",
        approver=_approval_actor(approver),
        decided_at=approval.decided_at,
        executed_at=max(completed_times) if completed_times else None,
        impact_facts=_approval_impact_facts(approval),
        steps=_approval_steps(approval),
        dry_run_available=bool(impact.get("dry_run_available", False)),
        dry_run_status=_approval_task_state(tasks)
        if approval.status == ApprovalStatus.dry_run_only.value
        else None,
        recovery_point_label=approval.recovery_point_id,
        rollback_available=bool(approval.rollback_plan or approval.recovery_point_id),
        rollback_steps=[
            str(step)[:500] for step in approval.rollback_plan[:50] if isinstance(step, str)
        ],
        timeline=timeline,
        raw_evidence_available=bool(approval.parameters or approval.impact),
    )


@router.get(
    "/api/v1/approvals/{approval_id}/evidence",
    response_model=ApprovalEvidenceView,
    tags=["repairs"],
)
def get_approval_evidence(
    approval_id: str,
    db: DB,
    _: Annotated[User, Depends(require_role(Role.admin))],
) -> ApprovalEvidenceView:
    approval = db.get(Approval, approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="approval not found")
    parameters = redact_structure(approval.parameters)
    impact = redact_structure(approval.impact)
    return ApprovalEvidenceView(
        approval_id=approval.id,
        parameters=parameters if isinstance(parameters, dict) else {},
        impact=impact if isinstance(impact, dict) else {},
    )


@router.get("/api/v1/approvals", response_model=list[ApprovalView], tags=["repairs"])
def list_approvals(
    db: DB,
    _: Annotated[User, Depends(require_role(Role.operator))],
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Approval]:
    expire_pending_approvals(db)
    return list(
        db.scalars(
            select(Approval).order_by(desc(Approval.requested_at)).limit(limit).offset(offset)
        ).all()
    )


@router.post(
    "/api/v1/approvals/{approval_id}/decision", response_model=ApprovalView, tags=["repairs"]
)
async def decide_approval(
    approval_id: str,
    payload: ApprovalDecision,
    request: Request,
    db: DB,
    settings: Config,
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
    if (
        payload.decision
        in {
            ApprovalStatus.approved.value,
            ApprovalStatus.approved_with_conditions.value,
            ApprovalStatus.dry_run_only.value,
        }
        and approval.risk_level >= 2
        and approval.requested_by == user.id
    ):
        write_audit(
            db,
            actor=user,
            action="approval.self_approval_rejected",
            resource_type="approval",
            resource_id=approval.id,
            outcome="rejected",
            details={"action": approval.action_name, "risk_level": approval.risk_level},
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
        raise HTTPException(status_code=403, detail="requester cannot approve this high-risk task")
    if (
        payload.decision
        in {
            ApprovalStatus.approved.value,
            ApprovalStatus.approved_with_conditions.value,
        }
        and approval.risk_level >= 2
    ):
        if not payload.rollback_confirmed:
            raise HTTPException(
                status_code=422,
                detail="high-risk approval requires rollback confirmation",
            )
        if payload.current_password is None:
            raise HTTPException(
                status_code=422,
                detail="high-risk approval requires reauthentication",
            )
        _require_reauthentication_audited(
            db,
            user,
            payload.current_password,
            "approval.reauthenticate",
            request,
        )
    task_ids: list[str] = []
    if payload.decision in {
        ApprovalStatus.approved.value,
        ApprovalStatus.dry_run_only.value,
    }:
        agent_id = str(approval.parameters.get("agent_id", ""))
        agent = db.get(Agent, agent_id)
        raw_actions = approval.parameters.get("actions", [])
        if agent is None or not isinstance(raw_actions, list) or not raw_actions:
            raise HTTPException(status_code=409, detail="approval has no executable Agent plan")
        for raw_action in raw_actions:
            if not isinstance(raw_action, dict) or not isinstance(
                raw_action.get("parameters"), dict
            ):
                raise HTTPException(status_code=409, detail="approval Agent plan is invalid")
            action = str(raw_action.get("type", ""))
            parameters = {str(key): str(value) for key, value in raw_action["parameters"].items()}
            parameters["dry_run"] = (
                "true" if payload.decision == ApprovalStatus.dry_run_only.value else "false"
            )
            if action == "restricted_cleanup":
                expected_confirmation = f"CONFIRM CLEANUP {approval.id}"
                if payload.confirmation != expected_confirmation:
                    raise HTTPException(
                        status_code=409,
                        detail="restricted cleanup requires the exact second confirmation",
                    )
                parameters["second_confirmation"] = "confirmed"
            task = create_agent_task(
                db,
                agent_id=agent.id,
                action=action,
                parameters=parameters,
                settings=settings,
                approval_id=approval.id,
                requester_id=approval.requested_by,
                approver_id=user.id,
                target_host_id=approval.target_host_id or agent.host_id,
            )
            task_ids.append(task.id)
        attempt = db.scalar(
            select(RepairAttempt)
            .where(
                RepairAttempt.incident_id == approval.incident_id,
                RepairAttempt.action == approval.action_name,
                RepairAttempt.success.is_(None),
            )
            .order_by(desc(RepairAttempt.created_at))
        )
        if attempt is not None:
            attempt.after_state = {**attempt.after_state, "task_ids": task_ids}
            attempt.dry_run = payload.decision == ApprovalStatus.dry_run_only.value
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
        details={
            "confirmation_present": bool(payload.confirmation),
            "action": approval.action_name,
            "task_ids": task_ids,
        },
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    await event_broker.publish({"type": "approval.updated", "id": approval.id})
    return approval


@router.get("/api/v1/audit", response_model=list[AuditView], tags=["audit"])
def list_audit(
    db: DB,
    _: Annotated[User, Depends(require_role(Role.admin))],
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AuditLog]:
    return list(
        db.scalars(
            select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit).offset(offset)
        ).all()
    )


_AUDIT_ACTION_LABELS = {
    "auth.login": "Signed in",
    "auth.logout": "Signed out",
    "auth.login_failed": "Sign-in denied",
    "session.revoke": "Revoked session",
    "host.create": "Added host",
    "host.update": "Updated host",
    "host.delete": "Removed host",
    "host.stale": "Host became stale",
    "host.offline": "Host went offline",
    "host.register": "Registered host",
    "user.create": "Created user",
    "user.update": "Updated user",
    "user.delete": "Removed user",
    "approval.approved": "Approved operation",
    "approval.created": "Created approval",
    "approval.rejected": "Rejected operation",
    "notification.phase4_acceptance": "Sent Phase 4 acceptance notification",
}

_AUDIT_RESOURCE_LABELS = {
    "user": "User",
    "session": "Session",
    "host": "Host",
    "agent": "Guardian Agent",
    "alert": "Alert",
    "incident": "Incident",
    "approval": "Approval",
    "service_check": "Service check",
}


def _audit_source(source_ip: str | None) -> tuple[str, str]:
    if not source_ip:
        return ("internal_service", "Controller internal service")
    try:
        address = ip_address(source_ip)
    except ValueError:
        return ("unknown", "Unclassified source")
    if address.is_loopback:
        return ("internal_service", "Controller internal service")
    if address.is_private or address.is_link_local:
        return ("private_network", "Private network client")
    return ("external_client", "External client")


def _audit_severity(entry: AuditLog) -> str:
    if entry.outcome in {"failed", "denied", "error"}:
        return "critical" if entry.action.startswith(("auth.", "agent.", "user.")) else "warning"
    if any(word in entry.action for word in ("delete", "revoke", "disable", "offline")):
        return "warning"
    return "neutral"


def _audit_correlation_id(details: dict[str, object]) -> str | None:
    for key in ("correlation_id", "trace_id"):
        value = details.get(key)
        if isinstance(value, str) and value:
            return value[:128]
    return None


def _audit_request_id(details: dict[str, object]) -> str | None:
    value = details.get("request_id")
    return value[:128] if isinstance(value, str) and value else None


def _audit_resource_labels(db: Session, entries: list[AuditLog]) -> dict[tuple[str, str], str]:
    labels: dict[tuple[str, str], str] = {}
    model_fields: tuple[tuple[str, type[Any], Any], ...] = (
        ("host", Host, Host.name),
        ("user", User, User.email),
        ("incident", Incident, Incident.title),
        ("approval", Approval, Approval.action_name),
        ("service_check", ServiceCheck, ServiceCheck.name),
    )
    for resource_type, model, display_field in model_fields:
        ids = {
            entry.resource_id
            for entry in entries
            if entry.resource_type == resource_type and entry.resource_id
        }
        if not ids:
            continue
        for resource_id, display in db.execute(
            select(model.id, display_field).where(model.id.in_(ids))
        ).all():
            labels[(resource_type, resource_id)] = str(display)
    return labels


@router.get(
    "/api/v1/audit/presentation",
    response_model=list[AuditPresentationView],
    tags=["audit"],
)
def list_audit_presentations(
    db: DB,
    _: Annotated[User, Depends(require_role(Role.admin))],
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AuditPresentationView]:
    entries = list(
        db.scalars(
            select(AuditLog)
            .order_by(desc(AuditLog.created_at))
            .limit(limit)
            .offset(offset)
        ).all()
    )
    actor_ids = {entry.actor_id for entry in entries if entry.actor_id}
    actors = {
        user.id: user.email
        for user in db.scalars(select(User).where(User.id.in_(actor_ids))).all()
    } if actor_ids else {}
    resources = _audit_resource_labels(db, entries)
    result: list[AuditPresentationView] = []
    for entry in entries:
        source_type, source_display = _audit_source(entry.source_ip)
        actor_display = actors.get(entry.actor_id or "")
        if entry.action.startswith("agent.") and entry.actor_id is None:
            actor_type = "agent"
            actor_display = "Guardian Agent"
            source_display = "Agent certificate identity"
        elif actor_display:
            actor_type = "user"
        elif entry.actor_id is None:
            actor_type = "system"
        else:
            actor_type = "unknown"
        resource_display = resources.get(
            (entry.resource_type, entry.resource_id or ""),
            _AUDIT_RESOURCE_LABELS.get(entry.resource_type, "Unknown resource"),
        )
        result.append(
            AuditPresentationView(
                event_id=entry.id,
                display_action=_AUDIT_ACTION_LABELS.get(
                    entry.action, "Unknown audit action"
                ),
                action_code=entry.action,
                category=entry.action.partition(".")[0] or "system",
                severity=cast(Any, _audit_severity(entry)),
                result=entry.outcome,
                actor_display=actor_display
                or ("Controller service" if entry.actor_id is None else "Unknown actor"),
                actor_type=cast(Any, actor_type),
                resource_display=resource_display,
                resource_type=entry.resource_type,
                source_display=source_display,
                source_type=cast(Any, source_type),
                created_at=entry.created_at,
                summary=(
                    f"{_AUDIT_ACTION_LABELS.get(entry.action, 'Unknown audit action')} · "
                    f"{resource_display}"
                ),
                correlation_id=_audit_correlation_id(entry.details),
                request_id=_audit_request_id(entry.details),
                evidence_available=bool(entry.details or entry.resource_id or entry.source_ip),
            )
        )
    return result


@router.get("/api/v1/audit/export", tags=["audit"])
def export_audit_presentations(
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.admin))],
    format: Literal["csv", "jsonl"] = "csv",
    limit: Annotated[int, Query(ge=1, le=200)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
    query: Annotated[str | None, Query(max_length=160)] = None,
    result: Annotated[str | None, Query(max_length=32)] = None,
    category: Annotated[str | None, Query(max_length=64)] = None,
    severity: Annotated[str | None, Query(max_length=32)] = None,
    source_type: Annotated[str | None, Query(max_length=32)] = None,
    actor_type: Annotated[str | None, Query(max_length=32)] = None,
    resource_type: Annotated[str | None, Query(max_length=64)] = None,
) -> StreamingResponse:
    entries = list_audit_presentations(db, user, limit=limit, offset=offset)
    needle = (query or "").casefold().strip()
    entries = [
        entry
        for entry in entries
        if (result is None or entry.result == result)
        and (category is None or entry.category == category)
        and (severity is None or entry.severity == severity)
        and (source_type is None or entry.source_type == source_type)
        and (actor_type is None or entry.actor_type == actor_type)
        and (resource_type is None or entry.resource_type == resource_type)
        and (
            not needle
            or needle
            in " ".join(
                (
                    entry.display_action,
                    entry.resource_display,
                    entry.actor_display,
                    entry.source_display,
                    entry.correlation_id or "",
                    entry.request_id or "",
                )
            ).casefold()
        )
    ]
    rows = [
        {
            "event_id": entry.event_id,
            "created_at": entry.created_at.isoformat(),
            "action": entry.display_action,
            "category": entry.category,
            "severity": entry.severity,
            "result": entry.result,
            "actor": entry.actor_display,
            "resource": entry.resource_display,
            "resource_type": entry.resource_type,
            "source": entry.source_display,
            "summary": entry.summary,
            "correlation_id": entry.correlation_id or "",
            "request_id": entry.request_id or "",
        }
        for entry in entries
    ]
    output = io.StringIO()
    if format == "csv":
        fieldnames = list(rows[0]) if rows else [
            "event_id",
            "created_at",
            "action",
            "category",
            "severity",
            "result",
            "actor",
            "resource",
            "resource_type",
            "source",
            "summary",
            "correlation_id",
            "request_id",
        ]
        csv_rows = [
            {
                key: f"'{value}"
                if isinstance(value, str) and value.startswith(("=", "+", "-", "@"))
                else value
                for key, value in row.items()
            }
            for row in rows
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)
        media_type = "text/csv"
    else:
        output.write("\n".join(json.dumps(row, ensure_ascii=False) for row in rows))
        output.write("\n")
        media_type = "application/x-ndjson"
    write_audit(
        db,
        actor=user,
        action="audit.export",
        resource_type="audit",
        resource_id=None,
        outcome="success",
        details={"format": format, "row_count": len(rows), "offset": offset},
        source_ip=request.client.host if request.client else None,
    )
    db.commit()
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="guardian-audit.{format}"'},
    )


@router.get(
    "/api/v1/audit/{audit_id}/evidence",
    response_model=AuditEvidenceView,
    tags=["audit"],
)
def get_audit_evidence(
    audit_id: int,
    db: DB,
    _: Annotated[User, Depends(require_role(Role.admin))],
) -> AuditEvidenceView:
    entry = db.get(AuditLog, audit_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="audit entry not found")
    return AuditEvidenceView(
        audit_id=entry.id,
        action_code=entry.action,
        resource_type=entry.resource_type,
        resource_id=entry.resource_id,
        actor_id=entry.actor_id,
        source_ip=entry.source_ip,
        changes=cast(dict[str, Any], redact_structure(entry.details)),
        correlation_id=_audit_correlation_id(entry.details),
    )


@router.get("/api/v1/recovery-points", response_model=list[RecoveryPointView], tags=["recovery"])
def list_recovery_points(
    db: DB,
    _: Annotated[User, Depends(require_role(Role.operator))],
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[RecoveryPoint]:
    return list(
        db.scalars(
            select(RecoveryPoint)
            .order_by(desc(RecoveryPoint.created_at))
            .limit(limit)
            .offset(offset)
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
    catalog = [
        {
            "key": "environment",
            "value": settings.environment,
            "source": "GUARDIAN_ENVIRONMENT",
            "restart_required": True,
            "risk": "high",
        },
        {
            "key": "deployment_stage",
            "value": settings.deployment_stage,
            "source": "GUARDIAN_DEPLOYMENT_STAGE",
            "restart_required": True,
            "risk": "high",
        },
        {
            "key": "secure_cookies",
            "value": settings.secure_cookies,
            "source": "GUARDIAN_SECURE_COOKIES",
            "restart_required": True,
            "risk": "high",
        },
        {
            "key": "allowed_origins",
            "value": settings.allowed_origins,
            "source": "GUARDIAN_ALLOWED_ORIGINS",
            "restart_required": True,
            "risk": "high",
        },
        {
            "key": "agent_offline_after_seconds",
            "value": settings.agent_offline_after_seconds,
            "source": "GUARDIAN_AGENT_OFFLINE_AFTER_SECONDS",
            "restart_required": True,
            "risk": "medium",
        },
        {
            "key": "metric_retention_days",
            "value": settings.metric_retention_days,
            "source": "GUARDIAN_METRIC_RETENTION_DAYS",
            "restart_required": True,
            "risk": "medium",
        },
        {
            "key": "service_result_retention_days",
            "value": settings.service_result_retention_days,
            "source": "GUARDIAN_SERVICE_RESULT_RETENTION_DAYS",
            "restart_required": True,
            "risk": "medium",
        },
        {
            "key": "external_notifications_enabled",
            "value": settings.external_notifications_enabled,
            "source": "GUARDIAN_EXTERNAL_NOTIFICATIONS_ENABLED",
            "restart_required": True,
            "risk": "high",
        },
    ]
    return {
        "environment": settings.environment,
        "deployment_stage": settings.deployment_stage,
        "release_version": settings.release_version,
        "deployment_commit": settings.deployment_commit,
        "deployed_at": settings.deployed_at.isoformat() if settings.deployed_at else None,
        "secure_cookies": settings.secure_cookies,
        "auto_create_schema": settings.auto_create_schema,
        "allowed_origins": settings.allowed_origins,
        "max_incident_log_bytes": settings.max_incident_log_bytes,
        "login_attempts_per_10m": settings.login_attempts_per_10m,
        "nonce_ttl_seconds": settings.nonce_ttl_seconds,
        "agent_offline_after_seconds": settings.agent_offline_after_seconds,
        "agent_pending_identity_ttl_minutes": settings.agent_pending_identity_ttl_minutes,
        "approval_ttl_minutes": settings.approval_ttl_minutes,
        "metric_retention_days": settings.metric_retention_days,
        "service_result_retention_days": settings.service_result_retention_days,
        "max_metric_rows_per_host": settings.max_metric_rows_per_host,
        "max_results_per_check": settings.max_results_per_check,
        "external_notifications_enabled": settings.external_notifications_enabled,
        "settings_catalog": catalog,
        "secret_status": {
            "database_reference": settings.database_url_file is not None,
            "token_signing_material": settings.jwt_secret.get_secret_value()
            != "development-only-change-me-32-bytes",
            "field_encryption_material": bool(settings.field_encryption_key.get_secret_value()),
            "agent_enrollment_material": settings.agent_enrollment_token.get_secret_value()
            != "development-enrollment-token",
            "trusted_proxy_header_secret": bool(
                settings.trusted_proxy_cert_header_secret.get_secret_value()
            ),
        },
        "features": {
            "mtls": True,
            "request_signatures": True,
            "totp": True,
            "level2_default_enabled": False,
            "level3_requires_approval": True,
            "arbitrary_shell": False,
            "multi_vps_enrollment": True,
            "persistent_alerts": True,
            "notification_retry": True,
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
        ),
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
    if db.scalar(select(AgentIdentity).where(AgentIdentity.certificate_fingerprint == fingerprint)):
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
            expires_at=created_at + timedelta(minutes=settings.agent_pending_identity_ttl_minutes),
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
    "/api/v1/agents/{agent_id}/certificate/renew",
    response_model=AgentRenewResponse,
    tags=["agent"],
)
async def renew_agent_certificate(
    agent_id: str,
    payload: AgentRenewRequest,
    request: Request,
    db: DB,
    settings: Config,
) -> AgentRenewResponse:
    request_body = await request.body()
    agent = lock_active_agent(db, agent_id)
    authenticated_identity = verify_agent_request(
        request=request,
        agent=agent,
        payload=request_body,
        db=db,
        settings=settings,
    )
    if authenticated_identity.state != AgentIdentityState.active.value:
        db.rollback()
        raise HTTPException(status_code=409, detail="only the active identity can renew")
    try:
        validate_agent_csr(payload.csr_pem)
        verify_signing_key_proof(
            csr_pem=payload.csr_pem,
            signing_public_key=payload.signing_public_key,
            signing_key_proof=payload.signing_key_proof,
        )
    except AgentCertificateError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.agent_id == agent.id,
            AgentIdentity.rotation_id == payload.rotation_id,
        )
    ):
        db.rollback()
        raise HTTPException(status_code=409, detail="rotation id already used")
    try:
        issued = issue_agent_certificate(
            csr_pem=payload.csr_pem,
            agent_id=agent.id,
            host_id=agent.host_id,
            settings=settings,
        )
    except AgentCertificateError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="certificate issuance unavailable") from exc
    if db.scalar(
        select(AgentIdentity).where(
            (AgentIdentity.certificate_fingerprint == issued.fingerprint)
            | (AgentIdentity.certificate_serial == issued.serial)
        )
    ):
        db.rollback()
        raise HTTPException(status_code=409, detail="certificate identity already enrolled")
    renewed_at = datetime.now(UTC)
    try:
        generation = claim_agent_identity_version(db, agent, payload.expected_version)
        authenticated_identity.state = AgentIdentityState.retiring.value
        authenticated_identity.retiring_at = renewed_at
        identity = AgentIdentity(
            agent_id=agent.id,
            generation=generation,
            rotation_id=payload.rotation_id,
            state=AgentIdentityState.active.value,
            signing_public_key=payload.signing_public_key,
            certificate_fingerprint=issued.fingerprint,
            certificate_serial=issued.serial,
            expires_at=issued.expires_at,
            verified_at=renewed_at,
            activated_at=renewed_at,
        )
        db.add(identity)
        agent.signing_public_key = payload.signing_public_key
        agent.certificate_fingerprint = issued.fingerprint
        agent.certificate_serial = issued.serial
        db.flush()
        write_audit(
            db,
            actor=None,
            action="agent.certificate_renewed",
            resource_type="agent_identity",
            resource_id=identity.id,
            outcome="success",
            details={
                "agent_id": agent.id,
                "generation": generation,
                "rotation_id": payload.rotation_id,
                "previous_generation": authenticated_identity.generation,
                "certificate_serial": issued.serial,
                "certificate_expires_at": issued.expires_at.isoformat(),
            },
            source_ip=request.client.host if request.client else None,
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="certificate identity conflict") from exc
    return AgentRenewResponse(
        identity=identity,
        certificate_pem=issued.certificate_pem,
        ca_bundle_pem=issued.ca_bundle_pem,
        certificate_expires_at=issued.expires_at,
    )


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
    require_matching_crl_publication(db, payload, identity.certificate_serial)
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


def require_matching_crl_publication(
    db: Session,
    payload: AgentIdentityRevokeRequest,
    certificate_serial: str | None,
) -> AuditLog:
    publication = db.scalar(
        select(AuditLog)
        .where(
            AuditLog.action == "gateway.crl_publication",
            AuditLog.outcome == "success",
            AuditLog.resource_id == str(payload.crl_number),
        )
        .order_by(AuditLog.id.desc())
    )
    if (
        certificate_serial is None
        or publication is None
        or publication.details.get("sha256") != payload.crl_sha256
        or publication.details.get("certificate_serial") != certificate_serial
    ):
        raise HTTPException(status_code=409, detail="matching CRL publication is not verified")
    return publication


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
    payload: AgentIdentityRevokeRequest,
    request: Request,
    db: DB,
    user: Annotated[User, Depends(require_role(Role.owner))],
) -> None:
    agent = lock_active_agent(db, agent_id)
    active_identity = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.agent_id == agent.id,
            AgentIdentity.state == AgentIdentityState.active.value,
        )
    )
    if active_identity is None:
        raise HTTPException(status_code=409, detail="active Agent identity is missing")
    require_matching_crl_publication(db, payload, active_identity.certificate_serial)
    new_version = claim_agent_identity_version(db, agent, payload.expected_version)
    revoked_at = datetime.now(UTC)
    active_identity.state = AgentIdentityState.revoked.value
    active_identity.revoked_at = revoked_at
    agent.revoked_at = revoked_at
    write_audit(
        db,
        actor=user,
        action="agent.revoke",
        resource_type="agent",
        resource_id=agent.id,
        outcome="success",
        details={
            "certificate_fingerprint_suffix": agent.certificate_fingerprint[-12:],
            "certificate_serial": active_identity.certificate_serial,
            "identity_version": new_version,
            "crl_number": payload.crl_number,
            "crl_sha256": payload.crl_sha256,
        },
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
    if not enrollment_token:
        raise HTTPException(status_code=401, detail="invalid enrollment token")
    host: Host | None = None
    one_time_enrollment = True
    try:
        _, host = consume_enrollment_token(db, value=enrollment_token)
    except EnrollmentTokenError as exc:
        expected = settings.agent_enrollment_token.get_secret_value()
        legacy_allowed = settings.environment != "production" and secrets.compare_digest(
            enrollment_token, expected
        )
        if not legacy_allowed:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        one_time_enrollment = False
    fingerprint = normalize_certificate_fingerprint(payload.certificate_fingerprint)
    certificate_serial = None
    if settings.environment == "production":
        trusted_fingerprint, certificate_serial = trusted_client_certificate_identity(
            request,
            settings,
        )
        if not secrets.compare_digest(fingerprint, trusted_fingerprint):
            raise HTTPException(status_code=401, detail="enrollment certificate mismatch")
    if db.scalar(select(AgentIdentity).where(AgentIdentity.certificate_fingerprint == fingerprint)):
        raise HTTPException(status_code=409, detail="certificate already enrolled")
    if certificate_serial and db.scalar(
        select(AgentIdentity).where(AgentIdentity.certificate_serial == certificate_serial)
    ):
        raise HTTPException(status_code=409, detail="certificate serial already enrolled")
    try:
        enrolled_at = datetime.now(UTC)
        if host is not None and host.name != payload.host.name:
            raise HTTPException(status_code=409, detail="enrollment token host mismatch")
        if host is None:
            host = db.scalar(select(Host).where(Host.name == payload.host.name))
        if host is None:
            host = Host(**payload.host.model_dump())
            db.add(host)
            db.flush()
        agent = db.scalar(select(Agent).where(Agent.host_id == host.id))
        if agent is not None and agent.revoked_at is None:
            raise HTTPException(status_code=409, detail="host already has an active agent")
        if agent is None:
            agent = Agent(
                host_id=host.id,
                signing_public_key=payload.signing_public_key,
                certificate_fingerprint=fingerprint,
                certificate_serial=certificate_serial,
                version=payload.version,
            )
            db.add(agent)
            db.flush()
        else:
            agent.identity_version += 1
            agent.signing_public_key = payload.signing_public_key
            agent.certificate_fingerprint = fingerprint
            agent.certificate_serial = certificate_serial
            agent.version = payload.version
            agent.revoked_at = None
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
        host.enrolled_at = enrolled_at
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
                "one_time_token": one_time_enrollment,
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
    if not agent.host.enabled:
        raise HTTPException(status_code=403, detail="host monitoring is disabled")
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
    if payload.build is not None:
        agent.build_git_sha = payload.build.git_sha
        agent.build_id = payload.build.build_id
        agent.build_time = payload.build.build_time
        agent.go_version = payload.build.go_version
        agent.platform_os = payload.build.os
        agent.platform_arch = payload.build.arch
        agent.build_dirty = payload.build.dirty
        agent.binary_sha256 = payload.build.binary_sha256
    agent.host.last_seen_at = now
    agent.host.status = "healthy"
    agent.host.data_state = "agent_error" if payload.metrics.get("collection_error") else "normal"
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
    record_agent_check_results(db, agent=agent, services=payload.services, now=now)
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
    assigned_checks = assigned_agent_checks(db, agent)
    db.commit()
    await event_broker.publish({"type": "host.heartbeat", "host_id": agent.host_id})
    return {
        "accepted": True,
        "server_time": now.isoformat(),
        "identity_state": authenticated_identity.state,
        "identity_version": agent.identity_version,
        "tasks": serialized_tasks,
        "checks": assigned_checks,
    }
