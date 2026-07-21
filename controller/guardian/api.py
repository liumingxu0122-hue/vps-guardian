from __future__ import annotations

import secrets
import shlex
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal, cast

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
from guardian.alerting import acknowledge_alert, silence_alert
from guardian.audit import write_audit
from guardian.backup import (
    RecoveryPointNotFoundError,
    RecoveryPointPromotionConflict,
    RecoveryVerificationAttestation,
    promote_recovery_point,
)
from guardian.config import Settings, get_settings
from guardian.database import get_db
from guardian.enrollment import (
    EnrollmentTokenError,
    consume_enrollment_token,
    issue_enrollment_token,
)
from guardian.events import event_broker
from guardian.models import (
    Agent,
    AgentIdentity,
    AgentIdentityState,
    AgentTask,
    AlertInstance,
    AlertRule,
    Approval,
    ApprovalStatus,
    AuditLog,
    Host,
    Incident,
    MetricSnapshot,
    NotificationChannel,
    RecoveryPoint,
    RepairAttempt,
    Role,
    ServiceCheck,
    User,
)
from guardian.monitoring import assigned_agent_checks, record_agent_check_results
from guardian.notifications import NotificationConfigurationError, send_test_notification
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
    AlertRuleCreate,
    AlertRuleView,
    AlertSilenceRequest,
    AlertView,
    ApprovalDecision,
    ApprovalView,
    AuditView,
    EnrollmentTokenIssue,
    EnrollmentTokenView,
    HealthResponse,
    HostCreate,
    HostUpdate,
    HostView,
    IncidentView,
    LoginRequest,
    LoginResponse,
    NotificationChannelCreate,
    NotificationChannelView,
    RecoveryPointPromotionView,
    RecoveryPointVerifyRequest,
    RecoveryPointView,
    ServiceCheckCreate,
    ServiceCheckView,
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


def _snapshot_metric(snapshot: MetricSnapshot | None, key: str) -> float:
    if snapshot is None:
        return -1.0
    value = snapshot.payload.get(key)
    return float(value) if isinstance(value, int | float) else -1.0


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
    return hosts


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
    controller_url = str(request.base_url).rstrip("/")
    command = (
        "sudo ./scripts/install-agent.sh "
        "--binary ./agent-bundle/vps-guardian-agent "
        ' --sha256 "$(cat ./agent-bundle/vps-guardian-agent.sha256)" '
        f"--controller-url {shlex.quote(controller_url)} "
        f"--agent-name {shlex.quote(host.name)} "
        f"--agent-address {shlex.quote(host.address)} "
        "--certificate ./agent-bundle/agent.crt "
        "--private-key ./agent-bundle/agent.key "
        "--agent-ca ./agent-bundle/agent-ca.crt "
        "--server-ca ./agent-bundle/controller-ca.crt "
        "--signing-key ./agent-bundle/signing-ed25519.pem "
        ' --controller-public-key "$(cat ./agent-bundle/controller-public-key.txt)" '
        "--enrollment-token-file ./agent-bundle/enrollment-token"
    )
    return EnrollmentTokenView(
        token=issued.value,
        expires_at=issued.expires_at,
        install_command=command,
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


@router.get(
    "/api/v1/service-checks", response_model=list[ServiceCheckView], tags=["monitoring"]
)
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
) -> list[AlertInstance]:
    statement = select(AlertInstance)
    if state:
        statement = statement.where(AlertInstance.state == state)
    return list(db.scalars(statement.order_by(desc(AlertInstance.last_observed_at))).all())


@router.post(
    "/api/v1/alerts/{alert_id}/acknowledge", response_model=AlertView, tags=["alerts"]
)
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
        silence_alert(
            db, alert=alert, actor=user, reason=payload.reason, until=payload.until
        )
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
        payload.decision in {ApprovalStatus.approved.value, ApprovalStatus.dry_run_only.value}
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
    task_ids: list[str] = []
    if payload.decision in {ApprovalStatus.approved.value, ApprovalStatus.dry_run_only.value}:
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
            parameters = {
                str(key): str(value) for key, value in raw_action["parameters"].items()
            }
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
        "metric_retention_days": settings.metric_retention_days,
        "service_result_retention_days": settings.service_result_retention_days,
        "max_metric_rows_per_host": settings.max_metric_rows_per_host,
        "max_results_per_check": settings.max_results_per_check,
        "external_notifications_enabled": settings.external_notifications_enabled,
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
    agent.host.last_seen_at = now
    agent.host.status = "healthy"
    agent.host.data_state = (
        "agent_error" if payload.metrics.get("collection_error") else "normal"
    )
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
