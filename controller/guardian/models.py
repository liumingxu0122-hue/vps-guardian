from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import Mapped, Session, mapped_column, relationship

from guardian.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def default_approval_expiry() -> datetime:
    return utcnow() + timedelta(minutes=30)


_RECOVERY_ATTESTATION_HEX_REMAINDER = "lower(attestation_digest)"
for _hex_character in "0123456789abcdef":
    _RECOVERY_ATTESTATION_HEX_REMAINDER = (
        f"replace({_RECOVERY_ATTESTATION_HEX_REMAINDER}, '{_hex_character}', '')"
    )


class Role(StrEnum):
    viewer = "viewer"
    operator = "operator"
    admin = "admin"
    owner = "owner"


class HostStatus(StrEnum):
    unknown = "unknown"
    healthy = "healthy"
    degraded = "degraded"
    offline = "offline"


class HostDataState(StrEnum):
    normal = "normal"
    no_data = "no_data"
    stale = "stale"
    offline = "offline"
    agent_error = "agent_error"


class ServiceCheckKind(StrEnum):
    http = "http"
    https = "https"
    tcp = "tcp"
    icmp = "icmp"
    docker = "docker"
    systemd = "systemd"


class CheckResultStatus(StrEnum):
    ok = "ok"
    failed = "failed"
    unsupported = "unsupported"
    error = "error"


class AlertState(StrEnum):
    ok = "ok"
    pending = "pending"
    firing = "firing"
    acknowledged = "acknowledged"
    silenced = "silenced"
    resolved = "resolved"


class AlertSeverity(StrEnum):
    info = "info"
    warning = "warning"
    critical = "critical"


class NotificationKind(StrEnum):
    telegram = "telegram"
    smtp = "smtp"
    webhook = "webhook"


class IncidentStatus(StrEnum):
    open = "open"
    investigating = "investigating"
    mitigated = "mitigated"
    resolved = "resolved"


class ApprovalStatus(StrEnum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    dry_run_only = "dry_run_only"
    executed = "executed"
    expired = "expired"


class AgentIdentityState(StrEnum):
    pending = "pending"
    active = "active"
    retiring = "retiring"
    revoked = "revoked"
    retired = "retired"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default=Role.viewer.value)
    totp_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(120), unique=True)
    address: Mapped[str] = mapped_column(String(255))
    os_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    location: Mapped[str | None] = mapped_column(String(120), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default=HostStatus.unknown.value)
    data_state: Mapped[str] = mapped_column(
        String(32), default=HostDataState.no_data.value, server_default="no_data"
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    group_name: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list, server_default="[]")
    labels: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    agent: Mapped[Agent | None] = relationship(back_populates="host", uselist=False)


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), unique=True)
    signing_public_key: Mapped[str] = mapped_column(Text)
    certificate_fingerprint: Mapped[str] = mapped_column(String(128), unique=True)
    certificate_serial: Mapped[str | None] = mapped_column(
        String(128), nullable=True, unique=True
    )
    identity_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    host: Mapped[Host] = relationship(back_populates="agent")
    identities: Mapped[list[AgentIdentity]] = relationship(
        back_populates="agent",
        cascade="all, delete-orphan",
    )


class AgentIdentity(Base):
    __tablename__ = "agent_identities"
    __table_args__ = (
        CheckConstraint(
            "state IN ('pending', 'active', 'retiring', 'revoked', 'retired')",
            name="ck_agent_identity_state",
        ),
        CheckConstraint("generation >= 1", name="ck_agent_identity_generation"),
        CheckConstraint(
            "successful_heartbeats >= 0",
            name="ck_agent_identity_successful_heartbeats",
        ),
        UniqueConstraint("agent_id", "generation", name="uq_agent_identity_generation"),
        UniqueConstraint("agent_id", "rotation_id", name="uq_agent_identity_rotation_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id: Mapped[str] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), index=True
    )
    generation: Mapped[int] = mapped_column(Integer)
    rotation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    state: Mapped[str] = mapped_column(String(16), index=True)
    signing_public_key: Mapped[str] = mapped_column(Text)
    certificate_fingerprint: Mapped[str] = mapped_column(String(128), unique=True)
    certificate_serial: Mapped[str | None] = mapped_column(
        String(128), nullable=True, unique=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    successful_heartbeats: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0"
    )
    last_pending_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retiring_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    agent: Mapped[Agent] = relationship(back_populates="identities")


class MetricSnapshot(Base):
    __tablename__ = "metric_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    payload: Mapped[dict[str, object]] = mapped_column(JSON)


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"
    __table_args__ = (
        CheckConstraint("length(token_hash) = 64", name="ck_enrollment_token_hash_length"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ServiceCheck(Base):
    __tablename__ = "service_checks"
    __table_args__ = (
        CheckConstraint("interval_seconds >= 15", name="ck_service_check_interval"),
        CheckConstraint("timeout_seconds >= 1", name="ck_service_check_timeout"),
        CheckConstraint("failure_threshold >= 1", name="ck_service_check_failure_threshold"),
        CheckConstraint("recovery_threshold >= 1", name="ck_service_check_recovery_threshold"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(120), unique=True)
    kind: Mapped[str] = mapped_column(String(24), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    host_id: Mapped[str | None] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=True, index=True
    )
    runner_agent_id: Mapped[str | None] = mapped_column(
        ForeignKey("agents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    configuration: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    group_name: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=5)
    failure_threshold: Mapped[int] = mapped_column(Integer, default=3)
    recovery_threshold: Mapped[int] = mapped_column(Integer, default=2)
    severity: Mapped[str] = mapped_column(String(16), default=AlertSeverity.warning.value)
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ServiceCheckResult(Base):
    __tablename__ = "service_check_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    check_id: Mapped[str] = mapped_column(
        ForeignKey("service_checks.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(24), index=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    details: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)


class AlertRule(Base):
    __tablename__ = "alert_rules"
    __table_args__ = (
        CheckConstraint("failure_threshold >= 1", name="ck_alert_rule_failure_threshold"),
        CheckConstraint("recovery_threshold >= 1", name="ck_alert_rule_recovery_threshold"),
        CheckConstraint("repeat_interval_seconds >= 60", name="ck_alert_rule_repeat_interval"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(120), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    source_type: Mapped[str] = mapped_column(String(32), index=True)
    source_id: Mapped[str] = mapped_column(String(36), index=True)
    severity: Mapped[str] = mapped_column(String(16), default=AlertSeverity.warning.value)
    group_key: Mapped[str] = mapped_column(String(120), default="default")
    failure_threshold: Mapped[int] = mapped_column(Integer, default=3)
    recovery_threshold: Mapped[int] = mapped_column(Integer, default=2)
    repeat_interval_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    escalation_after_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    recovery_notifications: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AlertInstance(Base):
    __tablename__ = "alert_instances"
    __table_args__ = (
        CheckConstraint("consecutive_failures >= 0", name="ck_alert_failures"),
        CheckConstraint("consecutive_successes >= 0", name="ck_alert_successes"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id: Mapped[str] = mapped_column(
        ForeignKey("alert_rules.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    state: Mapped[str] = mapped_column(String(24), default=AlertState.ok.value, index=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    consecutive_successes: Mapped[int] = mapped_column(Integer, default=0)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    fired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    silenced_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_notified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    notification_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(String(512), default="")
    details: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)


class AlertTransition(Base):
    __tablename__ = "alert_transitions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alert_instances.id", ondelete="CASCADE"), index=True
    )
    previous_state: Mapped[str] = mapped_column(String(24))
    current_state: Mapped[str] = mapped_column(String(24), index=True)
    reason: Mapped[str] = mapped_column(String(255))
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class MaintenanceWindow(Base):
    __tablename__ = "maintenance_windows"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(120), unique=True)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    matchers: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AlertSilence(Base):
    __tablename__ = "alert_silences"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id: Mapped[str | None] = mapped_column(
        ForeignKey("alert_instances.id", ondelete="CASCADE"), nullable=True, index=True
    )
    matchers: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    reason: Mapped[str] = mapped_column(String(255))
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(120), unique=True)
    kind: Mapped[str] = mapped_column(String(24), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    configuration: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, default=30)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    channel_id: Mapped[str] = mapped_column(
        ForeignKey("notification_channels.id", ondelete="CASCADE"), index=True
    )
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alert_instances.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    response_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_summary: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title: Mapped[str] = mapped_column(String(255))
    fault_type: Mapped[str] = mapped_column(String(120), index=True)
    severity: Mapped[int] = mapped_column(Integer, default=2)
    status: Mapped[str] = mapped_column(String(32), default=IncidentStatus.open.value, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    affected_hosts: Mapped[list[str]] = mapped_column(JSON, default=list)
    affected_services: Mapped[list[str]] = mapped_column(JSON, default=list)
    evidence: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)
    excluded_causes: Mapped[list[str]] = mapped_column(JSON, default=list)
    recommendations: Mapped[list[str]] = mapped_column(JSON, default=list)
    auto_repair_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    risk: Mapped[str] = mapped_column(String(255), default="unknown")
    verification_plan: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    timeline: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)


class Approval(Base):
    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    action_name: Mapped[str] = mapped_column(String(120))
    risk_level: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), default=ApprovalStatus.pending.value)
    parameters: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    impact: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    recovery_point_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    rollback_plan: Mapped[list[str]] = mapped_column(JSON, default=list)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=default_approval_expiry, index=True
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    requested_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    target_host_id: Mapped[str | None] = mapped_column(
        ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(120), index=True)
    resource_type: Mapped[str] = mapped_column(String(80))
    resource_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    outcome: Mapped[str] = mapped_column(String(32))
    details: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


@event.listens_for(Session, "before_flush")
def prevent_audit_mutation(
    session: Session, flush_context: object, instances: object | None
) -> None:
    del flush_context, instances
    changed = session.dirty.union(session.deleted)
    if any(isinstance(entry, AuditLog) for entry in changed):
        raise ValueError("audit records are append-only")


class Nonce(Base):
    __tablename__ = "nonces"

    value: Mapped[str] = mapped_column(String(128), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(36), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class AgentTask(Base):
    __tablename__ = "agent_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    approval_id: Mapped[str | None] = mapped_column(
        ForeignKey("approvals.id", ondelete="SET NULL"), nullable=True, index=True
    )
    requester_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    approver_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    target_host_id: Mapped[str | None] = mapped_column(
        ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(120))
    parameters: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    nonce: Mapped[str] = mapped_column(String(128), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    signature: Mapped[str] = mapped_column(Text)
    result: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    verification_result: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RepairAttempt(Base):
    __tablename__ = "repair_attempts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    action: Mapped[str] = mapped_column(String(120), index=True)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True)
    success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    before_state: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    after_state: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class RecoveryPoint(Base):
    __tablename__ = "recovery_points"

    __table_args__ = (
        CheckConstraint(
            "verification_version >= 0",
            name="ck_recovery_point_verification_version",
        ),
        CheckConstraint(
            "(verified = false AND verified_at IS NULL "
            "AND attestation_digest IS NULL AND verification_version = 0) OR "
            "(verified = true AND verified_at IS NOT NULL "
            "AND attestation_digest IS NOT NULL AND verification_version >= 1)",
            name="ck_recovery_point_verification_state",
        ),
        CheckConstraint(
            "attestation_digest IS NULL OR "
            "(length(attestation_digest) = 64 "
            "AND lower(attestation_digest) = attestation_digest "
            f"AND {_RECOVERY_ATTESTATION_HEX_REMAINDER} = '')",
            name="ck_recovery_point_attestation_digest",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    service_name: Mapped[str] = mapped_column(String(120), index=True)
    snapshot_id: Mapped[str] = mapped_column(String(128), unique=True)
    manifest: Mapped[dict[str, object]] = mapped_column(JSON)
    checksum: Mapped[str] = mapped_column(String(128))
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_version: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    attestation_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


Index("ix_repair_action_created", RepairAttempt.action, RepairAttempt.created_at)
Index(
    "uq_agent_identity_one_active",
    AgentIdentity.agent_id,
    unique=True,
    sqlite_where=AgentIdentity.state == AgentIdentityState.active.value,
    postgresql_where=AgentIdentity.state == AgentIdentityState.active.value,
)
Index(
    "uq_agent_identity_one_pending",
    AgentIdentity.agent_id,
    unique=True,
    sqlite_where=AgentIdentity.state == AgentIdentityState.pending.value,
    postgresql_where=AgentIdentity.state == AgentIdentityState.pending.value,
)
