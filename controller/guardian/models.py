from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from sqlalchemy import (
    JSON,
    BigInteger,
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
    false,
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
    closed = "closed"


class AlertSeverity(StrEnum):
    info = "info"
    warning = "warning"
    critical = "critical"


class NotificationKind(StrEnum):
    telegram = "telegram"
    smtp = "smtp"
    discord = "discord"
    webhook = "webhook"


class IncidentStatus(StrEnum):
    open = "open"
    acknowledged = "acknowledged"
    investigating = "investigating"
    mitigating = "mitigating"
    resolved = "resolved"


class ApprovalStatus(StrEnum):
    pending = "pending"
    approved = "approved"
    partially_approved = "partially_approved"
    approved_with_conditions = "approved_with_conditions"
    changes_requested = "changes_requested"
    rejected = "rejected"
    dry_run_only = "dry_run_only"
    executing = "executing"
    executed = "executed"
    failed = "failed"
    rolled_back = "rolled_back"
    expired = "expired"
    withdrawn = "withdrawn"


class AgentIdentityState(StrEnum):
    pending = "pending"
    active = "active"
    retiring = "retiring"
    revoked = "revoked"
    retired = "retired"


class EnrollmentStatus(StrEnum):
    waiting = "waiting"
    installer_downloaded = "installer_downloaded"
    installer_verified = "installer_verified"
    prerequisites_checked = "prerequisites_checked"
    agent_downloaded = "agent_downloaded"
    agent_verified = "agent_verified"
    local_key_generated = "local_key_generated"
    csr_submitted = "csr_submitted"
    certificate_issued = "certificate_issued"
    service_installed = "service_installed"
    service_started = "service_started"
    heartbeat_received = "heartbeat_received"
    completed = "completed"
    failed = "failed"
    expired = "expired"
    revoked = "revoked"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default=Role.viewer.value)
    totp_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list, server_default="[]")
    session_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false()
    )
    identity_setup_enforced: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false()
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    totp_enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    totp_pending_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_pending_created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_totp_counter: Mapped[int | None] = mapped_column(Integer, nullable=True)
    recovery_codes_confirmed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_by: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    @property
    def identity_setup_required(self) -> bool:
        return bool(
            self.must_change_password
            or (
                self.identity_setup_enforced
                and (not self.totp_enabled or self.recovery_codes_confirmed_at is None)
            )
        )


class UserSession(Base):
    __tablename__ = "user_sessions"
    __table_args__ = (
        CheckConstraint("session_version >= 1", name="ck_user_session_version"),
        CheckConstraint("expires_at > issued_at", name="ck_user_session_expiry"),
        CheckConstraint(
            "idle_expires_at <= absolute_expires_at",
            name="ck_user_session_idle_absolute",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), index=True, unique=True)
    csrf_secret_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    idle_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    remember_me: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    step_up_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    revoke_reason: Mapped[str | None] = mapped_column(String(160), nullable=True)
    user_agent_digest: Mapped[str] = mapped_column(String(64))
    ip_digest: Mapped[str] = mapped_column(String(64))
    user_agent_summary: Mapped[str] = mapped_column(String(160), default="unknown:unknown")
    ip_summary: Mapped[str] = mapped_column(String(80), default="protected")
    created_via: Mapped[str] = mapped_column(String(32), default="api_token")
    last_activity_type: Mapped[str] = mapped_column(String(64), default="sign_in")
    device_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    rotated_from_session_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    session_version: Mapped[int] = mapped_column(Integer)


class RecoveryCode(Base):
    __tablename__ = "recovery_codes"
    __table_args__ = (
        UniqueConstraint("user_id", "code_hash", name="uq_recovery_code_user_hash"),
        Index("ix_recovery_codes_user_batch", "user_id", "batch_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    batch_id: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


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
    notes: Mapped[str | None] = mapped_column(String(500), nullable=True)
    desired_os_family: Mapped[str] = mapped_column(
        String(32), default="auto", server_default="auto"
    )
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
    certificate_serial: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    identity_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    build_git_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    build_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    build_time: Mapped[str | None] = mapped_column(String(64), nullable=True)
    go_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    platform_os: Mapped[str | None] = mapped_column(String(32), nullable=True)
    platform_arch: Mapped[str | None] = mapped_column(String(32), nullable=True)
    build_dirty: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    binary_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
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
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    generation: Mapped[int] = mapped_column(Integer)
    rotation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    state: Mapped[str] = mapped_column(String(16), index=True)
    signing_public_key: Mapped[str] = mapped_column(Text)
    certificate_fingerprint: Mapped[str] = mapped_column(String(128), unique=True)
    certificate_serial: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    successful_heartbeats: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
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


class PortTrafficPolicy(Base):
    __tablename__ = "port_traffic_policies"
    __table_args__ = (
        CheckConstraint("port_start >= 1 AND port_start <= 65535", name="ck_port_traffic_start"),
        CheckConstraint("port_end >= port_start AND port_end <= 65535", name="ck_port_traffic_end"),
        CheckConstraint(
            "protocol IN ('tcp', 'udp', 'both')", name="ck_port_traffic_protocol"
        ),
        CheckConstraint(
            "direction IN ('rx', 'tx', 'both')", name="ck_port_traffic_direction"
        ),
        CheckConstraint(
            "mode IN ('monitor_only', 'enforcing')", name="ck_port_traffic_mode"
        ),
        CheckConstraint(
            "status IN ('pending', 'active', 'disabled', 'error')",
            name="ck_port_traffic_status",
        ),
        CheckConstraint("generation >= 1", name="ck_port_traffic_generation"),
        CheckConstraint(
            "quota_bytes IS NULL OR quota_bytes > 0", name="ck_port_traffic_quota"
        ),
        CheckConstraint(
            "egress_rate_bps IS NULL OR egress_rate_bps >= 8000",
            name="ck_port_traffic_egress_rate",
        ),
        Index("ix_port_traffic_host_status", "host_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    host_id: Mapped[str] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(120))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    protocol: Mapped[str] = mapped_column(String(8))
    direction: Mapped[str] = mapped_column(String(8))
    port_start: Mapped[int] = mapped_column(Integer)
    port_end: Mapped[int] = mapped_column(Integer)
    interface_name: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mode: Mapped[str] = mapped_column(String(16), default="monitor_only")
    quota_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    reset_policy: Mapped[dict[str, object]] = mapped_column(
        JSON, default=dict, server_default="{}"
    )
    egress_rate_bps: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    generation: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    approved_by: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    reset_approval_id: Mapped[str | None] = mapped_column(
        ForeignKey("approvals.id", ondelete="SET NULL"), nullable=True
    )
    reset_requested_by: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    reset_approved_by: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PortTrafficSample(Base):
    __tablename__ = "port_traffic_samples"
    __table_args__ = (
        UniqueConstraint(
            "policy_id", "collected_at", name="uq_port_traffic_sample_policy_time"
        ),
        CheckConstraint("rx_bytes_total >= 0", name="ck_port_traffic_sample_rx"),
        CheckConstraint("tx_bytes_total >= 0", name="ck_port_traffic_sample_tx"),
        CheckConstraint("current_period_rx >= 0", name="ck_port_traffic_period_rx"),
        CheckConstraint("current_period_tx >= 0", name="ck_port_traffic_period_tx"),
        Index("ix_port_traffic_sample_host_time", "host_id", "collected_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    policy_id: Mapped[str] = mapped_column(
        ForeignKey("port_traffic_policies.id", ondelete="CASCADE"), index=True
    )
    host_id: Mapped[str] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), index=True
    )
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    rx_bytes_total: Mapped[int] = mapped_column(BigInteger)
    tx_bytes_total: Mapped[int] = mapped_column(BigInteger)
    current_period_rx: Mapped[int] = mapped_column(BigInteger)
    current_period_tx: Mapped[int] = mapped_column(BigInteger)
    quota_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    counter_generation: Mapped[int] = mapped_column(Integer)
    runtime_rule_state: Mapped[str] = mapped_column(String(32))
    shaping_state: Mapped[str] = mapped_column(String(32))
    current_egress_rate_bps: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    discontinuity_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)


class PortTrafficHourlyRollup(Base):
    __tablename__ = "port_traffic_hourly_rollups"
    __table_args__ = (
        UniqueConstraint(
            "policy_id", "bucket_start", name="uq_port_traffic_hourly_policy_bucket"
        ),
        Index("ix_port_traffic_hourly_host_bucket", "host_id", "bucket_start"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    policy_id: Mapped[str] = mapped_column(
        ForeignKey("port_traffic_policies.id", ondelete="CASCADE"), index=True
    )
    host_id: Mapped[str] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), index=True
    )
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    rx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    tx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    sample_count: Mapped[int] = mapped_column(Integer, default=0)
    missing_intervals: Mapped[int] = mapped_column(Integer, default=0)
    discontinuity_count: Mapped[int] = mapped_column(Integer, default=0)


class PortTrafficDailyRollup(Base):
    __tablename__ = "port_traffic_daily_rollups"
    __table_args__ = (
        UniqueConstraint(
            "policy_id", "bucket_start", name="uq_port_traffic_daily_policy_bucket"
        ),
        Index("ix_port_traffic_daily_host_bucket", "host_id", "bucket_start"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    policy_id: Mapped[str] = mapped_column(
        ForeignKey("port_traffic_policies.id", ondelete="CASCADE"), index=True
    )
    host_id: Mapped[str] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), index=True
    )
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    rx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    tx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    sample_count: Mapped[int] = mapped_column(Integer, default=0)
    missing_intervals: Mapped[int] = mapped_column(Integer, default=0)
    discontinuity_count: Mapped[int] = mapped_column(Integer, default=0)


class PortTrafficResetEvent(Base):
    __tablename__ = "port_traffic_reset_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    policy_id: Mapped[str] = mapped_column(
        ForeignKey("port_traffic_policies.id", ondelete="CASCADE"), index=True
    )
    host_id: Mapped[str] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), index=True
    )
    reason: Mapped[str] = mapped_column(String(64))
    previous_generation: Mapped[int] = mapped_column(Integer)
    new_generation: Mapped[int] = mapped_column(Integer)
    previous_rx_bytes: Mapped[int] = mapped_column(BigInteger)
    previous_tx_bytes: Mapped[int] = mapped_column(BigInteger)
    requested_by: Mapped[str | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    approval_id: Mapped[str | None] = mapped_column(
        ForeignKey("approvals.id", ondelete="SET NULL"), nullable=True
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class PortTrafficRuntimeState(Base):
    __tablename__ = "port_traffic_runtime_states"

    policy_id: Mapped[str] = mapped_column(
        ForeignKey("port_traffic_policies.id", ondelete="CASCADE"), primary_key=True
    )
    runtime_rule_state: Mapped[str] = mapped_column(String(32), default="unknown")
    shaping_state: Mapped[str] = mapped_column(String(32), default="disabled")
    counter_generation: Mapped[int] = mapped_column(Integer, default=1)
    last_sample_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_reset_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_reset_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    restore_error: Mapped[str | None] = mapped_column(String(240), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"
    __table_args__ = (
        UniqueConstraint(
            "progress_token_hash",
            name="uq_enrollment_tokens_progress_token_hash",
        ),
        CheckConstraint("length(token_hash) = 64", name="ck_enrollment_token_hash_length"),
        CheckConstraint(
            "progress_token_hash IS NULL OR length(progress_token_hash) = 64",
            name="ck_enrollment_progress_token_hash_length",
        ),
        CheckConstraint(
            "status IN ('waiting', 'installer_downloaded', 'installer_verified', "
            "'prerequisites_checked', 'agent_downloaded', 'agent_verified', "
            "'local_key_generated', 'csr_submitted', 'certificate_issued', "
            "'service_installed', 'service_started', 'heartbeat_received', "
            "'completed', 'failed', 'expired', 'revoked')",
            name="ck_enrollment_token_status",
        ),
        CheckConstraint(
            "status_sequence >= 0 AND status_sequence <= 12",
            name="ck_enrollment_token_status_sequence",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    progress_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    status: Mapped[str] = mapped_column(
        String(32), default=EnrollmentStatus.waiting.value, server_default="waiting", index=True
    )
    status_sequence: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    status_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    source_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    os_family: Mapped[str] = mapped_column(
        String(32), default="auto", server_default="auto"
    )
    installer_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_step: Mapped[str | None] = mapped_column(String(32), nullable=True)
    error_summary: Mapped[str | None] = mapped_column(String(240), nullable=True)
    rolled_back: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class EnrollmentEvent(Base):
    __tablename__ = "enrollment_events"
    __table_args__ = (
        CheckConstraint(
            "status IN ('waiting', 'installer_downloaded', 'installer_verified', "
            "'prerequisites_checked', 'agent_downloaded', 'agent_verified', "
            "'local_key_generated', 'csr_submitted', 'certificate_issued', "
            "'service_installed', 'service_started', 'heartbeat_received', "
            "'completed', 'failed', 'expired', 'revoked')",
            name="ck_enrollment_event_status",
        ),
        CheckConstraint(
            "status_sequence >= 0 AND status_sequence <= 12",
            name="ck_enrollment_event_status_sequence",
        ),
        UniqueConstraint(
            "enrollment_id",
            "status",
            name="uq_enrollment_event_status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    enrollment_id: Mapped[str] = mapped_column(
        ForeignKey("enrollment_tokens.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(32))
    status_sequence: Mapped[int] = mapped_column(Integer)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_summary: Mapped[str | None] = mapped_column(String(240), nullable=True)
    rolled_back: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())


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
    assigned_to: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    silenced_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
    event_scope: Mapped[list[str]] = mapped_column(JSON, default=list, server_default="[]")
    severity_filter: Mapped[list[str]] = mapped_column(JSON, default=list, server_default="[]")
    retry_policy: Mapped[dict[str, object]] = mapped_column(JSON, default=dict, server_default="{}")
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
    assigned_to: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    postmortem: Mapped[str | None] = mapped_column(Text, nullable=True)
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
    if any(isinstance(entry, (AuditLog, PortTrafficResetEvent)) for entry in changed):
        raise ValueError("audit and traffic reset records are append-only")


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
