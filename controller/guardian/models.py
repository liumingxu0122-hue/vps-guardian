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
    labels: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
    action: Mapped[str] = mapped_column(String(120))
    parameters: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    nonce: Mapped[str] = mapped_column(String(128), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    signature: Mapped[str] = mapped_column(Text)
    result: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)
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
