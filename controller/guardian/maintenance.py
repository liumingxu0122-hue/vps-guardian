from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network

from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from guardian.models import (
    Agent,
    AgentIdentity,
    AgentIdentityState,
    AgentMaintenanceEvent,
    AgentMaintenanceKind,
    AgentMaintenanceSession,
    Host,
    User,
)

TERMINAL_STATUSES = frozenset(
    {"completed", "failed", "rolled_back", "expired", "revoked"}
)
STATUS_SEQUENCE = {
    "waiting": 0,
    "started": 1,
    "artifact_verified": 2,
    "service_stopped": 3,
    "identity_rotated": 4,
    "service_started": 5,
    "heartbeat_verified": 6,
    "confirmation_pending": 7,
    "completed": 8,
    "failed": 8,
    "rolled_back": 8,
    "expired": 8,
    "revoked": 8,
}
ALLOWED_BY_KIND = {
    AgentMaintenanceKind.repair.value: {
        "started", "artifact_verified", "service_stopped", "service_started",
        "heartbeat_verified", "completed", "failed", "rolled_back",
    },
    AgentMaintenanceKind.reinstall.value: {
        "started", "artifact_verified", "service_stopped", "identity_rotated",
        "service_started", "heartbeat_verified", "confirmation_pending",
        "completed", "failed", "rolled_back",
    },
    AgentMaintenanceKind.rotate_identity.value: {
        "started", "artifact_verified", "identity_rotated", "service_started",
        "heartbeat_verified", "confirmation_pending", "completed", "failed",
        "rolled_back",
    },
    AgentMaintenanceKind.decommission.value: {
        "started", "artifact_verified", "service_stopped", "confirmation_pending",
        "completed", "failed",
    },
}


class MaintenanceSessionError(ValueError):
    pass


@dataclass(frozen=True)
class IssuedMaintenanceSession:
    session: AgentMaintenanceSession
    value: str


def _now(value: datetime | None = None) -> datetime:
    return value or datetime.now(UTC)


def maintenance_credential_digest(value: str, *, kind: str, channel: str) -> str:
    if channel not in {"start", "progress"} or kind not in ALLOWED_BY_KIND:
        raise MaintenanceSessionError("invalid maintenance credential domain")
    return hashlib.sha256(f"vps-guardian:{kind}:{channel}:{value}".encode()).hexdigest()


def _record(
    db: Session,
    session: AgentMaintenanceSession,
    status: str,
    *,
    error_code: str | None = None,
    error_summary: str | None = None,
    rolled_back: bool = False,
) -> None:
    session.status = status
    session.status_sequence = STATUS_SEQUENCE[status]
    session.status_updated_at = _now()
    session.error_code = error_code
    session.error_summary = error_summary
    session.rolled_back = rolled_back
    if status == "completed":
        session.completed_at = session.status_updated_at
    db.add(
        AgentMaintenanceEvent(
            session_id=session.id,
            status=status,
            status_sequence=session.status_sequence,
            error_code=error_code,
            error_summary=error_summary,
            rolled_back=rolled_back,
        )
    )


def issue_maintenance_session(
    db: Session,
    *,
    host: Host,
    agent: Agent,
    actor: User,
    kind: str,
    source_cidr: str | None,
    purge_local_state: bool,
    approval_id: str | None,
    ttl: timedelta = timedelta(minutes=10),
) -> IssuedMaintenanceSession:
    if kind not in ALLOWED_BY_KIND:
        raise MaintenanceSessionError("unsupported maintenance session kind")
    if not timedelta(minutes=1) <= ttl <= timedelta(minutes=10):
        raise MaintenanceSessionError("maintenance session TTL must not exceed 10 minutes")
    if agent.revoked_at is not None or not host.enabled:
        raise MaintenanceSessionError("maintenance requires an enabled active Agent")
    if source_cidr is not None:
        try:
            ip_network(source_cidr, strict=False)
        except ValueError as exc:
            raise MaintenanceSessionError("source CIDR is invalid") from exc
    if kind != AgentMaintenanceKind.decommission.value and purge_local_state:
        raise MaintenanceSessionError("purge mode is only valid for decommission")
    if kind == AgentMaintenanceKind.decommission.value and not approval_id:
        raise MaintenanceSessionError("decommission requires an approved high-risk request")
    active = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.agent_id == agent.id,
            AgentIdentity.state == AgentIdentityState.active.value,
        )
    )
    if active is None:
        raise MaintenanceSessionError("Agent has no active identity")
    now = _now()
    existing = db.scalar(
        select(AgentMaintenanceSession)
        .where(
            AgentMaintenanceSession.host_id == host.id,
            AgentMaintenanceSession.status.not_in(TERMINAL_STATUSES),
        )
        .order_by(AgentMaintenanceSession.created_at.desc())
        .limit(1)
    )
    if existing is not None and existing.status != "waiting":
        raise MaintenanceSessionError(
            "an in-progress maintenance session must be resolved before issuing another"
        )
    db.execute(
        update(AgentMaintenanceSession)
        .where(
            AgentMaintenanceSession.host_id == host.id,
            AgentMaintenanceSession.status == "waiting",
        )
        .values(status="revoked", revoked_at=now, status_updated_at=now)
    )
    value = secrets.token_urlsafe(48)
    session = AgentMaintenanceSession(
        host_id=host.id,
        agent_id=agent.id,
        kind=kind,
        token_hash=maintenance_credential_digest(value, kind=kind, channel="start"),
        source_cidr=source_cidr,
        purge_local_state=purge_local_state,
        expected_identity_version=agent.identity_version,
        old_identity_id=active.id,
        approval_id=approval_id,
        created_by=actor.id,
        expires_at=now + ttl,
        status_updated_at=now,
    )
    db.add(session)
    db.flush()
    _record(db, session, "waiting")
    return IssuedMaintenanceSession(session=session, value=value)


def _source_allowed(session: AgentMaintenanceSession, source_ip: str | None) -> bool:
    if session.source_cidr is None:
        return True
    if not source_ip:
        return False
    try:
        return ip_address(source_ip) in ip_network(session.source_cidr, strict=False)
    except ValueError:
        return False


def consume_maintenance_session(
    db: Session,
    *,
    value: str,
    kind: str,
    source_ip: str | None,
) -> tuple[AgentMaintenanceSession, str]:
    digest = maintenance_credential_digest(value, kind=kind, channel="start")
    session = db.scalar(
        select(AgentMaintenanceSession).where(
            AgentMaintenanceSession.token_hash == digest
        )
    )
    now = _now()
    if session is None or not hmac.compare_digest(session.token_hash, digest):
        raise MaintenanceSessionError("invalid maintenance credential")
    if session.kind != kind:
        raise MaintenanceSessionError("maintenance credential type mismatch")
    if session.revoked_at is not None or session.status in TERMINAL_STATUSES:
        raise MaintenanceSessionError("maintenance credential is no longer active")
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at <= now:
        _record(db, session, "expired")
        raise MaintenanceSessionError("maintenance credential expired")
    if not _source_allowed(session, source_ip):
        raise MaintenanceSessionError("maintenance source is outside the allowed CIDR")
    progress = secrets.token_urlsafe(48)
    result = db.execute(
        update(AgentMaintenanceSession)
        .where(
            AgentMaintenanceSession.id == session.id,
            AgentMaintenanceSession.used_at.is_(None),
            AgentMaintenanceSession.status == "waiting",
        )
        .values(
            used_at=now,
            progress_token_hash=maintenance_credential_digest(
                progress, kind=kind, channel="progress"
            ),
            status="started",
            status_sequence=STATUS_SEQUENCE["started"],
            status_updated_at=now,
        )
        .execution_options(synchronize_session=False)
    )
    if not isinstance(result, CursorResult) or result.rowcount != 1:
        db.rollback()
        raise MaintenanceSessionError("maintenance credential was already consumed")
    db.add(
        AgentMaintenanceEvent(
            session_id=session.id,
            status="started",
            status_sequence=STATUS_SEQUENCE["started"],
        )
    )
    db.flush()
    db.refresh(session)
    return session, progress


def authenticate_progress(
    db: Session, *, value: str, kind: str
) -> AgentMaintenanceSession:
    digest = maintenance_credential_digest(value, kind=kind, channel="progress")
    session = db.scalar(
        select(AgentMaintenanceSession).where(
            AgentMaintenanceSession.progress_token_hash == digest
        )
    )
    if (
        session is None
        or session.kind != kind
        or session.progress_token_hash is None
        or not hmac.compare_digest(session.progress_token_hash, digest)
    ):
        raise MaintenanceSessionError("invalid maintenance progress credential")
    if session.status in TERMINAL_STATUSES or session.revoked_at is not None:
        raise MaintenanceSessionError("maintenance session is terminal")
    return session


def advance_maintenance(
    db: Session,
    *,
    session: AgentMaintenanceSession,
    status: str,
    error_code: str | None = None,
    error_summary: str | None = None,
    rolled_back: bool = False,
) -> None:
    if status not in ALLOWED_BY_KIND[session.kind]:
        raise MaintenanceSessionError("status is not valid for this maintenance kind")
    if (
        status not in {"failed", "rolled_back"}
        and STATUS_SEQUENCE[status] <= session.status_sequence
    ):
        raise MaintenanceSessionError("maintenance progress must be monotonic")
    if error_summary is not None and len(error_summary) > 240:
        raise MaintenanceSessionError("error summary is too long")
    _record(
        db,
        session,
        status,
        error_code=error_code,
        error_summary=error_summary,
        rolled_back=rolled_back,
    )
