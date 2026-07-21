from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian.audit import write_audit
from guardian.models import Agent, HostStatus


def mark_stale_agents_offline(
    db: Session,
    *,
    offline_after_seconds: int,
    now: datetime | None = None,
) -> list[str]:
    observed_at = now or datetime.now(UTC)
    cutoff = observed_at - timedelta(seconds=offline_after_seconds)
    changed: list[str] = []
    agents = db.scalars(
        select(Agent).where(Agent.revoked_at.is_(None), Agent.last_heartbeat_at.is_not(None))
    ).all()
    for agent in agents:
        last_heartbeat = agent.last_heartbeat_at
        if last_heartbeat is None:
            continue
        if last_heartbeat.tzinfo is None:
            last_heartbeat = last_heartbeat.replace(tzinfo=UTC)
        if last_heartbeat >= cutoff or agent.host.status == HostStatus.offline.value:
            continue
        agent.host.status = HostStatus.offline.value
        changed.append(agent.host_id)
        write_audit(
            db,
            actor=None,
            action="host.offline",
            resource_type="host",
            resource_id=agent.host_id,
            outcome="detected",
            details={"offline_after_seconds": offline_after_seconds},
        )
    return changed
