from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian.alerting import observe_alert
from guardian.audit import write_audit
from guardian.models import Agent, AlertRule, HostDataState, HostStatus


def _liveness_rule(db: Session, agent: Agent) -> AlertRule:
    rule = db.scalar(
        select(AlertRule).where(
            AlertRule.source_type == "host_liveness",
            AlertRule.source_id == agent.host_id,
        )
    )
    if rule is None:
        rule = AlertRule(
            name=f"host-{agent.host.name}-liveness",
            source_type="host_liveness",
            source_id=agent.host_id,
            severity="critical",
            group_key=agent.host.group_name or "hosts",
            failure_threshold=3,
            recovery_threshold=2,
        )
        db.add(rule)
        db.flush()
    return rule


def mark_stale_agents_offline(
    db: Session,
    *,
    offline_after_seconds: int,
    now: datetime | None = None,
) -> list[str]:
    observed_at = now or datetime.now(UTC)
    cutoff = observed_at - timedelta(seconds=offline_after_seconds)
    stale_cutoff = observed_at - timedelta(seconds=max(30, offline_after_seconds // 2))
    changed: list[str] = []
    agents = db.scalars(
        select(Agent).where(Agent.revoked_at.is_(None), Agent.last_heartbeat_at.is_not(None))
    ).all()
    for agent in agents:
        if not agent.host.enabled:
            continue
        last_heartbeat = agent.last_heartbeat_at
        if last_heartbeat is None:
            continue
        if last_heartbeat.tzinfo is None:
            last_heartbeat = last_heartbeat.replace(tzinfo=UTC)
        if last_heartbeat >= stale_cutoff:
            observe_alert(
                db,
                rule=_liveness_rule(db, agent),
                success=True,
                summary=f"{agent.host.name} heartbeat is current",
                now=observed_at,
            )
            continue
        if last_heartbeat >= cutoff:
            if agent.host.data_state != HostDataState.stale.value:
                agent.host.data_state = HostDataState.stale.value
                agent.host.status = HostStatus.degraded.value
                write_audit(
                    db,
                    actor=None,
                    action="host.stale",
                    resource_type="host",
                    resource_id=agent.host_id,
                    outcome="detected",
                    details={"stale_after_seconds": max(30, offline_after_seconds // 2)},
                )
            observe_alert(
                db,
                rule=_liveness_rule(db, agent),
                success=False,
                summary=f"{agent.host.name} heartbeat is stale",
                now=observed_at,
            )
            continue
        if agent.host.status == HostStatus.offline.value:
            continue
        agent.host.status = HostStatus.offline.value
        agent.host.data_state = HostDataState.offline.value
        observe_alert(
            db,
            rule=_liveness_rule(db, agent),
            success=False,
            summary=f"{agent.host.name} is offline",
            now=observed_at,
        )
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
