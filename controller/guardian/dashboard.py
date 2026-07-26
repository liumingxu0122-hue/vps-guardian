from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import case, desc, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from guardian import __version__
from guardian.config import Settings
from guardian.models import (
    Agent,
    AlertInstance,
    AlertRule,
    Incident,
    IncidentStatus,
    MetricSnapshot,
    RecoveryPoint,
    User,
)

ACTIVE_ALERT_STATES = ("pending", "firing", "acknowledged", "silenced")
BOOTSTRAP_CACHE_SECONDS = 10.0


@dataclass(frozen=True)
class DashboardCacheEntry:
    payload: dict[str, object]
    etag: str
    expires_at: float
    db_duration_ms: float
    serialization_duration_ms: float


_cache: dict[str, DashboardCacheEntry] = {}
_cache_lock = threading.Lock()


def invalidate_dashboard_cache() -> None:
    with _cache_lock:
        _cache.clear()


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat()


def _cache_key(user: User, settings: Settings) -> str:
    return ":".join(
        (
            user.id,
            user.role,
            settings.deployment_stage,
            settings.release_version,
            str(settings.production_deployed),
            settings.operations_gate_decision,
        )
    )


def _etag(payload: dict[str, object]) -> tuple[str, float]:
    started = time.perf_counter()
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    digest = hashlib.sha256(serialized).hexdigest()
    elapsed = (time.perf_counter() - started) * 1000
    return f'"{digest}"', elapsed


def _number(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    return None


def _percentage(total: object, free: object) -> float | None:
    total_number = _number(total)
    free_number = _number(free)
    if total_number is None or free_number is None or total_number <= 0:
        return None
    return round(
        max(0.0, min(100.0, (total_number - free_number) * 100 / total_number)),
        2,
    )


def _snapshot_values(payload: dict[str, object]) -> dict[str, float | None]:
    cpu = _number(payload.get("cpu_percent"))
    if cpu is None:
        load = _number(payload.get("load_1"))
        count = _number(payload.get("cpu_count"))
        cpu = load * 100 / count if load is not None and count and count > 0 else None
    return {
        "cpu_percent": round(max(0.0, min(100.0, cpu)), 2)
        if cpu is not None
        else None,
        "memory_percent": _percentage(
            payload.get("memory_total"),
            payload.get("memory_available", payload.get("memory_free")),
        ),
        "disk_percent": _percentage(payload.get("disk_total"), payload.get("disk_free")),
        "network_total": (
            receive + transmit
            if (receive := _number(payload.get("network_rx_bytes"))) is not None
            and (transmit := _number(payload.get("network_tx_bytes"))) is not None
            else None
        ),
    }


def current_resource_summary(database: Session) -> dict[str, object]:
    """Return at most two samples per host for a small, lazy dashboard module."""
    ranked = (
        select(
            MetricSnapshot.host_id.label("host_id"),
            MetricSnapshot.collected_at.label("collected_at"),
            MetricSnapshot.payload.label("payload"),
            func.row_number()
            .over(
                partition_by=MetricSnapshot.host_id,
                order_by=desc(MetricSnapshot.collected_at),
            )
            .label("sample_rank"),
        )
        .subquery()
    )
    rows = database.execute(
        select(
            ranked.c.host_id,
            ranked.c.collected_at,
            ranked.c.payload,
            ranked.c.sample_rank,
        )
        .where(ranked.c.sample_rank <= 2)
        .order_by(ranked.c.host_id, ranked.c.sample_rank)
    ).all()

    samples: dict[str, list[tuple[datetime, dict[str, object]]]] = {}
    for host_id, collected_at, payload, _rank in rows:
        if isinstance(payload, dict):
            samples.setdefault(str(host_id), []).append((collected_at, payload))

    host_values: list[dict[str, object]] = []
    for host_id, host_samples in samples.items():
        current_at, current_payload = host_samples[0]
        current = _snapshot_values(current_payload)
        previous: dict[str, float | None] | None = None
        previous_at: datetime | None = None
        if len(host_samples) > 1:
            previous_at, previous_payload = host_samples[1]
            previous = _snapshot_values(previous_payload)

        network_rate: float | None = None
        if previous is not None and previous_at is not None:
            seconds = (current_at - previous_at).total_seconds()
            current_network = current["network_total"]
            previous_network = previous["network_total"]
            if (
                seconds > 0
                and current_network is not None
                and previous_network is not None
                and current_network >= previous_network
            ):
                network_rate = round((current_network - previous_network) / seconds, 2)

        values = {
            key: current[key]
            for key in ("cpu_percent", "memory_percent", "disk_percent")
        }
        values["network_bytes_per_second"] = network_rate
        deltas: dict[str, float | None] = {}
        for key in ("cpu_percent", "memory_percent", "disk_percent"):
            current_value = current[key]
            previous_value = previous[key] if previous is not None else None
            deltas[key] = (
                round(current_value - previous_value, 2)
                if current_value is not None and previous_value is not None
                else None
            )
        host_values.append(
            {
                "host_id": host_id,
                "collected_at": _iso(current_at),
                "current": values,
                "delta": deltas,
            }
        )

    def average(field: str) -> float | None:
        values = [
            float(host["current"][field])  # type: ignore[index]
            for host in host_values
            if host["current"][field] is not None  # type: ignore[index]
        ]
        return round(sum(values) / len(values), 2) if values else None

    def average_delta(field: str) -> float | None:
        values = [
            float(host["delta"][field])  # type: ignore[index]
            for host in host_values
            if host["delta"][field] is not None  # type: ignore[index]
        ]
        return round(sum(values) / len(values), 2) if values else None

    return {
        "generated_at": _iso(datetime.now(UTC)),
        "sampled_hosts": len(host_values),
        "current": {
            "cpu_percent": average("cpu_percent"),
            "memory_percent": average("memory_percent"),
            "disk_percent": average("disk_percent"),
            "network_bytes_per_second": average("network_bytes_per_second"),
        },
        "delta": {
            "cpu_percent": average_delta("cpu_percent"),
            "memory_percent": average_delta("memory_percent"),
            "disk_percent": average_delta("disk_percent"),
        },
        "hosts": host_values,
    }


def _build_payload(
    database: Session,
    *,
    settings: Settings,
    user: User,
) -> dict[str, object]:
    now = datetime.now(UTC)
    online_cutoff = now - timedelta(seconds=settings.agent_offline_after_seconds)

    total_agents, online_agents = database.execute(
        select(
            func.count(Agent.id),
            func.sum(
                case(
                    (
                        Agent.revoked_at.is_(None)
                        & Agent.last_heartbeat_at.is_not(None)
                        & (Agent.last_heartbeat_at >= online_cutoff),
                        1,
                    ),
                    else_=0,
                )
            ),
        )
    ).one()
    agent_total = int(total_agents or 0)
    agent_online = int(online_agents or 0)

    alert_rows = database.execute(
        select(AlertRule.severity, func.count(AlertInstance.id))
        .join(AlertInstance, AlertInstance.rule_id == AlertRule.id)
        .where(AlertInstance.state.in_(ACTIVE_ALERT_STATES))
        .group_by(AlertRule.severity)
    ).all()
    alert_counts = {str(severity): int(count) for severity, count in alert_rows}
    alert_active = sum(alert_counts.values())

    incident_rows = database.execute(
        select(Incident, User.email)
        .outerjoin(User, Incident.assigned_to == User.id)
        .where(
            Incident.status != IncidentStatus.resolved.value,
            Incident.severity <= 4,
        )
        .order_by(Incident.severity, desc(Incident.updated_at))
        .limit(5)
    ).all()
    incident_critical = sum(incident.severity <= 2 for incident, _ in incident_rows)
    incident_warning = sum(incident.severity in {3, 4} for incident, _ in incident_rows)

    backup_degraded = False
    try:
        with database.begin_nested():
            latest_backup = database.scalar(
                select(RecoveryPoint)
                .where(RecoveryPoint.verified.is_(True))
                .order_by(desc(RecoveryPoint.verified_at), desc(RecoveryPoint.created_at))
                .limit(1)
            )
    except SQLAlchemyError:
        latest_backup = None
        backup_degraded = True

    offline_agents = max(0, agent_total - agent_online)
    critical_count = alert_counts.get("critical", 0) + incident_critical
    warning_count = alert_counts.get("warning", 0) + incident_warning
    if critical_count or offline_agents:
        health_status = "critical"
    elif warning_count:
        health_status = "warning"
    else:
        health_status = "healthy"

    if offline_agents:
        health_reason = f"{offline_agents} agent(s) offline or stale"
    elif critical_count:
        health_reason = f"{critical_count} active critical condition(s)"
    elif warning_count:
        health_reason = f"{warning_count} active warning condition(s)"
    else:
        health_reason = "no active critical or warning conditions"

    attention: list[dict[str, object]] = [
        {
            "id": incident.id,
            "kind": "incident",
            "severity": (
                "critical"
                if incident.severity <= 2
                else "warning"
                if incident.severity <= 4
                else "info"
            ),
            "severity_level": incident.severity,
            "title": incident.title,
            "fault_type": incident.fault_type,
            "impact": {
                "hosts": incident.affected_hosts[:3],
                "services": incident.affected_services[:3],
            },
            "owner": owner_email,
            "status": incident.status,
            "occurred_at": _iso(incident.first_seen_at),
            "updated_at": _iso(incident.updated_at),
            "next_action": incident.recommendations[0] if incident.recommendations else None,
            "href": f"/incidents?selected={incident.id}",
        }
        for incident, owner_email in incident_rows
    ]

    backup_status = "unknown" if backup_degraded else settings.operations_backup_status
    if backup_status == "unknown" and latest_backup is not None:
        backup_status = "healthy"
    backup_scope = "offsite" if settings.deployment_stage == "staging" else "same_host"

    return {
        "generated_at": _iso(now),
        "user": {
            "id": user.id,
            "email": user.email,
            "role": user.role,
        },
        "environment": {
            "stage": settings.deployment_stage,
            "version": settings.release_version or __version__,
            "production_deployed": settings.production_deployed,
            "production_status": (
                "deployed" if settings.production_deployed else "not_deployed"
            ),
            "gate_decision": settings.operations_gate_decision,
            "deployed_at": _iso(settings.deployed_at),
        },
        "global_health": {
            "status": health_status,
            "reason": health_reason,
            "critical": critical_count,
            "warning": warning_count,
            "updated_at": _iso(now),
        },
        "agents": {
            "total": agent_total,
            "online": agent_online,
            "offline": offline_agents,
            "updated_at": _iso(now),
        },
        "alerts": {
            "active": alert_active,
            "critical": alert_counts.get("critical", 0),
            "warning": alert_counts.get("warning", 0),
            "info": alert_counts.get("info", 0),
            "updated_at": _iso(now),
        },
        "backup": {
            "status": backup_status,
            "scope": backup_scope,
            "verified": latest_backup is not None,
            "verified_at": _iso(latest_backup.verified_at) if latest_backup else None,
            "created_at": _iso(latest_backup.created_at) if latest_backup else None,
            "check_status": backup_status,
            "restore_status": settings.operations_restore_status,
            "rpo_seconds": settings.operations_rpo_seconds,
            "rto_seconds": settings.operations_rto_seconds,
        },
        "production_gate": {
            "status": "go" if settings.production_deployed else "blocked",
            "decision": settings.operations_gate_decision,
            "production_deployed": settings.production_deployed,
            "blockers": (
                []
                if settings.production_deployed
                or settings.operations_gate_decision == "approved_for_production"
                else [settings.operations_gate_decision]
            ),
        },
        "attention": attention,
        "sections": {
            "health": {"status": "ok"},
            "agents": {"status": "ok"},
            "alerts": {"status": "ok"},
            "backup": {"status": "degraded" if backup_degraded else "ok"},
            "attention": {"status": "ok"},
        },
    }


def dashboard_bootstrap(
    database: Session,
    *,
    settings: Settings,
    user: User,
) -> tuple[dict[str, object], str, bool, float, float]:
    key = _cache_key(user, settings)
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get(key)
        if cached is not None and cached.expires_at > now:
            return (
                cached.payload,
                cached.etag,
                True,
                cached.db_duration_ms,
                cached.serialization_duration_ms,
            )

    db_started = time.perf_counter()
    payload = _build_payload(database, settings=settings, user=user)
    db_duration_ms = (time.perf_counter() - db_started) * 1000
    etag, serialization_duration_ms = _etag(payload)
    entry = DashboardCacheEntry(
        payload=payload,
        etag=etag,
        expires_at=now + BOOTSTRAP_CACHE_SECONDS,
        db_duration_ms=db_duration_ms,
        serialization_duration_ms=serialization_duration_ms,
    )
    with _cache_lock:
        _cache[key] = entry
    return payload, etag, False, db_duration_ms, serialization_duration_ms
