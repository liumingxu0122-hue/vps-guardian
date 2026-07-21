from __future__ import annotations

import json
import math
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Literal

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from guardian.config import Settings
from guardian.models import (
    Agent,
    AgentIdentity,
    AgentIdentityState,
    AgentTask,
    AlertInstance,
    AlertRule,
    Approval,
    AuditLog,
    Host,
    Incident,
    MetricSnapshot,
    RecoveryPoint,
    RepairAttempt,
    Role,
    User,
)

Window = Literal["24h", "7d"]
ROLE_ORDER = {
    Role.viewer.value: 0,
    Role.operator.value: 1,
    Role.admin.value: 2,
    Role.owner.value: 3,
}


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _percentage(total: object, free: object) -> float | None:
    total_number = _number(total)
    free_number = _number(free)
    if total_number is None or free_number is None or total_number <= 0:
        return None
    return round(max(0.0, min(100.0, (total_number - free_number) * 100 / total_number)), 2)


def _cpu_percent(payload: dict[str, object]) -> tuple[float | None, str]:
    direct = _number(payload.get("cpu_percent"))
    if direct is not None:
        return round(max(0.0, min(100.0, direct)), 2), "cpu_time"
    load = _number(payload.get("load_1"))
    count = _number(payload.get("cpu_count"))
    if load is None or count is None or count <= 0:
        return None, "unavailable"
    return round(max(0.0, min(100.0, load * 100 / count)), 2), "normalized_load"


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _iso(value: datetime | None) -> str | None:
    aware = _aware(value)
    return aware.astimezone(UTC).isoformat() if aware else None


def _downsample(points: list[dict[str, object]], maximum: int = 96) -> list[dict[str, object]]:
    if len(points) <= maximum:
        return points
    stride = (len(points) - 1) / (maximum - 1)
    indexes = {round(index * stride) for index in range(maximum)}
    return [point for index, point in enumerate(points) if index in indexes]


def _resource_series(
    database: Session,
    *,
    window: Window,
    host_id: str | None,
) -> tuple[dict[str, list[dict[str, object]]], bool]:
    cutoff = datetime.now(UTC) - (timedelta(hours=24) if window == "24h" else timedelta(days=7))
    statement = select(
        MetricSnapshot.host_id,
        MetricSnapshot.collected_at,
        MetricSnapshot.payload["cpu_percent"].as_float(),
        MetricSnapshot.payload["load_1"].as_float(),
        MetricSnapshot.payload["cpu_count"].as_float(),
        MetricSnapshot.payload["memory_total_bytes"].as_float(),
        MetricSnapshot.payload["memory_available_bytes"].as_float(),
        MetricSnapshot.payload["disk_total_bytes"].as_float(),
        MetricSnapshot.payload["disk_free_bytes"].as_float(),
        MetricSnapshot.payload["network_rx_bytes"].as_float(),
        MetricSnapshot.payload["network_tx_bytes"].as_float(),
    ).where(MetricSnapshot.collected_at >= cutoff)
    if host_id:
        statement = statement.where(MetricSnapshot.host_id == host_id)
    rows = list(
        database.execute(statement.order_by(desc(MetricSnapshot.collected_at)).limit(50_001))
    )
    truncated = len(rows) > 50_000
    rows = list(reversed(rows[:50_000]))
    output: dict[str, list[dict[str, object]]] = defaultdict(list)
    previous_network: dict[str, tuple[datetime, float, float]] = {}
    for row in rows:
        host = str(row[0])
        collected_at = _aware(row[1])
        if collected_at is None:
            continue
        cpu, source = _cpu_percent(
            {"cpu_percent": row[2], "load_1": row[3], "cpu_count": row[4]}
        )
        receive = _number(row[9])
        transmit = _number(row[10])
        network_rate: float | None = None
        previous = previous_network.get(host)
        if receive is not None and transmit is not None:
            if previous:
                seconds = (collected_at - previous[0]).total_seconds()
                delta = receive + transmit - previous[1] - previous[2]
                if seconds > 0 and delta >= 0:
                    network_rate = round(delta / seconds, 2)
            previous_network[host] = (collected_at, receive, transmit)
        output[host].append(
            {
                "at": _iso(collected_at),
                "cpu_percent": cpu,
                "cpu_source": source,
                "memory_percent": _percentage(row[5], row[6]),
                "disk_percent": _percentage(row[7], row[8]),
                "network_bytes_per_second": network_rate,
            }
        )
    return {key: _downsample(value) for key, value in output.items()}, truncated


def _docker_component_status(payloads: list[dict[str, object]], fragment: str) -> str:
    observed = False
    for payload in payloads:
        services = payload.get("_services", [])
        if not isinstance(services, list):
            continue
        for service in services:
            if not isinstance(service, dict) or service.get("kind") != "docker":
                continue
            summary = service.get("summary")
            if not isinstance(summary, str):
                continue
            for line in summary.splitlines()[:500]:
                try:
                    record = json.loads(line)
                except (TypeError, ValueError):
                    continue
                name = str(record.get("Names", "")).lower()
                if fragment not in name:
                    continue
                observed = True
                state = str(record.get("State", "")).lower()
                if state == "running":
                    return "healthy"
    return "degraded" if observed else "unknown"


def build_operations_overview(
    database: Session,
    *,
    settings: Settings,
    user: User,
    window: Window,
    host_id: str | None,
) -> dict[str, object]:
    now = datetime.now(UTC)
    hosts = list(database.scalars(select(Host).order_by(Host.name)).all())
    host_map = {host.id: host for host in hosts}
    if host_id and host_id not in host_map:
        raise LookupError("host not found")
    agents = list(database.scalars(select(Agent)).all())
    agent_by_host = {agent.host_id: agent for agent in agents}
    identities = list(
        database.scalars(
            select(AgentIdentity).where(AgentIdentity.state == AgentIdentityState.active.value)
        ).all()
    )
    identity_by_agent = {identity.agent_id: identity for identity in identities}
    tasks = list(database.scalars(select(AgentTask)).all())
    task_counts: dict[str, dict[str, int]] = defaultdict(lambda: {"queued": 0, "failed": 0})
    for task in tasks:
        if task.status in {"pending", "delivered"}:
            task_counts[task.agent_id]["queued"] += 1
        elif task.status == "failed":
            task_counts[task.agent_id]["failed"] += 1

    latest_payloads: dict[str, dict[str, object]] = {}
    latest_collected: dict[str, datetime] = {}
    for host in hosts:
        snapshot = database.scalar(
            select(MetricSnapshot)
            .where(MetricSnapshot.host_id == host.id)
            .order_by(desc(MetricSnapshot.collected_at))
            .limit(1)
        )
        if snapshot:
            latest_payloads[host.id] = snapshot.payload
            latest_collected[host.id] = snapshot.collected_at

    series, series_truncated = _resource_series(
        database, window=window, host_id=host_id
    )
    host_rows: list[dict[str, object]] = []
    for host in hosts:
        agent = agent_by_host.get(host.id)
        identity = identity_by_agent.get(agent.id) if agent else None
        payload = latest_payloads.get(host.id, {})
        cpu, cpu_source = _cpu_percent(payload)
        certificate_status = "missing"
        if agent and agent.revoked_at:
            certificate_status = "revoked"
        elif agent and identity:
            expires_at = _aware(identity.expires_at)
            certificate_status = (
                "expiring" if expires_at and expires_at <= now + timedelta(days=30) else "valid"
            )
        offline_depth = payload.get("offline_queue_depth")
        if not isinstance(offline_depth, int):
            events = payload.get("_events", [])
            offline_depth = len(events) if isinstance(events, list) else 0
        current_series = series.get(host.id, [])
        latest_network = next(
            (
                point.get("network_bytes_per_second")
                for point in reversed(current_series)
                if point.get("network_bytes_per_second") is not None
            ),
            None,
        )
        host_rows.append(
            {
                "id": host.id,
                "name": host.name,
                "location": host.location,
                "status": host.status,
                "last_heartbeat_at": _iso(agent.last_heartbeat_at if agent else host.last_seen_at),
                "agent_serial": agent.certificate_serial if agent else None,
                "certificate_status": certificate_status,
                "offline_queue": offline_depth,
                "failed_tasks": task_counts[agent.id]["failed"] if agent else 0,
                "queued_tasks": task_counts[agent.id]["queued"] if agent else 0,
                "resources": {
                    "cpu_percent": cpu,
                    "cpu_source": cpu_source,
                    "memory_percent": _percentage(
                        payload.get("memory_total_bytes"), payload.get("memory_available_bytes")
                    ),
                    "disk_percent": _percentage(
                        payload.get("disk_total_bytes"), payload.get("disk_free_bytes")
                    ),
                    "network_bytes_per_second": latest_network,
                    "collected_at": _iso(latest_collected.get(host.id)),
                },
            }
        )

    incidents = list(
        database.scalars(select(Incident).order_by(desc(Incident.first_seen_at)).limit(100)).all()
    )
    alerts = list(
        database.scalars(
            select(AlertInstance).order_by(desc(AlertInstance.last_observed_at)).limit(1000)
        ).all()
    )
    alert_rules = {
        rule.id: rule
        for rule in database.scalars(
            select(AlertRule).where(AlertRule.id.in_({alert.rule_id for alert in alerts}))
        ).all()
    }
    approvals = list(
        database.scalars(select(Approval).order_by(desc(Approval.requested_at)).limit(100)).all()
    )
    repairs = list(
        database.scalars(select(RepairAttempt).order_by(desc(RepairAttempt.created_at)).limit(100)).all()
    )
    recovery_points = list(
        database.scalars(
            select(RecoveryPoint).order_by(desc(RecoveryPoint.created_at)).limit(500)
        ).all()
    )
    verified_points = [point for point in recovery_points if point.verified]
    accepted = verified_points[0] if verified_points else None
    accepted_value = settings.operations_accepted_snapshot or (
        accepted.snapshot_id if accepted else ""
    )
    backup_checked_at = settings.operations_backup_checked_at or (
        accepted.verified_at if accepted else None
    )
    backup_status = settings.operations_backup_status
    if backup_status == "unknown" and accepted:
        backup_status = "healthy"

    host_statuses = {name: 0 for name in ("healthy", "degraded", "offline", "unknown")}
    for host in hosts:
        host_statuses[host.status if host.status in host_statuses else "unknown"] += 1
    active_incidents = [incident for incident in incidents if incident.status != "resolved"]
    critical_incidents = [incident for incident in active_incidents if incident.severity >= 4]
    active_alerts = [
        alert for alert in alerts if alert.state not in {"ok", "resolved"}
    ]
    critical_alerts = [
        alert
        for alert in active_alerts
        if alert_rules.get(alert.rule_id) is not None
        and alert_rules[alert.rule_id].severity == "critical"
    ]
    warning_alerts = [
        alert
        for alert in active_alerts
        if alert_rules.get(alert.rule_id) is not None
        and alert_rules[alert.rule_id].severity == "warning"
    ]
    global_health = "healthy"
    if critical_incidents or critical_alerts or host_statuses["offline"]:
        global_health = "critical"
    elif (
        active_incidents
        or warning_alerts
        or host_statuses["degraded"]
        or host_statuses["unknown"]
    ):
        global_health = "degraded"

    role = ROLE_ORDER.get(user.role, 0)
    can_recover = role >= ROLE_ORDER[Role.operator.value]
    can_view_security = role >= ROLE_ORDER[Role.admin.value]
    can_approve = role >= ROLE_ORDER[Role.admin.value]

    timeline: list[dict[str, object]] = []
    for incident in incidents[:12]:
        timeline.append(
            {
                "id": f"incident-{incident.id}",
                "kind": "incident",
                "severity": incident.severity,
                "host_id": incident.affected_hosts[0] if incident.affected_hosts else None,
                "title": incident.title,
                "status": incident.status,
                "at": _iso(incident.first_seen_at),
            }
        )
    for repair in repairs[:12]:
        repair_incident = next(
            (item for item in incidents if item.id == repair.incident_id), None
        )
        timeline.append(
            {
                "id": f"repair-{repair.id}",
                "kind": "repair",
                "severity": 1 if repair.success else 3 if repair.success is False else 2,
                "host_id": (
                    repair_incident.affected_hosts[0]
                    if repair_incident and repair_incident.affected_hosts
                    else None
                ),
                "title": repair.action,
                "status": (
                    "passed"
                    if repair.success
                    else "failed"
                    if repair.success is False
                    else "running"
                ),
                "at": _iso(repair.created_at),
            }
        )
    if can_view_security:
        audits = list(
            database.scalars(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(12)).all()
        )
        for audit in audits:
            timeline.append(
                {
                    "id": f"audit-{audit.id}",
                    "kind": "audit",
                    "severity": 2 if audit.outcome in {"failed", "denied", "blocked"} else 1,
                    "host_id": audit.resource_id if audit.resource_type == "host" else None,
                    "title": audit.action,
                    "status": audit.outcome,
                    "at": _iso(audit.created_at),
                }
            )
    timeline.sort(key=lambda item: str(item.get("at") or ""), reverse=True)

    payloads = list(latest_payloads.values())
    topology = [
        {"id": "controller", "label": "Controller", "kind": "control", "status": "healthy"},
        {
            "id": "haproxy",
            "label": "HAProxy",
            "kind": "gateway",
            "status": _docker_component_status(payloads, "agent-gateway"),
        },
        {"id": "postgresql", "label": "PostgreSQL", "kind": "database", "status": "healthy"},
        {"id": "web", "label": "Web", "kind": "web", "status": "healthy"},
        *[
            {
                "id": f"agent-{host.id}",
                "label": host.name,
                "kind": "agent",
                "status": host.status,
            }
            for host in hosts
        ],
    ]

    return {
        "generated_at": _iso(now),
        "environment": {
            "current": settings.deployment_stage,
            "production_deployed": settings.production_deployed,
            "production_status": "deployed" if settings.production_deployed else "not_deployed",
            "gate_decision": settings.operations_gate_decision,
        },
        "global_health": global_health,
        "hosts": {"total": len(hosts), **host_statuses},
        "incidents": {"open": len(active_incidents), "critical": len(critical_incidents)},
        "alerts": {
            "active": len(active_alerts),
            "critical": len(critical_alerts),
            "warning": len(warning_alerts),
        },
        "pending_approvals": sum(approval.status == "pending" for approval in approvals),
        "verified_recovery_points": len(verified_points),
        "recent_incidents": [
            {
                "id": incident.id,
                "title": incident.title,
                "status": incident.status,
                "severity": incident.severity,
                "fault_type": incident.fault_type,
                "first_seen_at": _iso(incident.first_seen_at),
            }
            for incident in incidents[:8]
        ],
        "recovery": {
            "repository": "R2 Restic" if settings.deployment_stage == "staging" else "Restic",
            "status": backup_status,
            "accepted_snapshot": accepted_value[:12] if accepted_value else None,
            "last_backup_at": _iso(accepted.created_at if accepted else backup_checked_at),
            "last_check_at": _iso(backup_checked_at),
            "snapshot_count": settings.operations_snapshot_count
            if settings.operations_snapshot_count is not None
            else len(recovery_points),
            "restore_status": settings.operations_restore_status,
            "retention_policy": settings.operations_retention_policy,
            "rpo_seconds": settings.operations_rpo_seconds,
            "rto_seconds": settings.operations_rto_seconds,
            "measurement_scope": "staging_measured"
            if settings.operations_rpo_seconds is not None
            else "not_measured",
        },
        "security": {
            "uncovered_critical": settings.operations_uncovered_critical,
            "uncovered_high": settings.operations_uncovered_high,
            "mtls": "enforced",
            "crl": "enforced",
            "certificate_rotation": "operational" if identities else "not_observed",
            "last_scan_at": _iso(settings.operations_security_scan_at),
            "login_rate_limit": "enforced",
            "totp": "available",
            "rbac": "enforced",
            "audit": "append_only",
        },
        "permissions": {
            "role": user.role,
            "can_view_recovery": can_recover,
            "can_view_security": can_view_security,
            "can_approve": can_approve,
            "dangerous_actions": "approval_required",
        },
        "resource_window": window,
        "resource_series": series,
        "resource_series_truncated": series_truncated,
        "host_rows": host_rows,
        "topology": topology,
        "timeline": timeline[:30],
    }
