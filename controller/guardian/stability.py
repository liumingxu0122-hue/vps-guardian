from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from statistics import fmean
from typing import Literal, TypedDict

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from guardian.config import Settings
from guardian.models import (
    Agent,
    AlertInstance,
    AlertRule,
    Host,
    MetricSnapshot,
    ServiceCheck,
    ServiceCheckResult,
)

StabilityWindow = Literal["1h", "24h", "7d", "30d"]
WINDOWS = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


class AlertStats(TypedDict):
    firing: int
    recoveries: list[float]


def _as_float(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _round(value: float | None, digits: int = 2) -> float | None:
    return round(value, digits) if value is not None else None


def _average(values: list[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return _round(fmean(present)) if present else None


def build_stability_report(
    database: Session,
    *,
    settings: Settings,
    window: StabilityWindow,
    group: str | None = None,
    location: str | None = None,
) -> dict[str, object]:
    now = datetime.now(UTC)
    duration = WINDOWS[window]
    cutoff = now - duration
    hosts_statement = select(Host).order_by(Host.name)
    if group:
        hosts_statement = hosts_statement.where(Host.group_name == group)
    if location:
        hosts_statement = hosts_statement.where(Host.location == location)
    hosts = list(database.scalars(hosts_statement).all())
    host_ids = [host.id for host in hosts]
    if not host_ids:
        return {
            "generated_at": now.isoformat(),
            "window": window,
            "formula_version": 1,
            "hosts": [],
            "aggregates": [],
        }

    metric_rows = database.execute(
        select(
            MetricSnapshot.host_id,
            func.count(MetricSnapshot.id),
            func.min(MetricSnapshot.collected_at),
            func.max(MetricSnapshot.collected_at),
        )
        .where(
            MetricSnapshot.host_id.in_(host_ids),
            MetricSnapshot.collected_at >= cutoff,
        )
        .group_by(MetricSnapshot.host_id)
    ).all()
    metric_by_host = {
        str(row[0]): (int(row[1]), _aware(row[2]), _aware(row[3])) for row in metric_rows
    }

    agents = {
        agent.host_id: agent
        for agent in database.scalars(select(Agent).where(Agent.host_id.in_(host_ids))).all()
    }
    checks = list(
        database.scalars(
            select(ServiceCheck).where(ServiceCheck.host_id.in_(host_ids))
        ).all()
    )
    check_host = {check.id: check.host_id for check in checks if check.host_id}
    check_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "failed": 0})
    if check_host:
        result_rows = database.execute(
            select(ServiceCheckResult.check_id, ServiceCheckResult.status)
            .where(
                ServiceCheckResult.check_id.in_(list(check_host)),
                ServiceCheckResult.checked_at >= cutoff,
            )
            .limit(250_000)
        )
        for check_id, result_status in result_rows:
            host_id = check_host.get(str(check_id))
            if not host_id:
                continue
            check_stats[host_id]["total"] += 1
            if str(result_status) not in {"ok", "unsupported"}:
                check_stats[host_id]["failed"] += 1

    rules = list(database.scalars(select(AlertRule)).all())
    rule_host: dict[str, str] = {}
    for rule in rules:
        if rule.source_type in {"host_liveness", "agent_error"} and rule.source_id in host_ids:
            rule_host[rule.id] = rule.source_id
        elif rule.source_type == "service_check":
            check_target = check_host.get(rule.source_id)
            if check_target:
                rule_host[rule.id] = check_target
    alert_stats: dict[str, AlertStats] = defaultdict(
        lambda: {"firing": 0, "recoveries": []}
    )
    if rule_host:
        alerts = database.scalars(
            select(AlertInstance).where(
                AlertInstance.rule_id.in_(list(rule_host)),
                AlertInstance.first_observed_at >= cutoff,
            )
        ).all()
        for alert in alerts:
            host_id = rule_host.get(alert.rule_id)
            if not host_id:
                continue
            if alert.fired_at:
                alert_stats[host_id]["firing"] += 1
            fired_at = _aware(alert.fired_at)
            resolved_at = _aware(alert.resolved_at)
            if fired_at and resolved_at and resolved_at >= fired_at:
                alert_stats[host_id]["recoveries"].append(
                    (resolved_at - fired_at).total_seconds()
                )

    expected_interval = max(15, settings.agent_offline_after_seconds // 3)
    expected_samples = max(1, int(duration.total_seconds() / expected_interval))
    days = max(duration.total_seconds() / 86_400, 1 / 24)
    rows: list[dict[str, object]] = []
    for host in hosts:
        if not host.enabled:
            rows.append(
                {
                    "host_id": host.id,
                    "host_name": host.name,
                    "group": host.group_name,
                    "location": host.location,
                    "status": "excluded",
                    "reason": "disabled hosts are excluded from stability scoring",
                    "stability_score": None,
                    "uptime_score": None,
                    "heartbeat_score": None,
                    "check_success_score": None,
                    "failure_rate": None,
                    "mean_recovery_time": None,
                    "stale_ratio": None,
                    "alert_frequency": None,
                    "confidence": 0.0,
                    "sample_count": 0,
                    "check_count": 0,
                    "is_new": False,
                }
            )
            continue

        count, oldest, latest = metric_by_host.get(host.id, (0, None, None))
        agent = agents.get(host.id)
        latest_heartbeat = _aware(agent.last_heartbeat_at if agent else host.last_seen_at)
        coverage = min(1.0, count / expected_samples) if count else 0.0
        span_ratio = (
            min(1.0, max(0.0, (latest - oldest).total_seconds()) / duration.total_seconds())
            if oldest and latest and count > 1
            else 0.0
        )
        fresh = bool(
            latest_heartbeat
            and latest_heartbeat >= now - timedelta(seconds=settings.agent_offline_after_seconds)
        )
        uptime_score = _round(100 * min(1.0, (coverage + span_ratio + int(fresh)) / 3))
        heartbeat_score = _round(100 * coverage)
        stale_ratio = _round(1 - coverage, 4) if count else None

        result = check_stats[host.id]
        check_total = result["total"]
        check_failed = result["failed"]
        failure_rate = _round(check_failed / check_total, 4) if check_total else None
        check_success_score = (
            _round(100 * (1 - check_failed / check_total)) if check_total else None
        )

        host_alerts = alert_stats[host.id]
        firing_count = host_alerts["firing"]
        has_observations = bool(count or check_total or firing_count)
        alert_frequency = _round(firing_count / days) if has_observations else None
        recoveries = host_alerts["recoveries"]
        mean_recovery_time = _round(fmean(recoveries)) if recoveries else None
        calm_score = (
            max(0.0, 100.0 - min(100.0, alert_frequency * 10))
            if alert_frequency is not None
            else None
        )
        components = [
            (uptime_score if count else None, 0.35),
            (heartbeat_score if count else None, 0.25),
            (check_success_score, 0.25),
            (calm_score, 0.15),
        ]
        available = [(value, weight) for value, weight in components if value is not None]
        raw_score = (
            sum(float(value) * weight for value, weight in available)
            / sum(weight for _, weight in available)
            if available
            else None
        )
        metric_confidence = min(1.0, count / 12) if count else 0.0
        check_confidence = min(1.0, check_total / 3) if check_total else 0.0
        confidence = max(metric_confidence, check_confidence)
        stability_score = (
            _round(raw_score * confidence + 75 * (1 - confidence))
            if raw_score is not None
            else None
        )
        created_at = _aware(host.created_at)
        is_new = bool(created_at and created_at >= now - timedelta(hours=24))
        rows.append(
            {
                "host_id": host.id,
                "host_name": host.name,
                "group": host.group_name,
                "location": host.location,
                "status": "scored" if stability_score is not None else "no_data",
                "reason": (
                    "score uses observed heartbeat coverage, checks, and alert frequency"
                    if stability_score is not None
                    else "no samples or check results exist in this window"
                ),
                "stability_score": stability_score,
                "uptime_score": uptime_score if count else None,
                "heartbeat_score": heartbeat_score if count else None,
                "check_success_score": check_success_score,
                "failure_rate": failure_rate,
                "mean_recovery_time": mean_recovery_time,
                "stale_ratio": stale_ratio,
                "alert_frequency": alert_frequency,
                "confidence": _round(confidence, 4),
                "sample_count": count,
                "check_count": check_total,
                "is_new": is_new,
            }
        )

    rows.sort(
        key=lambda row: (
            row["stability_score"] is None,
            _as_float(row["stability_score"]) or 0.0,
            str(row["host_name"]),
        )
    )
    aggregate_groups: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        if row["status"] == "excluded":
            continue
        aggregate_groups[
            (str(row["group"] or "ungrouped"), str(row["location"] or "unknown"))
        ].append(row)
    aggregates = [
        {
            "group": key[0],
            "location": key[1],
            "host_count": len(items),
            "scored_count": sum(item["stability_score"] is not None for item in items),
            "stability_score": _average(
                [_as_float(item["stability_score"]) for item in items]
            ),
            "uptime_score": _average(
                [_as_float(item["uptime_score"]) for item in items]
            ),
            "check_success_score": _average(
                [_as_float(item["check_success_score"]) for item in items]
            ),
        }
        for key, items in sorted(aggregate_groups.items())
    ]
    return {
        "generated_at": now.isoformat(),
        "window": window,
        "formula_version": 1,
        "expected_heartbeat_interval_seconds": expected_interval,
        "hosts": rows,
        "aggregates": aggregates,
    }
