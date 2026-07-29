from __future__ import annotations

import calendar
import json
import math
import statistics
from datetime import UTC, date, datetime, time, timedelta
from typing import Any, cast
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import delete, desc, select
from sqlalchemy.orm import Session

from guardian.alerting import observe_alert
from guardian.config import Settings
from guardian.models import (
    Agent,
    AgentTask,
    AlertInstance,
    AlertRule,
    AlertState,
    PortTrafficDailyRollup,
    PortTrafficHourlyRollup,
    PortTrafficPolicy,
    PortTrafficRuntimeState,
    PortTrafficSample,
)
from guardian.schemas import PortTrafficHistoryPoint, PortTrafficObservation

MAX_POLICIES_PER_HOST = 64
RAW_RETENTION_DAYS = 7
HOURLY_RETENTION_DAYS = 90
DAILY_RETENTION_DAYS = 400
MAX_HISTORY_DAYS = 400
EXPECTED_SAMPLE_SECONDS = 60
QUOTA_THRESHOLDS = (70, 85, 95, 100)


class PortTrafficError(ValueError):
    pass


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _protocols(value: str) -> frozenset[str]:
    return frozenset({"tcp", "udp"} if value == "both" else {value})


def policy_overlaps(
    *,
    protocol: str,
    port_start: int,
    port_end: int,
    existing: PortTrafficPolicy,
) -> bool:
    return bool(_protocols(protocol) & _protocols(existing.protocol)) and not (
        port_end < existing.port_start or port_start > existing.port_end
    )


def ensure_policy_capacity_and_no_overlap(
    db: Session,
    *,
    host_id: str,
    protocol: str,
    port_start: int,
    port_end: int,
    exclude_policy_id: str | None = None,
) -> None:
    policies = list(
        db.scalars(
            select(PortTrafficPolicy).where(
                PortTrafficPolicy.host_id == host_id,
                PortTrafficPolicy.status != "disabled",
            )
        ).all()
    )
    if exclude_policy_id is None and len(policies) >= MAX_POLICIES_PER_HOST:
        raise PortTrafficError("a host may have at most 64 port traffic policies")
    if any(
        item.id != exclude_policy_id
        and policy_overlaps(
            protocol=protocol,
            port_start=port_start,
            port_end=port_end,
            existing=item,
        )
        for item in policies
    ):
        raise PortTrafficError("port range overlaps an existing Guardian policy")


def _valid_date(value: object, field: str) -> date:
    if not isinstance(value, str):
        raise PortTrafficError(f"{field} must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise PortTrafficError(f"{field} must be an ISO date") from exc


def validate_reset_policy(value: dict[str, Any]) -> dict[str, object]:
    if not value:
        return {"type": "manual", "timezone": "UTC"}
    allowed = {
        "type",
        "timezone",
        "day",
        "month",
        "every",
        "anchor_date",
        "date",
    }
    if set(value) - allowed:
        raise PortTrafficError("reset policy contains unsupported fields")
    policy_type = value.get("type", "manual")
    if policy_type not in {
        "manual",
        "monthly",
        "interval_days",
        "interval_months",
        "yearly",
        "fixed_date",
    }:
        raise PortTrafficError("reset policy type is unsupported")
    timezone_name = value.get("timezone", "UTC")
    if not isinstance(timezone_name, str) or len(timezone_name) > 64:
        raise PortTrafficError("reset timezone is invalid")
    try:
        ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise PortTrafficError("reset timezone is unknown") from exc
    result: dict[str, object] = {"type": policy_type, "timezone": timezone_name}
    if policy_type in {"monthly", "interval_months", "yearly"}:
        day = value.get("day")
        if not isinstance(day, int) or not 1 <= day <= 31:
            raise PortTrafficError("reset day must be between 1 and 31")
        result["day"] = day
    if policy_type == "yearly":
        month = value.get("month")
        if not isinstance(month, int) or not 1 <= month <= 12:
            raise PortTrafficError("reset month must be between 1 and 12")
        result["month"] = month
    if policy_type in {"interval_days", "interval_months"}:
        every = value.get("every")
        maximum = 366 if policy_type == "interval_days" else 120
        if not isinstance(every, int) or not 1 <= every <= maximum:
            raise PortTrafficError("reset interval is outside the supported range")
        result["every"] = every
        result["anchor_date"] = _valid_date(value.get("anchor_date"), "anchor_date").isoformat()
    if policy_type == "fixed_date":
        result["date"] = _valid_date(value.get("date"), "date").isoformat()
    return result


def _clamp(year: int, month: int, day: int) -> date:
    return date(year, month, min(day, calendar.monthrange(year, month)[1]))


def _add_months(value: date, months: int, day: int) -> date:
    index = value.year * 12 + value.month - 1 + months
    return _clamp(index // 12, index % 12 + 1, day)


def _normalized_int(policy: dict[str, object], key: str) -> int:
    value = policy[key]
    if not isinstance(value, int):
        raise PortTrafficError(f"normalized reset policy {key} is invalid")
    return value


def next_reset_at(
    policy: dict[str, object], *, after: datetime | None = None
) -> datetime | None:
    normalized = validate_reset_policy(dict(policy))
    if normalized["type"] == "manual":
        return None
    timezone = ZoneInfo(str(normalized["timezone"]))
    local_after = _aware(after or datetime.now(UTC)).astimezone(timezone)
    today = local_after.date()
    policy_type = normalized["type"]
    candidate: date
    if policy_type == "monthly":
        day = _normalized_int(normalized, "day")
        candidate = _clamp(today.year, today.month, day)
        if candidate <= today:
            candidate = _add_months(candidate, 1, day)
    elif policy_type == "yearly":
        month = _normalized_int(normalized, "month")
        day = _normalized_int(normalized, "day")
        candidate = _clamp(
            today.year, month, day
        )
        if candidate <= today:
            candidate = _clamp(
                today.year + 1,
                month,
                day,
            )
    elif policy_type == "fixed_date":
        candidate = date.fromisoformat(str(normalized["date"]))
        if candidate <= today:
            return None
    elif policy_type == "interval_days":
        candidate = date.fromisoformat(str(normalized["anchor_date"]))
        every = _normalized_int(normalized, "every")
        if candidate <= today:
            elapsed = (today - candidate).days
            candidate += timedelta(days=((elapsed // every) + 1) * every)
    else:
        candidate = date.fromisoformat(str(normalized["anchor_date"]))
        every = _normalized_int(normalized, "every")
        day = _normalized_int(normalized, "day")
        while candidate <= today:
            candidate = _add_months(candidate, every, day)
    return datetime.combine(candidate, time.min, timezone).astimezone(UTC)


def ensure_quota_alert_rules(db: Session, policy: PortTrafficPolicy) -> None:
    for threshold in QUOTA_THRESHOLDS:
        source_id = f"{policy.id}:{threshold}"
        if db.scalar(
            select(AlertRule).where(
                AlertRule.source_type == "port_traffic_quota",
                AlertRule.source_id == source_id,
            )
        ):
            continue
        db.add(
            AlertRule(
                name=f"Port traffic {policy.id} quota {threshold}%",
                source_type="port_traffic_quota",
                source_id=source_id,
                severity="critical" if threshold >= 95 else "warning",
                group_key=policy.host_id,
                failure_threshold=1,
                recovery_threshold=2,
                repeat_interval_seconds=3600,
                recovery_notifications=True,
            )
        )
    for source_type, severity, name in (
        ("port_traffic_runtime", "critical", "kernel rule and sample continuity"),
        ("port_traffic_shaping", "critical", "egress shaping state"),
        ("port_traffic_enforcement", "critical", "quota enforcement state"),
        ("port_traffic_snapshot_gap", "warning", "snapshot continuity"),
        ("port_traffic_spike", "warning", "traffic anomaly"),
    ):
        if db.scalar(
            select(AlertRule).where(
                AlertRule.source_type == source_type,
                AlertRule.source_id == policy.id,
            )
        ):
            continue
        db.add(
            AlertRule(
                name=f"Port traffic {policy.id} {name}",
                source_type=source_type,
                source_id=policy.id,
                severity=severity,
                group_key=policy.host_id,
                failure_threshold=1,
                recovery_threshold=2,
                repeat_interval_seconds=3600,
                recovery_notifications=True,
            )
        )


def _quota_state(percent: float | None) -> str:
    if percent is None:
        return "unlimited"
    if percent >= 100:
        return "exhausted"
    if percent >= 95:
        return "critical"
    if percent >= 70:
        return "warning"
    return "normal"


def _observe_quota_alerts(
    db: Session,
    policy: PortTrafficPolicy,
    *,
    percent: float | None,
    now: datetime,
) -> None:
    rules = db.scalars(
        select(AlertRule).where(
            AlertRule.source_type == "port_traffic_quota",
            AlertRule.source_id.like(f"{policy.id}:%"),
        )
    ).all()
    for rule in rules:
        threshold = int(rule.source_id.rsplit(":", 1)[1])
        if percent is None:
            observe_alert(
                db,
                rule=rule,
                success=True,
                summary=f"{policy.name} has no configured quota",
                details={
                    "policy_id": policy.id,
                    "host_id": policy.host_id,
                    "quota_percent": None,
                    "threshold": threshold,
                },
                now=now,
            )
            continue
        alert = db.scalar(
            select(AlertInstance).where(AlertInstance.rule_id == rule.id)
        )
        active = alert is not None and alert.state not in {
            AlertState.ok.value,
            AlertState.resolved.value,
            AlertState.closed.value,
        }
        recovery_level = max(0, threshold - 2)
        success = percent < (recovery_level if active else threshold)
        observe_alert(
            db,
            rule=rule,
            success=success,
            summary=f"{policy.name} quota usage is {percent:.1f}%",
            details={
                "policy_id": policy.id,
                "host_id": policy.host_id,
                "quota_percent": round(percent, 3),
                "threshold": threshold,
            },
            now=now,
        )


def _observe_runtime_alerts(
    db: Session,
    policy: PortTrafficPolicy,
    *,
    rule_success: bool,
    shaping_success: bool,
    summary: str,
    now: datetime,
) -> None:
    for source_type, success in (
        ("port_traffic_runtime", rule_success),
        ("port_traffic_shaping", shaping_success),
    ):
        rule = db.scalar(
            select(AlertRule).where(
                AlertRule.source_type == source_type,
                AlertRule.source_id == policy.id,
            )
        )
        if rule is None:
            continue
        observe_alert(
            db,
            rule=rule,
            success=success,
            summary=summary,
            details={"policy_id": policy.id, "host_id": policy.host_id},
            now=now,
        )


def _observe_policy_alert(
    db: Session,
    policy: PortTrafficPolicy,
    *,
    source_type: str,
    success: bool,
    summary: str,
    details: dict[str, object],
    now: datetime,
) -> None:
    rule = db.scalar(
        select(AlertRule).where(
            AlertRule.source_type == source_type,
            AlertRule.source_id == policy.id,
        )
    )
    if rule is not None:
        observe_alert(
            db,
            rule=rule,
            success=success,
            summary=summary,
            details={"policy_id": policy.id, "host_id": policy.host_id, **details},
            now=now,
        )


def _traffic_spike(
    recent: list[PortTrafficSample],
    *,
    delta_rx: int,
    delta_tx: int,
) -> tuple[bool, int | None]:
    intervals: list[int] = []
    for newer, older in zip(recent, recent[1:], strict=False):
        if (
            newer.counter_generation == older.counter_generation
            and newer.rx_bytes_total >= older.rx_bytes_total
            and newer.tx_bytes_total >= older.tx_bytes_total
        ):
            intervals.append(
                newer.rx_bytes_total
                - older.rx_bytes_total
                + newer.tx_bytes_total
                - older.tx_bytes_total
            )
    if len(intervals) < 3:
        return False, None
    baseline = int(statistics.median(intervals))
    delta = delta_rx + delta_tx
    return delta > max(10 * 1024 * 1024, baseline * 10), baseline


def _bucket(value: datetime, resolution: str) -> datetime:
    aware = _aware(value).astimezone(UTC)
    if resolution == "hour":
        return aware.replace(minute=0, second=0, microsecond=0)
    return aware.replace(hour=0, minute=0, second=0, microsecond=0)


def _update_rollup(
    db: Session,
    model: type[PortTrafficHourlyRollup] | type[PortTrafficDailyRollup],
    *,
    policy: PortTrafficPolicy,
    collected_at: datetime,
    delta_rx: int,
    delta_tx: int,
    missing: int,
    discontinuity: bool,
    valid_interval: bool,
    resolution: str,
) -> None:
    bucket_start = _bucket(collected_at, resolution)
    row = db.scalar(
        select(model).where(
            model.policy_id == policy.id,
            model.bucket_start == bucket_start,
        )
    )
    if row is None:
        row = model(
            policy_id=policy.id,
            host_id=policy.host_id,
            bucket_start=bucket_start,
            rx_bytes=0,
            tx_bytes=0,
            sample_count=0,
            missing_intervals=0,
            discontinuity_count=0,
        )
        db.add(row)
    typed_row = cast(PortTrafficHourlyRollup | PortTrafficDailyRollup, row)
    typed_row.rx_bytes += delta_rx
    typed_row.tx_bytes += delta_tx
    typed_row.sample_count += int(valid_interval)
    typed_row.missing_intervals += missing
    typed_row.discontinuity_count += int(discontinuity)


def ingest_observations(
    db: Session,
    *,
    host_id: str,
    collected_at: datetime,
    observations: list[PortTrafficObservation],
) -> None:
    policies = {
        item.id: item
        for item in db.scalars(
            select(PortTrafficPolicy).where(
                PortTrafficPolicy.host_id == host_id,
                PortTrafficPolicy.enabled.is_(True),
            )
        ).all()
    }
    observed_policy_ids: set[str] = set()
    for observation in observations:
        policy = policies.get(observation.policy_id)
        if policy is None:
            continue
        recent = list(
            db.scalars(
                select(PortTrafficSample)
                .where(PortTrafficSample.policy_id == policy.id)
                .order_by(desc(PortTrafficSample.collected_at))
                .limit(11)
            ).all()
        )
        previous = recent[0] if recent else None
        if previous is not None:
            timestamp_order = _aware(collected_at) - _aware(previous.collected_at)
            if timestamp_order == timedelta(0):
                observed_policy_ids.add(policy.id)
                continue
            if timestamp_order < timedelta(0):
                continue
        observed_policy_ids.add(policy.id)
        reason = observation.discontinuity_reason
        delta_rx = delta_tx = missing = 0
        if previous is not None:
            elapsed = max(
                0,
                int(
                    (
                        _aware(collected_at) - _aware(previous.collected_at)
                    ).total_seconds()
                ),
            )
            missing = max(0, elapsed // EXPECTED_SAMPLE_SECONDS - 1)
            if observation.counter_generation != previous.counter_generation:
                reason = reason or "counter_reset"
            elif (
                observation.rx_bytes_total < previous.rx_bytes_total
                or observation.tx_bytes_total < previous.tx_bytes_total
            ):
                reason = reason or "counter_wrap"
            else:
                delta_rx = observation.rx_bytes_total - previous.rx_bytes_total
                delta_tx = observation.tx_bytes_total - previous.tx_bytes_total
        sample = PortTrafficSample(
            policy_id=policy.id,
            host_id=host_id,
            collected_at=collected_at,
            rx_bytes_total=observation.rx_bytes_total,
            tx_bytes_total=observation.tx_bytes_total,
            current_period_rx=observation.current_period_rx,
            current_period_tx=observation.current_period_tx,
            quota_bytes=observation.quota_bytes,
            counter_generation=observation.counter_generation,
            runtime_rule_state=observation.runtime_rule_state,
            shaping_state=observation.shaping_state,
            current_egress_rate_bps=observation.current_egress_rate_bps,
            discontinuity_reason=reason,
        )
        db.add(sample)
        for model, resolution in (
            (PortTrafficHourlyRollup, "hour"),
            (PortTrafficDailyRollup, "day"),
        ):
            _update_rollup(
                db,
                model,
                policy=policy,
                collected_at=collected_at,
                delta_rx=delta_rx,
                delta_tx=delta_tx,
                missing=missing,
                discontinuity=reason is not None,
                valid_interval=previous is not None and reason is None,
                resolution=resolution,
            )
        runtime = db.get(PortTrafficRuntimeState, policy.id)
        if runtime is None:
            runtime = PortTrafficRuntimeState(policy_id=policy.id)
            db.add(runtime)
        runtime.runtime_rule_state = observation.runtime_rule_state
        runtime.shaping_state = observation.shaping_state
        runtime.counter_generation = observation.counter_generation
        runtime.last_sample_at = collected_at
        runtime.restore_error = (
            reason if observation.runtime_rule_state in {"error", "missing"} else None
        )
        runtime.updated_at = datetime.now(UTC)
        quota = observation.quota_bytes or policy.quota_bytes
        total = observation.current_period_rx + observation.current_period_tx
        percent = (total * 100 / quota) if quota else None
        _observe_quota_alerts(db, policy, percent=percent, now=_aware(collected_at))
        expected_shaping = policy.egress_rate_bps is not None
        _observe_runtime_alerts(
            db,
            policy,
            rule_success=observation.runtime_rule_state == "active",
            shaping_success=(
                observation.shaping_state == "active"
                if expected_shaping
                else observation.shaping_state == "disabled"
            ),
            summary=(
                f"{policy.name} runtime={observation.runtime_rule_state} "
                f"shaping={observation.shaping_state}"
            ),
            now=_aware(collected_at),
        )
        spike, baseline = _traffic_spike(
            recent,
            delta_rx=delta_rx,
            delta_tx=delta_tx,
        )
        _observe_policy_alert(
            db,
            policy,
            source_type="port_traffic_spike",
            success=not spike,
            summary=f"{policy.name} traffic interval is {delta_rx + delta_tx} bytes",
            details={
                "interval_bytes": delta_rx + delta_tx,
                "baseline_bytes": baseline,
            },
            now=_aware(collected_at),
        )
        _observe_policy_alert(
            db,
            policy,
            source_type="port_traffic_enforcement",
            success=(
                policy.mode != "enforcing"
                or observation.runtime_rule_state == "active"
            ),
            summary=f"{policy.name} quota enforcement runtime state",
            details={"runtime_rule_state": observation.runtime_rule_state},
            now=_aware(collected_at),
        )
        _observe_policy_alert(
            db,
            policy,
            source_type="port_traffic_snapshot_gap",
            success=True,
            summary=f"{policy.name} traffic snapshot received",
            details={"collected_at": _aware(collected_at).isoformat()},
            now=_aware(collected_at),
        )
    for policy in policies.values():
        if policy.id in observed_policy_ids:
            continue
        runtime = db.get(PortTrafficRuntimeState, policy.id)
        last_sample_at = runtime.last_sample_at if runtime else None
        old_enough = (
            _aware(collected_at) - _aware(policy.created_at)
        ).total_seconds() > EXPECTED_SAMPLE_SECONDS * 3
        if old_enough and missing_is_gap(last_sample_at, now=_aware(collected_at)):
            _observe_runtime_alerts(
                db,
                policy,
                rule_success=False,
                shaping_success=policy.egress_rate_bps is None,
                summary=f"{policy.name} has a traffic sample gap",
                now=_aware(collected_at),
            )
            _observe_policy_alert(
                db,
                policy,
                source_type="port_traffic_snapshot_gap",
                success=False,
                summary=f"{policy.name} has a traffic snapshot gap",
                details={
                    "last_sample_at": (
                        _aware(last_sample_at).isoformat()
                        if last_sample_at is not None
                        else None
                    )
                },
                now=_aware(collected_at),
            )


def history_resolution(starts_at: datetime, ends_at: datetime) -> str:
    duration = _aware(ends_at) - _aware(starts_at)
    if duration <= timedelta(hours=24):
        return "raw"
    if duration <= timedelta(days=90):
        return "hour"
    return "day"


def query_history(
    db: Session,
    *,
    policy_id: str,
    starts_at: datetime,
    ends_at: datetime,
    limit: int,
) -> tuple[str, list[PortTrafficHistoryPoint]]:
    if _aware(ends_at) <= _aware(starts_at):
        raise PortTrafficError("history end must be after start")
    if _aware(ends_at) - _aware(starts_at) > timedelta(days=MAX_HISTORY_DAYS):
        raise PortTrafficError("history range exceeds 400 days")
    resolution = history_resolution(starts_at, ends_at)
    if resolution == "raw":
        rows = db.scalars(
            select(PortTrafficSample)
            .where(
                PortTrafficSample.policy_id == policy_id,
                PortTrafficSample.collected_at >= starts_at,
                PortTrafficSample.collected_at <= ends_at,
            )
            .order_by(PortTrafficSample.collected_at)
            .limit(limit)
        ).all()
        points: list[PortTrafficHistoryPoint] = []
        previous: PortTrafficSample | None = None
        for row in rows:
            # The first cumulative counter is a baseline, not a zero-traffic
            # interval. Omit it so callers cannot mistake missing history for 0.
            if previous is None:
                previous = row
                continue
            rx: int | None = None
            tx: int | None = None
            if (
                row.counter_generation == previous.counter_generation
                and row.rx_bytes_total >= previous.rx_bytes_total
                and row.tx_bytes_total >= previous.tx_bytes_total
            ):
                rx = row.rx_bytes_total - previous.rx_bytes_total
                tx = row.tx_bytes_total - previous.tx_bytes_total
            elapsed = max(
                0,
                int((_aware(row.collected_at) - _aware(previous.collected_at)).total_seconds()),
            )
            missing = max(0, elapsed // EXPECTED_SAMPLE_SECONDS - 1)
            points.append(
                PortTrafficHistoryPoint(
                    at=row.collected_at,
                    rx_bytes=rx,
                    tx_bytes=tx,
                    combined_bytes=rx + tx if rx is not None and tx is not None else None,
                    missing_intervals=missing,
                    discontinuity_count=int(row.discontinuity_reason is not None),
                    discontinuity_reason=row.discontinuity_reason,
                )
            )
            previous = row
        return resolution, points
    if resolution == "hour":
        hourly = db.scalars(
            select(PortTrafficHourlyRollup)
            .where(
                PortTrafficHourlyRollup.policy_id == policy_id,
                PortTrafficHourlyRollup.bucket_start >= starts_at,
                PortTrafficHourlyRollup.bucket_start <= ends_at,
            )
            .order_by(PortTrafficHourlyRollup.bucket_start)
            .limit(limit)
        ).all()
        rollups: list[PortTrafficHourlyRollup | PortTrafficDailyRollup] = list(hourly)
    else:
        daily = db.scalars(
            select(PortTrafficDailyRollup)
            .where(
                PortTrafficDailyRollup.policy_id == policy_id,
                PortTrafficDailyRollup.bucket_start >= starts_at,
                PortTrafficDailyRollup.bucket_start <= ends_at,
            )
            .order_by(PortTrafficDailyRollup.bucket_start)
            .limit(limit)
        ).all()
        rollups = list(daily)
    return resolution, [
        PortTrafficHistoryPoint(
            at=row.bucket_start,
            rx_bytes=row.rx_bytes if row.sample_count else None,
            tx_bytes=row.tx_bytes if row.sample_count else None,
            combined_bytes=row.rx_bytes + row.tx_bytes if row.sample_count else None,
            missing_intervals=row.missing_intervals,
            discontinuity_count=row.discontinuity_count,
        )
        for row in rollups
    ]


def estimate_exhaustion(
    *,
    period_total: int,
    quota_bytes: int | None,
    period_start: datetime | None,
    now: datetime,
) -> datetime | None:
    if quota_bytes is None or period_start is None or period_total <= 0:
        return None
    elapsed = (_aware(now) - _aware(period_start)).total_seconds()
    if elapsed <= 0:
        return None
    bytes_per_second = period_total / elapsed
    remaining = quota_bytes - period_total
    if remaining <= 0:
        return _aware(now)
    return _aware(now) + timedelta(seconds=remaining / bytes_per_second)


def prune_port_traffic(db: Session, *, now: datetime | None = None) -> dict[str, int]:
    checked_at = _aware(now or datetime.now(UTC))
    counts = {}
    for name, model, column, days in (
        ("raw", PortTrafficSample, PortTrafficSample.collected_at, RAW_RETENTION_DAYS),
        (
            "hourly",
            PortTrafficHourlyRollup,
            PortTrafficHourlyRollup.bucket_start,
            HOURLY_RETENTION_DAYS,
        ),
        (
            "daily",
            PortTrafficDailyRollup,
            PortTrafficDailyRollup.bucket_start,
            DAILY_RETENTION_DAYS,
        ),
    ):
        result = db.execute(
            delete(model).where(column < checked_at - timedelta(days=days))
        )
        counts[name] = int(getattr(result, "rowcount", 0) or 0)
    return counts


def quota_state(percent: float | None) -> str:
    return _quota_state(percent)


def missing_is_gap(last_sample_at: datetime | None, *, now: datetime) -> bool:
    return last_sample_at is None or (
        _aware(now) - _aware(last_sample_at)
    ).total_seconds() > EXPECTED_SAMPLE_SECONDS * 3


def safe_missing_count(elapsed_seconds: float) -> int:
    return max(0, math.floor(elapsed_seconds / EXPECTED_SAMPLE_SECONDS) - 1)


def dispatch_due_port_traffic_resets(
    db: Session,
    *,
    settings: Settings,
    now: datetime | None = None,
) -> int:
    """Queue each due approved schedule once; reconciliation advances the boundary."""
    from guardian.audit import write_audit
    from guardian.tasking import create_agent_task

    current = _aware(now or datetime.now(UTC))
    runtimes = db.scalars(
        select(PortTrafficRuntimeState).where(
            PortTrafficRuntimeState.next_reset_at.is_not(None),
            PortTrafficRuntimeState.next_reset_at <= current,
        )
    ).all()
    queued = 0
    for runtime in runtimes:
        due_at = runtime.next_reset_at
        if due_at is None:
            continue
        policy = db.get(PortTrafficPolicy, runtime.policy_id)
        if policy is None or not policy.enabled:
            continue
        normalized = validate_reset_policy(policy.reset_policy)
        if normalized["type"] == "manual":
            runtime.next_reset_at = None
            continue
        if not (
            policy.reset_approval_id
            and policy.reset_requested_by
            and policy.reset_approved_by
            and policy.reset_requested_by != policy.reset_approved_by
        ):
            runtime.restore_error = "scheduled reset lacks independent approval provenance"
            runtime.updated_at = current
            _observe_policy_alert(
                db,
                policy,
                source_type="port_traffic_enforcement",
                success=False,
                summary=f"{policy.name} scheduled reset authorization is invalid",
                details={"next_reset_at": _aware(due_at).isoformat()},
                now=current,
            )
            continue
        outstanding = db.scalar(
            select(AgentTask).where(
                AgentTask.target_host_id == policy.host_id,
                AgentTask.action == "port_traffic_reset",
                AgentTask.status.in_(["pending", "running"]),
                AgentTask.parameters["policy_id"].as_string() == policy.id,
            )
        )
        if outstanding is not None:
            continue
        agent = db.scalar(
            select(Agent).where(
                Agent.host_id == policy.host_id,
                Agent.revoked_at.is_(None),
            )
        )
        if agent is None:
            runtime.restore_error = "scheduled reset has no active Agent"
            runtime.updated_at = current
            continue
        parameters = {
            "policy_id": policy.id,
            "protocol": policy.protocol,
            "direction": policy.direction,
            "port_start": str(policy.port_start),
            "port_end": str(policy.port_end),
            "interface_name": policy.interface_name or "",
            "mode": policy.mode,
            "quota_bytes": str(policy.quota_bytes or 0),
            "egress_rate_bps": str(policy.egress_rate_bps or 0),
            "counter_generation": str(policy.generation),
            "reset_policy": json.dumps(
                policy.reset_policy,
                separators=(",", ":"),
                sort_keys=True,
            ),
            "next_reset_at": (
                next_boundary.isoformat()
                if (
                    next_boundary := next_reset_at(
                        policy.reset_policy,
                        after=_aware(due_at),
                    )
                )
                else ""
            ),
            "reason": "scheduled",
            "scheduled_for": _aware(due_at).isoformat(),
            "second_confirmation": "confirmed",
            "dry_run": "false",
        }
        task = create_agent_task(
            db,
            agent_id=agent.id,
            action="port_traffic_reset",
            parameters=parameters,
            settings=settings,
            approval_id=policy.reset_approval_id,
            requester_id=policy.reset_requested_by,
            approver_id=policy.reset_approved_by,
            target_host_id=policy.host_id,
        )
        runtime.restore_error = None
        runtime.updated_at = current
        write_audit(
            db,
            actor=None,
            action="port_traffic.scheduled_reset_queued",
            resource_type="port_traffic_policy",
            resource_id=policy.id,
            outcome="pending",
            details={
                "task_id": task.id,
                "scheduled_for": parameters["scheduled_for"],
            },
        )
        queued += 1
    return queued
