from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import delete, desc, select
from sqlalchemy.orm import Session

from guardian.alerting import observe_alert
from guardian.models import (
    Agent,
    AlertRule,
    CheckResultStatus,
    MetricSnapshot,
    ServiceCheck,
    ServiceCheckResult,
)
from guardian.probes import ProbeDefinition, ProbeResult, run_probe
from guardian.redaction import redact_structure


def _configuration(check: ServiceCheck) -> dict[str, Any]:
    return cast(dict[str, Any], check.configuration)


def probe_definition_from_check(check: ServiceCheck) -> ProbeDefinition:
    configuration = _configuration(check)
    target = str(configuration.get("target", ""))
    kind = "http" if check.kind in {"http", "https"} else check.kind
    if kind not in {"http", "tcp", "icmp"}:
        raise ValueError("check kind must run on its selected agent")
    return ProbeDefinition(
        id=check.id,
        kind=cast(Any, kind),
        target=target,
        port=configuration.get("port"),
        timeout_seconds=check.timeout_seconds,
        expected_statuses=configuration.get("expected_statuses", [200]),
        expected_contains=configuration.get("expected_contains"),
        expected_json=configuration.get("expected_json"),
        verify_tls=bool(configuration.get("verify_tls", True)),
        allowed_networks=configuration.get("allowed_networks", []),
        denied_networks=configuration.get("denied_networks", []),
        max_response_bytes=int(configuration.get("max_response_bytes", 65536)),
    )


def _rule_for_check(db: Session, check: ServiceCheck) -> AlertRule | None:
    return db.scalar(
        select(AlertRule).where(
            AlertRule.source_type == "service_check", AlertRule.source_id == check.id
        )
    )


def persist_check_result(
    db: Session,
    *,
    check: ServiceCheck,
    result: ProbeResult,
) -> ServiceCheckResult:
    status = (
        CheckResultStatus.ok.value
        if result.success
        else CheckResultStatus.unsupported.value
        if result.status == "unsupported"
        else CheckResultStatus.failed.value
    )
    details = redact_structure(result.evidence)
    if not isinstance(details, dict):
        details = {}
    record = ServiceCheckResult(
        check_id=check.id,
        status=status,
        checked_at=result.checked_at,
        latency_ms=result.latency_ms,
        status_code=(
            int(details["status"])
            if isinstance(details.get("status"), int)
            else None
        ),
        message=result.error[:512] if result.error else None,
        details=details,
    )
    check.last_checked_at = result.checked_at
    check.updated_at = result.checked_at
    db.add(record)
    rule = _rule_for_check(db, check)
    if rule is not None and rule.enabled and status != CheckResultStatus.unsupported.value:
        observe_alert(
            db,
            rule=rule,
            success=result.success,
            summary=(result.error or f"{check.name} is healthy")[:512],
            details={"check_id": check.id, "kind": check.kind, "status": status},
            now=result.checked_at,
        )
    return record


async def run_due_controller_checks(
    db: Session, *, now: datetime | None = None
) -> list[ServiceCheckResult]:
    now = now or datetime.now(UTC)
    checks = db.scalars(
        select(ServiceCheck).where(
            ServiceCheck.enabled.is_(True), ServiceCheck.runner_agent_id.is_(None)
        )
    ).all()
    records: list[ServiceCheckResult] = []
    for check in checks:
        last_checked = check.last_checked_at
        if last_checked is not None:
            if last_checked.tzinfo is None:
                last_checked = last_checked.replace(tzinfo=UTC)
            if last_checked + timedelta(seconds=check.interval_seconds) > now:
                continue
        try:
            definition = probe_definition_from_check(check)
        except ValueError as exc:
            result = ProbeResult(
                check.id,
                check.kind,
                False,
                now,
                0,
                error=str(exc),
                status="unsupported",
            )
        else:
            result = await run_probe(definition)
        records.append(persist_check_result(db, check=check, result=result))
    return records


def assigned_agent_checks(db: Session, agent: Agent) -> list[dict[str, object]]:
    checks = db.scalars(
        select(ServiceCheck).where(
            ServiceCheck.enabled.is_(True), ServiceCheck.runner_agent_id == agent.id
        )
    ).all()
    return [
        {
            "id": check.id,
            "kind": check.kind,
            "configuration": check.configuration,
            "timeout_seconds": check.timeout_seconds,
        }
        for check in checks
    ]


def record_agent_check_results(
    db: Session,
    *,
    agent: Agent,
    services: list[dict[str, Any]],
    now: datetime | None = None,
) -> int:
    now = now or datetime.now(UTC)
    accepted = 0
    for item in services[:500]:
        if item.get("kind") != "guardian_check_result":
            continue
        check_id = str(item.get("check_id", ""))
        check = db.scalar(
            select(ServiceCheck).where(
                ServiceCheck.id == check_id,
                ServiceCheck.runner_agent_id == agent.id,
                ServiceCheck.enabled.is_(True),
            )
        )
        if check is None:
            continue
        raw_status = str(item.get("status", "error"))
        status = raw_status if raw_status in {"ok", "failed", "unsupported"} else "error"
        raw_details = redact_structure(item.get("details", {}))
        details = raw_details if isinstance(raw_details, dict) else {}
        result = ProbeResult(
            probe_id=check.id,
            kind=check.kind,
            success=status == "ok",
            checked_at=now,
            latency_ms=float(item.get("latency_ms", 0)),
            evidence=details,
            error=str(item.get("message", ""))[:300] or None,
            status=cast(Any, status if status != "error" else "failed"),
        )
        persist_check_result(db, check=check, result=result)
        accepted += 1
    return accepted


def prune_monitoring_history(
    db: Session,
    *,
    metric_retention_days: int,
    check_retention_days: int,
    max_metric_rows_per_host: int,
    max_results_per_check: int,
    now: datetime | None = None,
) -> None:
    now = now or datetime.now(UTC)
    db.execute(
        delete(MetricSnapshot).where(
            MetricSnapshot.collected_at < now - timedelta(days=metric_retention_days)
        )
    )
    db.execute(
        delete(ServiceCheckResult).where(
            ServiceCheckResult.checked_at < now - timedelta(days=check_retention_days)
        )
    )
    host_ids = db.scalars(select(MetricSnapshot.host_id).distinct()).all()
    for host_id in host_ids:
        keep = select(MetricSnapshot.id).where(MetricSnapshot.host_id == host_id).order_by(
            desc(MetricSnapshot.collected_at)
        ).limit(max_metric_rows_per_host)
        db.execute(
            delete(MetricSnapshot).where(
                MetricSnapshot.host_id == host_id, MetricSnapshot.id.not_in(keep)
            )
        )
    check_ids = db.scalars(select(ServiceCheckResult.check_id).distinct()).all()
    for check_id in check_ids:
        keep = (
            select(ServiceCheckResult.id)
            .where(ServiceCheckResult.check_id == check_id)
            .order_by(desc(ServiceCheckResult.checked_at))
            .limit(max_results_per_check)
        )
        db.execute(
            delete(ServiceCheckResult).where(
                ServiceCheckResult.check_id == check_id,
                ServiceCheckResult.id.not_in(keep),
            )
        )

