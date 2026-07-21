from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian.audit import write_audit
from guardian.config import Settings
from guardian.diagnostics import Diagnosis, DiagnosticContext, DiagnosticEngine
from guardian.models import (
    Agent,
    AgentTask,
    Incident,
    IncidentStatus,
    RepairAttempt,
)
from guardian.redaction import redact_structure
from guardian.runbooks import RepairOrchestrator, load_runbook
from guardian.schemas import AgentHeartbeat

STAGING_PROFILE = "staging_acceptance"
STAGE_ID = re.compile(r"^[a-f0-9]{32}$")
TERMINAL_TASK_STATES = {"succeeded", "failed"}


@dataclass(slots=True)
class Observation:
    diagnosis: Diagnosis
    service: str
    context: dict[str, str]


def _profile(agent: Agent) -> dict[str, str] | None:
    labels = agent.host.labels
    if labels.get("guardian_profile") != STAGING_PROFILE:
        return None
    stage_id = labels.get("guardian_stage_id", "")
    if not STAGE_ID.fullmatch(stage_id):
        return None
    return labels


def _docker_records(services: list[dict[str, Any]], stage_id: str) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    required_labels = (
        "org.vps-guardian.scope=staging",
        f"org.vps-guardian.stage-id={stage_id}",
    )
    for item in services:
        if item.get("kind") != "docker" or not isinstance(item.get("summary"), str):
            continue
        for line in item["summary"].splitlines()[:500]:
            try:
                record = json.loads(line)
            except (TypeError, ValueError):
                continue
            if not isinstance(record, dict):
                continue
            labels = str(record.get("Labels", ""))
            if not all(label in labels for label in required_labels):
                continue
            output.append(
                {
                    "name": str(record.get("Names", ""))[:128],
                    "state": str(record.get("State", "")).lower()[:32],
                    "status": str(record.get("Status", ""))[:128],
                }
            )
    return output


def _fixture_record(records: list[dict[str, str]], service: str) -> dict[str, str] | None:
    suffix = f"-fixture-{service}-1"
    matches = [record for record in records if record["name"].endswith(suffix)]
    return matches[0] if len(matches) == 1 else None


def _probes(metrics: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = metrics.get("probes", [])
    if not isinstance(raw, list):
        return {}
    output: dict[str, dict[str, Any]] = {}
    for item in raw[:100]:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            output[item["name"][:128]] = item
    return output


def _percentage(total: object, free: object) -> float | None:
    if not isinstance(total, (int, float)) or not isinstance(free, (int, float)) or total <= 0:
        return None
    return round((float(total) - float(free)) * 100 / float(total), 2)


def _config_invalid(services: list[dict[str, Any]], container: str) -> bool:
    matches = [
        item
        for item in services
        if item.get("kind") == "config_validation"
        and item.get("container") == container
        and item.get("config_path")
        == "/var/lib/vps-guardian-staging/fixtures/caddy/Caddyfile"
    ]
    return len(matches) == 1 and matches[0].get("healthy") is False


def _observe(agent: Agent, payload: AgentHeartbeat, labels: dict[str, str]) -> Observation | None:
    engine = DiagnosticEngine()
    records = _docker_records(payload.services, labels["guardian_stage_id"])
    api_container = _fixture_record(records, "api")
    caddy_container = _fixture_record(records, "caddy")
    probes = _probes(payload.metrics)
    api_probe = probes.get("fixture-api", {})
    edge_probe = probes.get("fixture-edge", {})
    database_probe = probes.get("fixture-database", {})
    controller_probe = probes.get("controller", {})

    if api_container and api_container["state"] in {"exited", "dead"}:
        diagnoses = engine.diagnose(
            DiagnosticContext(
                host_id=agent.host_id,
                service="fixture-api",
                agent_online=True,
                container_state=api_container["state"],
            )
        )
        if diagnoses:
            return Observation(
                diagnoses[0],
                "fixture-api",
                {
                    "agent_online": "true",
                    "service": "fixture-api",
                    "container": api_container["name"],
                    "health_url": "http://127.0.0.1:18080/health",
                },
            )

    if caddy_container and _config_invalid(payload.services, caddy_container["name"]):
        diagnoses = engine.diagnose(
            DiagnosticContext(
                host_id=agent.host_id,
                service="fixture-caddy",
                agent_online=True,
                local_app_healthy=False,
                container_state=caddy_container["state"],
                recent_deployment={"scope": "staging fixture configuration"},
            )
        )
        if diagnoses:
            diagnosis = next(
                item for item in diagnoses if item.fault_type == "post_deployment_regression"
            )
            return Observation(
                diagnosis,
                "fixture-caddy",
                {
                    "agent_online": "true",
                    "service": "fixture-caddy",
                    "container": caddy_container["name"],
                    "config_path": (
                        "/var/lib/vps-guardian-staging/fixtures/caddy/Caddyfile"
                    ),
                    "health_url": "http://127.0.0.1:18082/health",
                    "verified_recovery_point": "true",
                    "recovery_point": "staging-baseline",
                    "changed_seconds_ago": "60",
                },
            )

    if (
        database_probe.get("failure_class") == "database_corruption"
        and database_probe.get("http_ok") is False
        and api_probe.get("http_ok") is True
    ):
        diagnoses = engine.diagnose(
            DiagnosticContext(
                host_id=agent.host_id,
                service="fixture-database",
                agent_online=True,
                database_error="malformed page",
                database_service_running=True,
                database_port_open=True,
            )
        )
        if diagnoses:
            return Observation(
                diagnoses[0],
                "fixture-database",
                {"agent_online": "true", "service": "fixture-database"},
            )

    disk_percent = _percentage(
        payload.metrics.get("disk_total_bytes"), payload.metrics.get("disk_free_bytes")
    )
    inode_percent = _percentage(
        payload.metrics.get("inode_total"), payload.metrics.get("inode_free")
    )
    if (disk_percent is not None and disk_percent >= 90) or (
        inode_percent is not None and inode_percent >= 90
    ):
        diagnoses = engine.diagnose(
            DiagnosticContext(
                host_id=agent.host_id,
                service="fixture-cache",
                agent_online=True,
                disk_percent=disk_percent,
                inode_percent=inode_percent,
                disk_usage_sources=[{"path": "staging fixture cache", "scope": "allowlisted"}],
            )
        )
        if diagnoses:
            return Observation(
                diagnoses[0],
                "fixture-cache",
                {
                    "agent_online": "true",
                    "service": "fixture-cache",
                    "cache_path": "/var/lib/vps-guardian-staging/fixtures/cache",
                    "health_url": "http://127.0.0.1:18080/health",
                },
            )

    if (
        edge_probe.get("http_status") == 502
        and api_probe.get("http_ok") is True
        and edge_probe.get("tcp_ok") is True
    ):
        diagnoses = engine.diagnose(
            DiagnosticContext(
                host_id=agent.host_id,
                service="fixture-edge",
                tcp_443_ok=True,
                tls_ok=controller_probe.get("tls_ok") is True,
                http_status=502,
            )
        )
        if diagnoses:
            return Observation(
                diagnoses[0],
                "fixture-edge",
                {"agent_online": "true", "service": "fixture-edge"},
            )

    if edge_probe.get("http_ok") is False and api_probe.get("http_ok") is True:
        diagnoses = engine.diagnose(
            DiagnosticContext(
                host_id=agent.host_id,
                service="fixture-edge",
                agent_online=True,
                local_app_healthy=True,
                external_https_ok=False,
                http_status=(
                    int(edge_probe["http_status"])
                    if isinstance(edge_probe.get("http_status"), int)
                    else None
                ),
            )
        )
        if diagnoses:
            return Observation(
                diagnoses[0],
                "fixture-edge",
                {"agent_online": "true", "service": "fixture-edge"},
            )

    if (
        api_container
        and api_container["state"] == "running"
        and api_probe.get("http_ok") is False
    ):
        diagnoses = engine.diagnose(
            DiagnosticContext(
                host_id=agent.host_id,
                service="fixture-api",
                agent_online=True,
                local_app_healthy=False,
                container_state="running",
                http_status=(
                    int(api_probe["http_status"])
                    if isinstance(api_probe.get("http_status"), int)
                    else None
                ),
            )
        )
        if diagnoses:
            diagnosis = next(
                item for item in diagnoses if item.fault_type == "application_health_failed"
            )
            return Observation(
                diagnosis,
                "fixture-api",
                {
                    "agent_online": "true",
                    "service": "fixture-api",
                    "container": api_container["name"],
                    "health_url": "http://127.0.0.1:18080/health",
                },
            )
    return None


def _active_incident(
    db: Session, *, host_id: str, service: str, fault_type: str
) -> Incident | None:
    incidents = db.scalars(
        select(Incident)
        .where(Incident.status != IncidentStatus.resolved.value)
        .order_by(Incident.first_seen_at.desc())
    ).all()
    return next(
        (
            incident
            for incident in incidents
            if incident.fault_type == fault_type
            and host_id in incident.affected_hosts
            and service in incident.affected_services
        ),
        None,
    )


def _open_incident(db: Session, agent: Agent, observation: Observation) -> Incident:
    existing = _active_incident(
        db,
        host_id=agent.host_id,
        service=observation.service,
        fault_type=observation.diagnosis.fault_type,
    )
    if existing:
        return existing
    now = datetime.now(UTC)
    diagnosis = observation.diagnosis
    incident = Incident(
        title=f"{observation.service}: {diagnosis.fault_type}",
        fault_type=diagnosis.fault_type,
        severity=4 if diagnosis.fault_type == "database_corruption" else 2,
        status=IncidentStatus.open.value,
        confidence=diagnosis.confidence,
        affected_hosts=[agent.host_id],
        affected_services=[observation.service],
        evidence=[
            *diagnosis.evidence,
            {"name": "monitor_profile", "value": STAGING_PROFILE, "source": "controller"},
        ],
        excluded_causes=diagnosis.excluded_causes,
        recommendations=diagnosis.recommendations,
        auto_repair_allowed=diagnosis.auto_repair_allowed,
        risk=diagnosis.risk,
        verification_plan=diagnosis.verification,
        timeline=[{"at": now.isoformat(), "message": f"detected by rule {diagnosis.rule_id}"}],
    )
    db.add(incident)
    db.flush()
    write_audit(
        db,
        actor=None,
        action="incident.detected",
        resource_type="incident",
        resource_id=incident.id,
        outcome="success",
        details={"fault_type": diagnosis.fault_type, "rule_id": diagnosis.rule_id},
    )
    return incident


def _append_once(incident: Incident, marker: str, message: str) -> bool:
    if any(marker in str(item.get("message", "")) for item in incident.timeline):
        return False
    incident.timeline = [
        *incident.timeline,
        {"at": datetime.now(UTC).isoformat(), "message": message},
    ]
    return True


def _record_stop_once(
    db: Session,
    incident: Incident,
    *,
    marker: str,
    message: str,
    reason: str,
) -> None:
    if not _append_once(incident, marker, message):
        return
    write_audit(
        db,
        actor=None,
        action="repair.plan",
        resource_type="incident",
        resource_id=incident.id,
        outcome="blocked",
        details={"reason": reason, "task_count": 0},
    )


def _repair_details(
    observation: Observation, settings: Settings
) -> tuple[Path, dict[str, str]] | None:
    mapping = {
        "container_exited": "restart_exited_container.yaml",
        "application_health_failed": "restart_unhealthy_container.yaml",
        "storage_pressure": "cleanup_allowlisted_cache.yaml",
        "post_deployment_regression": "rollback_caddy_config.yaml",
    }
    filename = mapping.get(observation.diagnosis.fault_type)
    if not filename:
        return None
    return settings.runbook_directory / filename, observation.context


def _record_plan_audit(
    db: Session, incident: Incident, plan_reason: str, task_ids: list[str]
) -> None:
    write_audit(
        db,
        actor=None,
        action="repair.plan",
        resource_type="incident",
        resource_id=incident.id,
        outcome="scheduled" if task_ids else "blocked",
        details={"reason": plan_reason, "task_count": len(task_ids)},
    )


def _maybe_dispatch(
    db: Session,
    *,
    agent: Agent,
    incident: Incident,
    observation: Observation,
    labels: dict[str, str],
    settings: Settings,
) -> None:
    locked_incident = db.scalar(
        select(Incident).where(Incident.id == incident.id).with_for_update()
    )
    if locked_incident is None:
        return
    incident = locked_incident
    details = _repair_details(observation, settings)
    if details is None:
        return
    path, context = details
    runbook = load_runbook(path)
    attempts = list(
        db.scalars(
            select(RepairAttempt)
            .where(
                RepairAttempt.incident_id == incident.id,
                RepairAttempt.action == runbook.name,
            )
            .order_by(RepairAttempt.created_at.desc())
        ).all()
    )
    actual = [attempt for attempt in attempts if not attempt.dry_run]
    dry_runs = [attempt for attempt in attempts if attempt.dry_run]
    if actual:
        latest = actual[0]
        if latest.success is None:
            _record_stop_once(
                db,
                incident,
                marker="repair already in progress",
                message="repair already in progress; concurrent dispatch suppressed",
                reason="concurrent repair is already in progress",
            )
            return
        created_at = latest.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        cooldown_active = datetime.now(UTC) < created_at + runbook.cooldown
        maximum_reached = len(actual) >= runbook.max_attempts
        if cooldown_active:
            _record_stop_once(
                db,
                incident,
                marker="repair cooldown",
                message="repair cooldown is active; early retry blocked",
                reason="repair cooldown is active; incident remains escalated",
            )
        if maximum_reached:
            _record_stop_once(
                db,
                incident,
                marker="maximum repair attempts",
                message="maximum repair attempts reached; incident escalated without retry",
                reason="maximum repair attempts reached; incident must be escalated",
            )
        if cooldown_active or maximum_reached:
            return
        plan = RepairOrchestrator().plan(
            db,
            runbook=runbook,
            incident=incident,
            agent=agent,
            context=context,
            settings=settings,
            dry_run=False,
            level2_enabled=labels.get("guardian_level2_caddy") == "true",
        )
        _record_plan_audit(db, incident, plan.reason, plan.task_ids)
        return
    if dry_runs:
        if dry_runs[0].success is None:
            _record_stop_once(
                db,
                incident,
                marker="repair already in progress",
                message="repair already in progress; concurrent dispatch suppressed",
                reason="concurrent repair is already in progress",
            )
            return
        if dry_runs[0].success is False:
            _append_once(incident, "dry-run failed", "dry-run failed; automatic execution blocked")
            return
        if runbook.risk_level == 2 and labels.get("guardian_level2_caddy") != "true":
            _append_once(
                incident,
                "Level 2 switch",
                "dry-run passed; waiting for explicit Level 2 switch",
            )
            return
        plan = RepairOrchestrator().plan(
            db,
            runbook=runbook,
            incident=incident,
            agent=agent,
            context=context,
            settings=settings,
            dry_run=False,
            level2_enabled=labels.get("guardian_level2_caddy") == "true",
        )
        _record_plan_audit(db, incident, plan.reason, plan.task_ids)
        return
    plan = RepairOrchestrator().plan(
        db,
        runbook=runbook,
        incident=incident,
        agent=agent,
        context=context,
        settings=settings,
        dry_run=True,
        level2_enabled=labels.get("guardian_level2_caddy") == "true",
    )
    _record_plan_audit(db, incident, plan.reason, plan.task_ids)


def record_agent_results(db: Session, agent: Agent, events: list[dict[str, Any]]) -> None:
    changed_task_ids: set[str] = set()
    for event in events:
        if event.get("type") != "action_result" or not isinstance(event.get("result"), dict):
            continue
        result = event["result"]
        task_id = str(result.get("task_id", ""))
        task = db.scalar(
            select(AgentTask).where(AgentTask.id == task_id, AgentTask.agent_id == agent.id)
        )
        if not task or task.status in TERMINAL_TASK_STATES:
            continue
        task.status = "succeeded" if result.get("success") is True else "failed"
        redacted = redact_structure(result)
        task.result = redacted if isinstance(redacted, dict) else {"result": "invalid"}
        changed_task_ids.add(task.id)
        write_audit(
            db,
            actor=None,
            action="agent.task_result",
            resource_type="agent_task",
            resource_id=task.id,
            outcome=task.status,
            details={"action": task.action, "dry_run": task.parameters.get("dry_run")},
        )
    if not changed_task_ids:
        return
    attempts = db.scalars(
        select(RepairAttempt).where(RepairAttempt.success.is_(None))
    ).all()
    for attempt in attempts:
        raw_ids = attempt.after_state.get("task_ids", [])
        if not isinstance(raw_ids, list) or not raw_ids:
            continue
        task_ids = [str(item) for item in raw_ids]
        tasks = list(db.scalars(select(AgentTask).where(AgentTask.id.in_(task_ids))).all())
        if len(tasks) != len(task_ids) or any(
            task.status not in TERMINAL_TASK_STATES for task in tasks
        ):
            continue
        attempt.success = all(task.status == "succeeded" for task in tasks)
        attempt.after_state = {
            **attempt.after_state,
            "task_statuses": {task.id: task.status for task in tasks},
        }
        incident = db.get(Incident, attempt.incident_id)
        if incident:
            outcome = "passed" if attempt.success else "failed"
            incident.timeline = [
                *incident.timeline,
                {
                    "at": datetime.now(UTC).isoformat(),
                    "message": f"repair {attempt.action} {outcome}",
                },
            ]
        write_audit(
            db,
            actor=None,
            action="repair.completed",
            resource_type="repair_attempt",
            resource_id=attempt.id,
            outcome="success" if attempt.success else "failed",
            details={"runbook": attempt.action, "dry_run": attempt.dry_run},
        )


def _resolve_absent_incidents(
    db: Session, agent: Agent, current_incident: Incident | None
) -> None:
    for incident in db.scalars(
        select(Incident).where(Incident.status != IncidentStatus.resolved.value)
    ).all():
        if incident is current_incident or agent.host_id not in incident.affected_hosts:
            continue
        if not any(
            item.get("name") == "monitor_profile" and item.get("value") == STAGING_PROFILE
            for item in incident.evidence
        ):
            continue
        incident.status = IncidentStatus.resolved.value
        incident.resolved_at = datetime.now(UTC)
        incident.timeline = [
            *incident.timeline,
            {"at": incident.resolved_at.isoformat(), "message": "healthy observation confirmed"},
        ]
        write_audit(
            db,
            actor=None,
            action="incident.resolved",
            resource_type="incident",
            resource_id=incident.id,
            outcome="success",
            details={"fault_type": incident.fault_type},
        )


def reconcile_staging_heartbeat(
    db: Session,
    *,
    agent: Agent,
    payload: AgentHeartbeat,
    settings: Settings,
) -> None:
    """Reconcile a heartbeat inside the caller's Agent-row-locked transaction."""
    labels = _profile(agent)
    if labels is None:
        return
    observation = _observe(agent, payload, labels)
    incident = _open_incident(db, agent, observation) if observation else None
    _resolve_absent_incidents(db, agent, incident)
    if incident and observation:
        _maybe_dispatch(
            db,
            agent=agent,
            incident=incident,
            observation=observation,
            labels=labels,
            settings=settings,
        )
