from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from guardian.config import Settings
from guardian.database import SessionLocal
from guardian.models import Agent, AgentTask, AuditLog, Host, Incident, RepairAttempt
from guardian.reconciliation import reconcile_staging_heartbeat, record_agent_results
from guardian.schemas import AgentHeartbeat
from sqlalchemy import select

RUNBOOKS = Path(__file__).parents[1] / "runbooks"
STAGE_ID = "a" * 32


def staging_inventory() -> str:
    with SessionLocal() as db:
        host = Host(
            name="staging-agent",
            address="192.0.2.10",
            labels={
                "guardian_profile": "staging_acceptance",
                "guardian_stage_id": STAGE_ID,
                "guardian_level2_caddy": "false",
            },
        )
        db.add(host)
        db.flush()
        agent = Agent(
            host_id=host.id,
            signing_public_key="A" * 44,
            certificate_fingerprint="AA" * 32,
        )
        db.add(agent)
        db.commit()
        return agent.id


def exited_payload() -> AgentHeartbeat:
    docker_record = {
        "Names": "vps-guardian-staging-fixture-api-1",
        "State": "exited",
        "Status": "Exited (1)",
        "Labels": (
            "org.vps-guardian.scope=staging,"
            f"org.vps-guardian.stage-id={STAGE_ID}"
        ),
    }
    return AgentHeartbeat(
        collected_at=datetime.now(UTC),
        version="0.1.0",
        metrics={"disk_total_bytes": 100, "disk_free_bytes": 50, "probes": []},
        services=[{"kind": "docker", "summary": json.dumps(docker_record)}],
        events=[],
    )


def invalid_caddy_payload() -> AgentHeartbeat:
    container = "vps-guardian-staging-fixture-caddy-1"
    docker_record = {
        "Names": container,
        "State": "running",
        "Status": "Up 1 minute (unhealthy)",
        "Labels": (
            "org.vps-guardian.scope=staging,"
            f"org.vps-guardian.stage-id={STAGE_ID}"
        ),
    }
    return AgentHeartbeat(
        collected_at=datetime.now(UTC),
        version="0.1.0",
        metrics={"disk_total_bytes": 100, "disk_free_bytes": 50, "probes": []},
        services=[
            {"kind": "docker", "summary": json.dumps(docker_record)},
            {
                "kind": "config_validation",
                "container": container,
                "config_path": "/var/lib/vps-guardian-staging/fixtures/caddy/Caddyfile",
                "healthy": False,
            },
        ],
        events=[],
    )


def failed_database_probe_payload(*, api_ok: bool) -> AgentHeartbeat:
    docker_record = {
        "Names": "vps-guardian-staging-fixture-api-1",
        "State": "running",
        "Status": "Up 1 minute",
        "Labels": (
            "org.vps-guardian.scope=staging,"
            f"org.vps-guardian.stage-id={STAGE_ID}"
        ),
    }
    return AgentHeartbeat(
        collected_at=datetime.now(UTC),
        version="0.1.0",
        metrics={
            "disk_total_bytes": 100,
            "disk_free_bytes": 50,
            "probes": [
                {
                    "name": "fixture-api",
                    "http_ok": api_ok,
                    "http_status": 200 if api_ok else 503,
                },
                {
                    "name": "fixture-database",
                    "http_ok": False,
                    "http_status": 503,
                    "failure_class": "database_corruption",
                },
            ],
        },
        services=[{"kind": "docker", "summary": json.dumps(docker_record)}],
        events=[],
    )


def result_event(task: AgentTask, success: bool = True) -> dict[str, object]:
    return {
        "type": "action_result",
        "result": {
            "task_id": task.id,
            "action": task.action,
            "success": success,
            "dry_run": task.parameters["dry_run"] == "true",
            "before": {},
            "after": {},
            "message": "bounded test result",
            "finished_at": datetime.now(UTC).isoformat(),
        },
    }


def test_database_failure_requires_an_independently_healthy_api(tmp_path: Path) -> None:
    agent_id = staging_inventory()
    settings = Settings(
        environment="test",
        controller_signing_key_file=tmp_path / "controller-key.pem",
        runbook_directory=RUNBOOKS,
    )
    with SessionLocal() as db:
        agent = db.get(Agent, agent_id)
        assert agent

        reconcile_staging_heartbeat(
            db,
            agent=agent,
            payload=failed_database_probe_payload(api_ok=False),
            settings=settings,
        )
        application_incident = db.query(Incident).one()
        assert application_incident.fault_type == "application_health_failed"

        reconcile_staging_heartbeat(
            db,
            agent=agent,
            payload=failed_database_probe_payload(api_ok=True),
            settings=settings,
        )
        incidents = list(db.scalars(select(Incident).order_by(Incident.first_seen_at)).all())
        assert [incident.fault_type for incident in incidents] == [
            "application_health_failed",
            "database_corruption",
        ]
        assert application_incident.status == "resolved"


def test_staging_reconciler_runs_dry_run_then_one_actual_repair(tmp_path: Path) -> None:
    agent_id = staging_inventory()
    settings = Settings(
        environment="test",
        controller_signing_key_file=tmp_path / "controller-key.pem",
        runbook_directory=RUNBOOKS,
    )
    payload = exited_payload()
    with SessionLocal() as db:
        agent = db.get(Agent, agent_id)
        assert agent
        reconcile_staging_heartbeat(db, agent=agent, payload=payload, settings=settings)
        dry_task = db.scalars(
            db.query(AgentTask).statement.order_by(AgentTask.created_at)
        ).one()
        assert dry_task.action == "restart_container"
        assert dry_task.parameters["dry_run"] == "true"
        assert db.query(Incident).one().fault_type == "container_exited"

        record_agent_results(db, agent, [result_event(dry_task)])
        reconcile_staging_heartbeat(db, agent=agent, payload=payload, settings=settings)
        tasks = list(db.query(AgentTask).order_by(AgentTask.created_at))
        assert [task.action for task in tasks] == [
            "restart_container",
            "restart_container",
            "local_health_check",
        ]
        assert [task.parameters["dry_run"] for task in tasks] == ["true", "false", "false"]

        record_agent_results(db, agent, [result_event(tasks[1]), result_event(tasks[2])])
        reconcile_staging_heartbeat(db, agent=agent, payload=payload, settings=settings)
        assert db.query(AgentTask).count() == 3
        attempts = list(db.query(RepairAttempt).order_by(RepairAttempt.created_at))
        assert [attempt.success for attempt in attempts] == [True, True]


def test_persistent_fault_records_concurrency_cooldown_and_attempt_stop(tmp_path: Path) -> None:
    agent_id = staging_inventory()
    settings = Settings(
        environment="test",
        controller_signing_key_file=tmp_path / "controller-key.pem",
        runbook_directory=RUNBOOKS,
    )
    payload = exited_payload()
    with SessionLocal() as db:
        agent = db.get(Agent, agent_id)
        assert agent
        reconcile_staging_heartbeat(db, agent=agent, payload=payload, settings=settings)
        reconcile_staging_heartbeat(db, agent=agent, payload=payload, settings=settings)
        dry_task = db.scalars(select(AgentTask).order_by(AgentTask.created_at)).one()
        incident = db.query(Incident).one()
        assert any(
            "concurrent dispatch suppressed" in item["message"]
            for item in incident.timeline
        )

        record_agent_results(db, agent, [result_event(dry_task)])
        reconcile_staging_heartbeat(db, agent=agent, payload=payload, settings=settings)
        tasks = list(db.scalars(select(AgentTask).order_by(AgentTask.created_at)).all())
        assert len(tasks) == 3
        record_agent_results(
            db,
            agent,
            [result_event(tasks[1], success=True), result_event(tasks[2], success=False)],
        )
        reconcile_staging_heartbeat(db, agent=agent, payload=payload, settings=settings)

        assert db.query(AgentTask).count() == 3
        actual = list(
            db.scalars(
                select(RepairAttempt).where(
                    RepairAttempt.incident_id == incident.id,
                    RepairAttempt.dry_run.is_(False),
                )
            ).all()
        )
        assert len(actual) == 1
        messages = [str(item["message"]) for item in incident.timeline]
        assert any("repair cooldown is active" in message for message in messages)
        assert any("maximum repair attempts reached" in message for message in messages)
        blocked_reasons = [
            str(entry.details["reason"])
            for entry in db.scalars(
                select(AuditLog).where(
                    AuditLog.resource_id == incident.id,
                    AuditLog.action == "repair.plan",
                    AuditLog.outcome == "blocked",
                )
            ).all()
        ]
        assert any("concurrent repair" in reason for reason in blocked_reasons)
        assert any("cooldown" in reason for reason in blocked_reasons)
        assert any("maximum repair attempts" in reason for reason in blocked_reasons)


def test_staging_level2_runs_dry_run_before_waiting_for_switch(tmp_path: Path) -> None:
    agent_id = staging_inventory()
    settings = Settings(
        environment="test",
        controller_signing_key_file=tmp_path / "controller-key.pem",
        runbook_directory=RUNBOOKS,
    )
    payload = invalid_caddy_payload()
    with SessionLocal() as db:
        agent = db.get(Agent, agent_id)
        assert agent
        reconcile_staging_heartbeat(db, agent=agent, payload=payload, settings=settings)
        dry_task = db.scalars(
            db.query(AgentTask).statement.order_by(AgentTask.created_at)
        ).one()
        assert dry_task.action == "rollback_caddy_config"
        assert dry_task.parameters["dry_run"] == "true"

        record_agent_results(db, agent, [result_event(dry_task)])
        reconcile_staging_heartbeat(db, agent=agent, payload=payload, settings=settings)
        assert db.query(AgentTask).count() == 1
        incident = db.query(Incident).one()
        assert any("Level 2 switch" in item["message"] for item in incident.timeline)

        agent.host.labels = {
            **agent.host.labels,
            "guardian_level2_caddy": "true",
        }
        reconcile_staging_heartbeat(db, agent=agent, payload=payload, settings=settings)
        tasks = list(db.query(AgentTask).order_by(AgentTask.created_at))
        assert [task.action for task in tasks] == [
            "rollback_caddy_config",
            "rollback_caddy_config",
            "local_health_check",
        ]
        assert [task.parameters["dry_run"] for task in tasks] == [
            "true",
            "false",
            "false",
        ]
