from __future__ import annotations

from datetime import UTC, timedelta
from pathlib import Path

import pytest
from guardian.config import Settings
from guardian.database import SessionLocal
from guardian.models import Agent, Approval, Host, Incident
from guardian.runbooks import RepairOrchestrator, load_runbook

RUNBOOKS = Path(__file__).parents[1] / "runbooks"


def test_all_repository_runbooks_validate() -> None:
    loaded = [load_runbook(path) for path in sorted(RUNBOOKS.glob("*.yaml"))]
    assert {runbook.name for runbook in loaded} == {
        "cleanup_allowlisted_cache",
        "reload_valid_caddy",
        "restart_exited_container",
        "restart_unhealthy_container",
        "restore_database",
        "rollback_caddy_config",
        "rollback_recent_service",
    }


def test_arbitrary_shell_action_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "malicious.yaml"
    path.write_text(
        """
name: malicious_shell
version: 1
risk_level: 1
conditions: [{type: fault_type, value: test}]
prechecks: []
actions:
  - type: shell
    parameters: {command: whoami}
postchecks: []
rollback_on_failure: false
cooldown: 10m
max_attempts: 1
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid runbook"):
        load_runbook(path)


def create_inventory():  # type: ignore[no-untyped-def]
    with SessionLocal() as db:
        host = Host(name="node-1", address="192.0.2.1")
        db.add(host)
        db.flush()
        agent = Agent(
            host_id=host.id,
            signing_public_key="A" * 44,
            certificate_fingerprint="AA:" * 31 + "AA",
        )
        incident = Incident(title="Container exited", fault_type="container_exited")
        db.add_all([agent, incident])
        db.commit()
        db.refresh(agent)
        db.refresh(incident)
        return agent.id, incident.id


def test_level1_dry_run_and_attempt_limit(tmp_path: Path) -> None:
    agent_id, incident_id = create_inventory()
    runbook = load_runbook(RUNBOOKS / "restart_exited_container.yaml")
    settings = Settings(environment="test", controller_signing_key_file=tmp_path / "key.pem")
    with SessionLocal() as db:
        incident = db.get(Incident, incident_id)
        agent = db.get(Agent, agent_id)
        assert incident and agent
        context = {
            "agent_online": "true",
            "container": "example-app",
            "health_url": "http://127.0.0.1:8080/health",
        }
        plan = RepairOrchestrator().plan(
            db,
            runbook=runbook,
            incident=incident,
            agent=agent,
            context=context,
            settings=settings,
            dry_run=True,
        )
        assert plan.requires_approval is False
        assert plan.dry_run is True
        assert plan.actions[0]["parameters"]["dry_run"] == "true"
        actual = RepairOrchestrator().plan(
            db,
            runbook=runbook,
            incident=incident,
            agent=agent,
            context=context,
            settings=settings,
            dry_run=False,
        )
        assert actual.requires_approval is False
        assert len(actual.task_ids) == 2
        blocked = RepairOrchestrator().plan(
            db,
            runbook=runbook,
            incident=incident,
            agent=agent,
            context=context,
            settings=settings,
            dry_run=False,
        )
        assert blocked.requires_approval is True
        assert "attempts" in blocked.reason


def test_level3_always_creates_approval(tmp_path: Path) -> None:
    agent_id, incident_id = create_inventory()
    runbook = load_runbook(RUNBOOKS / "restore_database.yaml")
    settings = Settings(environment="test", controller_signing_key_file=tmp_path / "key.pem")
    with SessionLocal() as db:
        incident = db.get(Incident, incident_id)
        agent = db.get(Agent, agent_id)
        assert incident and agent
        plan = RepairOrchestrator().plan(
            db,
            runbook=runbook,
            incident=incident,
            agent=agent,
            context={
                "verified_recovery_point": "true",
                "recovery_point": "snapshot-1",
                "restore_target": "temporary-instance",
            },
            settings=settings,
            dry_run=False,
        )
        assert plan.requires_approval is True
        assert plan.dry_run is True
        assert db.query(Approval).count() == 1
        approval = db.query(Approval).one()
        requested_at = approval.requested_at.replace(tzinfo=UTC)
        expires_at = approval.expires_at.replace(tzinfo=UTC)
        assert expires_at - requested_at == timedelta(minutes=settings.approval_ttl_minutes)


def test_level2_dry_run_is_allowed_but_execution_is_blocked_when_disabled(
    tmp_path: Path,
) -> None:
    agent_id, incident_id = create_inventory()
    runbook = load_runbook(RUNBOOKS / "rollback_recent_service.yaml")
    settings = Settings(environment="test", controller_signing_key_file=tmp_path / "key.pem")
    with SessionLocal() as db:
        incident = db.get(Incident, incident_id)
        agent = db.get(Agent, agent_id)
        assert incident and agent
        incident.fault_type = "post_deployment_regression"
        dry_run = RepairOrchestrator().plan(
            db,
            runbook=runbook,
            incident=incident,
            agent=agent,
            context={
                "verified_recovery_point": "true",
                "changed_seconds_ago": "60",
                "container": "example-app",
                "health_url": "http://127.0.0.1:8080/health",
            },
            settings=settings,
            dry_run=True,
            level2_enabled=False,
        )
        assert len(dry_run.task_ids) == 1
        assert dry_run.actions[0]["parameters"]["dry_run"] == "true"
        execution = RepairOrchestrator().plan(
            db,
            runbook=runbook,
            incident=incident,
            agent=agent,
            context={
                "verified_recovery_point": "true",
                "changed_seconds_ago": "60",
                "container": "example-app",
                "health_url": "http://127.0.0.1:8080/health",
            },
            settings=settings,
            dry_run=False,
            level2_enabled=False,
        )
        assert execution.actions == []
        assert "Level 2" in execution.reason
