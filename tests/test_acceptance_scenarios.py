from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from guardian.backup import (
    CommandResult,
    RecoveryPlanner,
    ResticAdapter,
    ResticConfig,
)
from guardian.config import Settings
from guardian.database import SessionLocal
from guardian.diagnostics import DiagnosticContext, DiagnosticEngine
from guardian.models import Agent, AgentTask, Approval, Host, Incident
from guardian.reports import incident_document, report_json
from guardian.runbooks import RepairOrchestrator, load_runbook

RUNBOOKS = Path(__file__).parents[1] / "runbooks"


def inventory(fault_type: str) -> tuple[str, str]:
    with SessionLocal() as database:
        host = Host(name="acceptance-node", address="192.0.2.100")
        database.add(host)
        database.flush()
        agent = Agent(
            host_id=host.id,
            signing_public_key="A" * 44,
            certificate_fingerprint="AA" * 32,
        )
        incident = Incident(title="Acceptance incident", fault_type=fault_type)
        database.add_all([agent, incident])
        database.commit()
        return agent.id, incident.id


def test_scenario_1_container_exit_restart_once_verify_and_report(tmp_path: Path) -> None:
    diagnosis = DiagnosticEngine().diagnose(
        DiagnosticContext(
            host_id="acceptance-node",
            service="api",
            agent_online=True,
            container_state="exited",
            logs=["container exited with status 1"],
        )
    )[0]
    agent_id, incident_id = inventory(diagnosis.fault_type)
    settings = Settings(environment="test", controller_signing_key_file=tmp_path / "key.pem")
    with SessionLocal() as database:
        agent = database.get(Agent, agent_id)
        incident = database.get(Incident, incident_id)
        assert agent and incident
        plan = RepairOrchestrator().plan(
            database,
            runbook=load_runbook(RUNBOOKS / "restart_exited_container.yaml"),
            incident=incident,
            agent=agent,
            context={
                "agent_online": "true",
                "container": "api",
                "health_url": "http://127.0.0.1:8080/health",
            },
            settings=settings,
            dry_run=False,
        )
        assert plan.requires_approval is False
        assert [
            task.action for task in database.query(AgentTask).order_by(AgentTask.created_at)
        ] == ["restart_container", "local_health_check"]
    document = incident_document(
        incident_id=incident_id,
        title="Container exited",
        diagnosis=diagnosis,
        timeline=[{"at": datetime.now(UTC).isoformat(), "message": "detected by Agent"}],
        repairs=[{"action": "restart_container", "attempt": 1}],
    )
    assert "container_exited" in report_json(document)
    assert "local and external health checks pass" in diagnosis.verification


def test_scenario_2_caddy_validation_precedes_reload_and_health_check() -> None:
    runbook = load_runbook(RUNBOOKS / "reload_valid_caddy.yaml")
    rollback = load_runbook(RUNBOOKS / "rollback_caddy_config.yaml")
    assert [step["type"] for step in runbook.data["prechecks"]] == ["validate_caddy"]
    assert [step["type"] for step in runbook.data["actions"]] == ["reload_caddy"]
    assert [step["type"] for step in runbook.data["postchecks"]] == ["local_health_check"]
    assert runbook.data["rollback_on_failure"] is True
    assert rollback.risk_level == 2
    assert [step["type"] for step in rollback.data["actions"]] == [
        "rollback_caddy_config"
    ]
    assert {condition["type"] for condition in rollback.data["conditions"]} >= {
        "verified_recovery_point",
        "service_level2_enabled",
    }


def test_scenario_3_https_502_is_backend_not_dns() -> None:
    diagnosis = DiagnosticEngine().diagnose(
        DiagnosticContext(
            host_id="node",
            service="api",
            tcp_443_ok=True,
            tls_ok=True,
            http_status=502,
        )
    )[0]
    assert diagnosis.fault_type == "reverse_proxy_backend_unavailable"
    assert "DNS failure" in diagnosis.excluded_causes


def test_scenario_4_local_service_healthy_external_failure_never_restarts() -> None:
    diagnosis = DiagnosticEngine().diagnose(
        DiagnosticContext(
            host_id="node",
            service="api",
            agent_online=True,
            local_app_healthy=True,
            external_https_ok=False,
        )
    )[0]
    assert diagnosis.fault_type == "external_entrance_failure"
    assert diagnosis.auto_repair_allowed is False
    assert "Do not restart" in diagnosis.risk


def test_scenario_5_storage_pressure_only_uses_allowlisted_cache_action() -> None:
    diagnosis = DiagnosticEngine().diagnose(
        DiagnosticContext(
            host_id="node",
            disk_percent=96,
            inode_percent=20,
            disk_usage_sources=[
                {"path": "/var/cache/vps-guardian-agent", "bytes": 1000},
                {"path": "/var/lib/postgresql", "bytes": 900},
            ],
        )
    )[0]
    runbook = load_runbook(RUNBOOKS / "cleanup_allowlisted_cache.yaml")
    assert diagnosis.fault_type == "storage_pressure"
    assert [action["type"] for action in runbook.data["actions"]] == ["cleanup_cache"]
    assert "database" in " ".join(diagnosis.recommendations).lower()


def test_scenario_6_database_corruption_stops_for_level3_approval(tmp_path: Path) -> None:
    diagnosis = DiagnosticEngine().diagnose(
        DiagnosticContext(host_id="node", service="database", database_error="malformed page")
    )[0]
    agent_id, incident_id = inventory(diagnosis.fault_type)
    settings = Settings(environment="test", controller_signing_key_file=tmp_path / "key.pem")
    with SessionLocal() as database:
        agent = database.get(Agent, agent_id)
        incident = database.get(Incident, incident_id)
        assert agent and incident
        plan = RepairOrchestrator().plan(
            database,
            runbook=load_runbook(RUNBOOKS / "restore_database.yaml"),
            incident=incident,
            agent=agent,
            context={
                "verified_recovery_point": "true",
                "recovery_point": "abcdef123456",
                "restore_target": "temporary-instance",
            },
            settings=settings,
            dry_run=False,
        )
        assert plan.requires_approval is True and plan.dry_run is True
        assert database.query(Approval).count() == 1
        assert database.query(AgentTask).count() == 0


class RecoveryExecutor:
    snapshot_id = "b" * 64

    def __init__(self, manifest: dict[str, object]) -> None:
        self.manifest = manifest
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv, *, env=None, cwd=None, timeout=900):  # type: ignore[no-untyped-def]
        del env, cwd, timeout
        arguments = tuple(argv)
        self.calls.append(arguments)
        if "snapshots" in arguments:
            return CommandResult(
                0,
                json.dumps(
                    [
                        {
                            "id": self.snapshot_id,
                            "short_id": self.snapshot_id[:8],
                            "hostname": "controller",
                            "time": "2026-07-15T00:00:00Z",
                            "tags": [
                                "guardian",
                                "guardian-host:controller",
                                "guardian-service:controller",
                                "guardian-manifest:"
                                + hashlib.sha256(
                                    json.dumps(self.manifest).encode("utf-8")
                                ).hexdigest(),
                            ],
                        }
                    ]
                ),
            )
        if "dump" in arguments:
            return CommandResult(0, json.dumps(self.manifest))
        if "restore" in arguments and "--dry-run" not in arguments:
            target = Path(arguments[arguments.index("--target") + 1])
            (target / "database").mkdir(parents=True)
            (target / "database" / "postgresql.dump").write_bytes(b"x" * 512)
            (target / "manifest.json").write_text(
                json.dumps(self.manifest), encoding="utf-8"
            )
        return CommandResult(0)


def test_scenario_8_controller_database_loss_uses_independent_recovery(tmp_path: Path) -> None:
    password_file = tmp_path / "password"
    password_file.write_text("secret\n", encoding="utf-8")
    dump_payload = b"x" * 512
    manifest = {
        "schema_version": 1,
        "host": "controller",
        "service": "controller",
        "artifacts": [
            {
                "path": "database/postgresql.dump",
                "size": len(dump_payload),
                "sha256": hashlib.sha256(dump_payload).hexdigest(),
            }
        ],
        "recovery_metadata": {
            "source_commit": "d" * 40,
            "alembic_revisions": ["0004_agent_dual_identity"],
            "configuration_references": ["controller environment"],
            "public_certificate_references": ["agent CA certificate"],
            "external_secret_references": ["database credential"],
            "contains_secret_values": False,
        },
    }
    executor = RecoveryExecutor(manifest)
    planner = RecoveryPlanner(
        ResticAdapter(
            ResticConfig(repository=str(tmp_path / "repo"), password_file=password_file),
            executor,
        )
    )
    assert planner.list_recovery_points()[0].host == "controller"
    assert planner.impact(RecoveryExecutor.snapshot_id).artifact_count == 1
    plan = planner.plan(
        RecoveryExecutor.snapshot_id,
        tmp_path / "new-controller",
        scope="controller",
    )
    planner.restore(
        RecoveryExecutor.snapshot_id,
        tmp_path / "new-controller",
        execute=True,
        approval_id="approval-1",
        plan_digest=plan.digest,
        confirmation=plan.confirmation,
        scope="controller",
    )
    assert any("restore" in call for call in executor.calls)


def test_scenario_9_incident_credentials_are_redacted() -> None:
    diagnosis = DiagnosticEngine().diagnose(
        DiagnosticContext(
            host_id="node",
            systemd_state="failed",
            logs=["Authorization: Bearer highly-sensitive-token"],
        )
    )[0]
    report = report_json(
        incident_document(
            incident_id="incident-9",
            title="Secret-bearing log",
            diagnosis=diagnosis,
            timeline=[{"at": "now", "message": "Cookie: session=secret-cookie"}],
            repairs=[],
        )
    )
    assert "highly-sensitive-token" not in report
    assert "secret-cookie" not in report
    assert "[REDACTED]" in report


def test_scenario_10_repeated_repair_stops_and_escalates(tmp_path: Path) -> None:
    agent_id, incident_id = inventory("container_exited")
    settings = Settings(environment="test", controller_signing_key_file=tmp_path / "key.pem")
    context = {
        "agent_online": "true",
        "container": "api",
        "health_url": "http://127.0.0.1:8080/health",
    }
    with SessionLocal() as database:
        agent = database.get(Agent, agent_id)
        incident = database.get(Incident, incident_id)
        assert agent and incident
        runbook = load_runbook(RUNBOOKS / "restart_exited_container.yaml")
        first = RepairOrchestrator().plan(
            database,
            runbook=runbook,
            incident=incident,
            agent=agent,
            context=context,
            settings=settings,
            dry_run=True,
        )
        second = RepairOrchestrator().plan(
            database,
            runbook=runbook,
            incident=incident,
            agent=agent,
            context=context,
            settings=settings,
            dry_run=False,
        )
        third = RepairOrchestrator().plan(
            database,
            runbook=runbook,
            incident=incident,
            agent=agent,
            context=context,
            settings=settings,
            dry_run=False,
        )
        assert first.actions
        assert second.actions
        assert not third.actions
        assert third.requires_approval is True
        assert "escalated" in third.reason
