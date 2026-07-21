from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from guardian.database import SessionLocal
from guardian.models import (
    Agent,
    AlertInstance,
    AlertRule,
    Host,
    MetricSnapshot,
    ServiceCheck,
    ServiceCheckResult,
)
from guardian.monitoring import (
    assigned_agent_checks,
    prune_monitoring_history,
    record_agent_check_results,
    run_due_controller_checks,
)
from sqlalchemy import func, select


async def test_controller_check_persists_result_and_drives_alert_hysteresis() -> None:
    calls = 0

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal calls
        calls += 1
        await reader.read(4096)
        writer.write(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    started = datetime.now(UTC)
    try:
        with SessionLocal() as db:
            check = ServiceCheck(
                name="local-integration",
                kind="http",
                configuration={
                    "target": f"http://127.0.0.1:{port}/health",
                    "expected_statuses": [200],
                    "allowed_networks": ["127.0.0.1/32"],
                },
                interval_seconds=15,
                failure_threshold=2,
            )
            db.add(check)
            db.flush()
            db.add(
                AlertRule(
                    name="local-integration-rule",
                    source_type="service_check",
                    source_id=check.id,
                    failure_threshold=2,
                    recovery_threshold=2,
                )
            )
            db.commit()
            first = await run_due_controller_checks(db, now=started)
            assert len(first) == 1 and first[0].status == "failed"
            second = await run_due_controller_checks(db, now=started + timedelta(seconds=16))
            assert len(second) == 1 and second[0].status == "failed"
            alert = db.scalar(select(AlertInstance))
            assert alert is not None and alert.state == "firing"
            assert calls == 2
    finally:
        server.close()
        await server.wait_closed()


def test_agent_check_assignment_and_result_are_bound_to_runner_identity() -> None:
    with SessionLocal() as db:
        host_a = Host(name="runner-a", address="192.0.2.1")
        host_b = Host(name="runner-b", address="192.0.2.2")
        db.add_all([host_a, host_b])
        db.flush()
        agent_a = Agent(
            host_id=host_a.id,
            signing_public_key="a",
            certificate_fingerprint="11" * 32,
        )
        agent_b = Agent(
            host_id=host_b.id,
            signing_public_key="b",
            certificate_fingerprint="22" * 32,
        )
        db.add_all([agent_a, agent_b])
        db.flush()
        check = ServiceCheck(
            name="remote-systemd",
            kind="systemd",
            host_id=host_a.id,
            runner_agent_id=agent_a.id,
            configuration={"unit": "example.service"},
        )
        db.add(check)
        db.flush()
        assert [item["id"] for item in assigned_agent_checks(db, agent_a)] == [check.id]
        assert assigned_agent_checks(db, agent_b) == []
        result = {
            "kind": "guardian_check_result",
            "check_id": check.id,
            "status": "ok",
            "latency_ms": 1,
            "details": {"state": "active"},
        }
        assert record_agent_check_results(db, agent=agent_b, services=[result]) == 0
        assert record_agent_check_results(db, agent=agent_a, services=[result]) == 1
        assert db.scalar(select(func.count(ServiceCheckResult.id))) == 1


def test_monitoring_retention_enforces_age_and_per_source_caps() -> None:
    now = datetime.now(UTC)
    with SessionLocal() as db:
        host = Host(name="retention", address="192.0.2.3")
        check = ServiceCheck(name="retention-check", kind="tcp", configuration={})
        db.add_all([host, check])
        db.flush()
        for offset in range(6):
            observed_at = (
                now - timedelta(days=10)
                if offset == 0
                else now - timedelta(minutes=offset)
            )
            db.add(
                MetricSnapshot(
                    host_id=host.id,
                    collected_at=observed_at,
                    payload={"cpu_percent": offset},
                )
            )
            db.add(
                ServiceCheckResult(
                    check_id=check.id,
                    status="ok",
                    checked_at=observed_at,
                    details={},
                )
            )
        db.flush()
        prune_monitoring_history(
            db,
            metric_retention_days=7,
            check_retention_days=7,
            max_metric_rows_per_host=3,
            max_results_per_check=4,
            now=now,
        )
        assert db.scalar(select(func.count(MetricSnapshot.id))) == 3
        assert db.scalar(select(func.count(ServiceCheckResult.id))) == 4
