from __future__ import annotations

from datetime import UTC, datetime, timedelta

from guardian.database import SessionLocal
from guardian.liveness import mark_stale_agents_offline
from guardian.models import Agent, AlertInstance, AuditLog, Host


def test_stale_agent_transitions_offline_once() -> None:
    observed_at = datetime(2026, 7, 16, 23, 0, tzinfo=UTC)
    with SessionLocal() as database:
        host = Host(name="stale-agent", address="192.0.2.40", status="healthy")
        database.add(host)
        database.flush()
        database.add(
            Agent(
                host_id=host.id,
                signing_public_key="A" * 44,
                certificate_fingerprint="AB" * 32,
                last_heartbeat_at=observed_at - timedelta(seconds=91),
            )
        )
        database.commit()

        assert mark_stale_agents_offline(
            database, offline_after_seconds=90, now=observed_at
        ) == [host.id]
        assert host.status == "offline"
        assert database.query(AuditLog).filter(AuditLog.action == "host.offline").count() == 1
        assert mark_stale_agents_offline(
            database, offline_after_seconds=90, now=observed_at
        ) == []
        assert database.query(AuditLog).filter(AuditLog.action == "host.offline").count() == 1


def test_agent_transitions_through_stale_before_offline() -> None:
    observed_at = datetime(2026, 7, 16, 23, 0, tzinfo=UTC)
    with SessionLocal() as database:
        host = Host(
            name="aging-agent",
            address="192.0.2.41",
            status="healthy",
            data_state="normal",
        )
        database.add(host)
        database.flush()
        database.add(
            Agent(
                host_id=host.id,
                signing_public_key="A" * 44,
                certificate_fingerprint="CD" * 32,
                last_heartbeat_at=observed_at - timedelta(seconds=60),
            )
        )
        database.commit()
        assert mark_stale_agents_offline(
            database, offline_after_seconds=90, now=observed_at
        ) == []
        assert host.status == "degraded"
        assert host.data_state == "stale"
        assert database.query(AuditLog).filter(AuditLog.action == "host.stale").count() == 1


def test_liveness_alert_counts_survive_cycles_and_require_recovery_hysteresis() -> None:
    heartbeat_at = datetime(2026, 7, 16, 23, 0, tzinfo=UTC)
    with SessionLocal() as database:
        host = Host(
            name="alerting-agent",
            address="192.0.2.42",
            status="healthy",
            data_state="normal",
        )
        database.add(host)
        database.flush()
        agent = Agent(
            host_id=host.id,
            signing_public_key="A" * 44,
            certificate_fingerprint="EF" * 32,
            last_heartbeat_at=heartbeat_at,
        )
        database.add(agent)
        database.commit()
        for seconds in (50, 80, 100):
            mark_stale_agents_offline(
                database,
                offline_after_seconds=90,
                now=heartbeat_at + timedelta(seconds=seconds),
            )
        alert = database.query(AlertInstance).one()
        assert alert.state == "firing"
        assert alert.consecutive_failures == 3

        agent.last_heartbeat_at = heartbeat_at + timedelta(seconds=100)
        mark_stale_agents_offline(
            database, offline_after_seconds=90, now=heartbeat_at + timedelta(seconds=101)
        )
        assert alert.state == "firing"
        mark_stale_agents_offline(
            database, offline_after_seconds=90, now=heartbeat_at + timedelta(seconds=102)
        )
        assert alert.state == "resolved"
