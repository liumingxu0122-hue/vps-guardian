from __future__ import annotations

from datetime import UTC, datetime, timedelta

from guardian.database import SessionLocal
from guardian.liveness import mark_stale_agents_offline
from guardian.models import Agent, AuditLog, Host


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
