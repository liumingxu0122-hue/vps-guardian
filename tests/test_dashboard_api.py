from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from guardian.config import get_settings
from guardian.dashboard import dashboard_bootstrap, invalidate_dashboard_cache
from guardian.database import SessionLocal, engine
from guardian.models import Approval, Host, Incident, MetricSnapshot, RecoveryPoint, User
from pytest import MonkeyPatch
from sqlalchemy import event
from sqlalchemy.exc import OperationalError


def seed_dashboard() -> None:
    with SessionLocal() as database:
        healthy = Host(name="hong-kong", address="192.0.2.10", status="healthy")
        offline = Host(name="us-west", address="192.0.2.20", status="offline")
        incident = Incident(
            title="Backend unavailable",
            fault_type="reverse_proxy_backend",
            severity=4,
            status="open",
        )
        database.add_all([healthy, offline, incident])
        database.flush()
        database.add_all(
            [
                MetricSnapshot(
                    host_id=healthy.id,
                    collected_at=datetime.now(UTC),
                    payload={
                        "load_1": 0.4,
                        "_services": [
                            {
                                "kind": "docker",
                                "summary": '{"Names":"api","State":"running"}',
                            }
                        ],
                    },
                ),
                Approval(
                    incident_id=incident.id,
                    action_name="restore_database",
                    risk_level=3,
                    status="pending",
                ),
                RecoveryPoint(
                    host_id=healthy.id,
                    service_name="api",
                    snapshot_id="abcdef123456",
                    manifest={"schema_version": 1},
                    checksum="a" * 64,
                    verified=True,
                    verified_at=datetime.now(UTC),
                    verification_version=1,
                    attestation_digest="b" * 64,
                ),
            ]
        )
        database.commit()


def test_dashboard_overview_services_and_latest_snapshot(
    client: TestClient, owner_token: str
) -> None:
    seed_dashboard()
    headers = {"Authorization": f"Bearer {owner_token}"}

    overview = client.get("/api/v1/overview", headers=headers)
    services = client.get("/api/v1/services", headers=headers)
    host_id = next(
        host["id"]
        for host in client.get("/api/v1/hosts", headers=headers).json()
        if host["name"] == "hong-kong"
    )
    latest = client.get(f"/api/v1/hosts/{host_id}/latest", headers=headers)

    assert overview.status_code == 200
    assert overview.json()["hosts"] == {
        "total": 0,
        "inventory_total": 2,
        "unregistered": 2,
        "disabled": 0,
        "healthy": 0,
        "degraded": 0,
        "offline": 0,
        "unknown": 0,
    }
    assert overview.json()["incidents"]["critical"] == 1
    assert overview.json()["pending_approvals"] == 1
    assert overview.json()["environment"]["production_status"] == "not_deployed"
    assert overview.json()["permissions"]["dangerous_actions"] == "approval_required"
    assert overview.json()["host_rows"][0]["name"] == "hong-kong"
    assert "address" not in str(overview.json()["host_rows"]).lower()
    assert overview.json()["resource_window"] == "24h"
    assert services.json()[0]["kind"] == "docker"
    assert latest.json()["payload"]["load_1"] == 0.4


def test_operations_overview_validates_window_and_host(
    client: TestClient, owner_token: str
) -> None:
    seed_dashboard()
    headers = {"Authorization": f"Bearer {owner_token}"}

    long_window = client.get("/api/v1/overview?window=30d", headers=headers)
    missing_host = client.get("/api/v1/overview?host_id=missing", headers=headers)

    assert long_window.status_code == 200
    assert long_window.json()["resource_window"] == "30d"
    assert missing_host.status_code == 404


def test_dashboard_bootstrap_is_lightweight_cacheable_and_measured(
    client: TestClient, owner_token: str
) -> None:
    seed_dashboard()
    invalidate_dashboard_cache()
    headers = {"Authorization": f"Bearer {owner_token}"}
    statements: list[str] = []

    def record_statement(
        _connection: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: object,
    ) -> None:
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", record_statement)
    try:
        response = client.get("/api/v1/dashboard/bootstrap", headers=headers)
    finally:
        event.remove(engine, "before_cursor_execute", record_statement)

    assert response.status_code == 200
    payload = response.json()
    assert payload["user"]["email"] == "owner@example.test"
    assert payload["agents"] == {
        "total": 0,
        "online": 0,
        "offline": 0,
        "updated_at": payload["generated_at"],
    }
    assert payload["backup"]["verified"] is True
    assert len(payload["attention"]) == 1
    assert "resource_series" not in payload
    assert "topology" not in payload
    assert "audit" not in payload
    assert "evidence" not in str(payload).lower()
    assert response.headers["etag"].startswith('"')
    assert "db;dur=" in response.headers["server-timing"]
    assert 'cache;desc="miss"' in response.headers["server-timing"]
    assert response.headers["cache-control"] == "private, max-age=0, must-revalidate"
    assert len(statements) <= 10

    not_modified = client.get(
        "/api/v1/dashboard/bootstrap",
        headers={**headers, "If-None-Match": response.headers["etag"]},
    )
    assert not_modified.status_code == 304
    assert not_modified.content == b""
    assert 'cache;desc="hit"' in not_modified.headers["server-timing"]


def test_dashboard_bootstrap_requires_authentication(client: TestClient) -> None:
    response = client.get("/api/v1/dashboard/bootstrap")

    assert response.status_code == 401


def test_dashboard_current_resources_is_small_and_uses_two_latest_samples(
    client: TestClient, owner_token: str
) -> None:
    seed_dashboard()
    headers = {"Authorization": f"Bearer {owner_token}"}
    with SessionLocal() as database:
        host = database.query(Host).filter(Host.name == "hong-kong").one()
        existing = (
            database.query(MetricSnapshot)
            .filter(MetricSnapshot.host_id == host.id)
            .one()
        )
        existing.collected_at = datetime(2026, 7, 21, 7, 59, tzinfo=UTC)
        existing.payload = {
            "cpu_percent": 30,
            "memory_total": 100,
            "memory_available": 50,
            "disk_total": 200,
            "disk_free": 80,
            "network_rx_bytes": 1_000,
            "network_tx_bytes": 2_000,
        }
        database.add(
            MetricSnapshot(
                host_id=host.id,
                collected_at=datetime(2026, 7, 21, 8, 0, tzinfo=UTC),
                payload={
                    "cpu_percent": 36,
                    "memory_total": 100,
                    "memory_available": 44,
                    "disk_total": 200,
                    "disk_free": 78,
                    "network_rx_bytes": 1_600,
                    "network_tx_bytes": 2_600,
                },
            )
        )
        database.commit()

    response = client.get("/api/v1/dashboard/resources/current", headers=headers)

    assert response.status_code == 200
    payload = response.json()
    assert payload["sampled_hosts"] == 1
    assert payload["current"] == {
        "cpu_percent": 36.0,
        "memory_percent": 56.0,
        "disk_percent": 61.0,
        "network_bytes_per_second": 20.0,
    }
    assert payload["delta"] == {
        "cpu_percent": 6.0,
        "memory_percent": 6.0,
        "disk_percent": 1.0,
    }
    assert payload["hosts"][0]["delta"] == {
        "cpu_percent": 6.0,
        "memory_percent": 6.0,
        "disk_percent": 1.0,
    }
    assert response.headers["cache-control"] == "private, max-age=15"
    assert "total;dur=" in response.headers["server-timing"]


def test_dashboard_current_resources_requires_authentication(client: TestClient) -> None:
    response = client.get("/api/v1/dashboard/resources/current")

    assert response.status_code == 401


def test_dashboard_bootstrap_degrades_noncritical_backup_section(
    monkeypatch: MonkeyPatch,
    owner_token: str,
) -> None:
    assert owner_token
    invalidate_dashboard_cache()
    with SessionLocal() as database:
        user = database.query(User).filter(User.email == "owner@example.test").one()

        def fail_backup_query(_statement: object) -> None:
            raise OperationalError("SELECT", {}, RuntimeError("simulated"))

        monkeypatch.setattr(database, "scalar", fail_backup_query)
        payload, _etag, _hit, _db_ms, _serialization_ms = dashboard_bootstrap(
            database,
            settings=get_settings(),
            user=user,
        )

    sections = payload["sections"]
    backup = payload["backup"]
    health = payload["global_health"]
    assert isinstance(sections, dict)
    assert isinstance(backup, dict)
    assert isinstance(health, dict)
    assert sections["backup"] == {"status": "degraded"}
    assert backup["status"] == "unknown"
    assert health["status"] in {"healthy", "warning", "critical"}


def test_public_settings_exposes_no_secret_values(
    client: TestClient, owner_token: str
) -> None:
    response = client.get(
        "/api/v1/settings/public", headers={"Authorization": f"Bearer {owner_token}"}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["features"]["arbitrary_shell"] is False
    serialized = str(payload).lower()
    assert "jwt_secret" not in serialized
    assert "enrollment_token" not in serialized
    assert "password_file" not in serialized
