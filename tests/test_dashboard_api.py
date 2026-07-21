from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from guardian.database import SessionLocal
from guardian.models import Approval, Host, Incident, MetricSnapshot, RecoveryPoint


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
        "total": 2,
        "healthy": 1,
        "degraded": 0,
        "offline": 1,
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

    invalid_window = client.get("/api/v1/overview?window=30d", headers=headers)
    missing_host = client.get("/api/v1/overview?host_id=missing", headers=headers)

    assert invalid_window.status_code == 422
    assert missing_host.status_code == 404


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
