from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pyotp
from fastapi.testclient import TestClient
from guardian.database import SessionLocal
from guardian.models import (
    Agent,
    AlertInstance,
    AlertRule,
    Host,
    Incident,
    MetricSnapshot,
    NotificationChannel,
    NotificationDelivery,
    ServiceCheck,
    ServiceCheckResult,
    User,
)


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_session_version_revokes_existing_bearer_token(
    client: TestClient, owner: User, owner_token: str
) -> None:
    with SessionLocal() as db:
        db.add(
            User(
                email="verified-recovery-owner@example.test",
                password_hash="not-used-in-this-test",
                role="owner",
                totp_enabled=True,
                recovery_codes_confirmed_at=datetime.now(UTC),
            )
        )
        db.commit()
    revoked = client.post(
        f"/api/v1/users/{owner.id}/revoke-sessions",
        headers=auth(owner_token),
    )
    assert revoked.status_code == 204
    assert client.get("/api/v1/auth/me", headers=auth(owner_token)).status_code == 401


def test_last_active_owner_cannot_be_removed_and_requires_reauthentication(
    client: TestClient, owner: User, owner_token: str
) -> None:
    wrong_password = client.patch(
        f"/api/v1/users/{owner.id}",
        headers=auth(owner_token),
        json={
            "role": "admin",
            "current_password": "incorrect-owner-password",
        },
    )
    assert wrong_password.status_code == 401

    last_owner = client.patch(
        f"/api/v1/users/{owner.id}",
        headers=auth(owner_token),
        json={
            "role": "admin",
            "current_password": "correct-horse-battery-staple",
        },
    )
    assert last_owner.status_code == 409


def test_owner_can_create_scoped_user_but_admin_cannot_create_users(
    client: TestClient, owner_token: str
) -> None:
    created = client.post(
        "/api/v1/users",
        headers=auth(owner_token),
        json={
            "email": "admin@example.test",
            "password": "another-correct-battery-staple",
            "role": "admin",
            "scopes": ["alerts:read", "hosts:read"],
        },
    )
    assert created.status_code == 201
    assert created.json()["scopes"] == ["alerts:read", "hosts:read"]

    login = client.post(
        "/api/v1/auth/login",
        json={
            "email": "admin@example.test",
            "password": "another-correct-battery-staple",
        },
    )
    denied = client.post(
        "/api/v1/users",
        headers=auth(login.json()["access_token"]),
        json={
            "email": "viewer@example.test",
            "password": "yet-another-secure-passphrase",
            "role": "viewer",
        },
    )
    assert denied.status_code == 403


def test_explicit_scopes_narrow_role_permissions(
    client: TestClient, owner_token: str
) -> None:
    created = client.post(
        "/api/v1/users",
        headers=auth(owner_token),
        json={
            "email": "scoped-viewer@example.test",
            "password": "scoped-viewer-secure-passphrase",
            "role": "viewer",
            "scopes": ["alerts:read"],
        },
    )
    assert created.status_code == 201
    login = client.post(
        "/api/v1/auth/login",
        json={
            "email": "scoped-viewer@example.test",
            "password": "scoped-viewer-secure-passphrase",
        },
    )
    token = login.json()["access_token"]
    blocked = client.get("/api/v1/alerts", headers=auth(token))
    assert blocked.status_code == 403
    changed = client.post(
        "/api/v1/auth/change-password",
        headers=auth(token),
        json={
            "current_password": "scoped-viewer-secure-passphrase",
            "new_password": "scoped-viewer-new-secure-passphrase",
            "retain_current_session": True,
        },
    )
    token = changed.json()["access_token"]
    setup = client.post(
        "/api/v1/auth/totp/setup",
        headers=auth(token),
        json={"current_password": "scoped-viewer-new-secure-passphrase"},
    )
    enabled = client.post(
        "/api/v1/auth/totp/enable",
        headers=auth(token),
        json={
            "current_password": "scoped-viewer-new-secure-passphrase",
            "totp_code": pyotp.TOTP(setup.json()["secret"]).now(),
        },
    )
    assert enabled.status_code == 200
    confirmed = client.post(
        "/api/v1/auth/recovery-codes/confirm",
        headers=auth(token),
        json={"confirmation": "I SAVED MY RECOVERY CODES"},
    )
    assert confirmed.status_code == 200
    assert client.get("/api/v1/alerts", headers=auth(token)).status_code == 200
    assert client.get("/api/v1/hosts", headers=auth(token)).status_code == 403


def test_stability_distinguishes_no_data_disabled_and_observed_hosts(
    client: TestClient, owner_token: str
) -> None:
    now = datetime.now(UTC)
    with SessionLocal() as db:
        observed = Host(
            name="observed-node",
            address="192.0.2.11",
            status="healthy",
            group_name="edge",
            location="hk",
            enrolled_at=now,
        )
        no_data = Host(name="new-node", address="192.0.2.12", group_name="edge")
        disabled = Host(
            name="disabled-node",
            address="192.0.2.13",
            group_name="archive",
            enabled=False,
        )
        db.add_all([observed, no_data, disabled])
        db.flush()
        db.add(
            Agent(
                host_id=observed.id,
                signing_public_key="AA" * 32,
                certificate_fingerprint="11" * 32,
                last_heartbeat_at=now,
            )
        )
        for minutes in (5, 15, 25, 35):
            db.add(
                MetricSnapshot(
                    host_id=observed.id,
                    collected_at=now - timedelta(minutes=minutes),
                    payload={"load_1": 0.1},
                )
            )
        check = ServiceCheck(
            name="observed-check",
            kind="http",
            host_id=observed.id,
            configuration={"target": "https://example.test/health"},
        )
        db.add(check)
        db.flush()
        db.add(
            ServiceCheckResult(
                check_id=check.id,
                status="ok",
                checked_at=now,
                latency_ms=12,
            )
        )
        db.commit()

    response = client.get("/api/v1/stability?window=1h", headers=auth(owner_token))
    assert response.status_code == 200
    rows = {row["host_name"]: row for row in response.json()["hosts"]}
    assert rows["observed-node"]["stability_score"] is not None
    assert 0 < rows["observed-node"]["confidence"] <= 1
    assert rows["new-node"]["status"] == "no_data"
    assert rows["new-node"]["stability_score"] is None
    assert rows["disabled-node"]["status"] == "excluded"
    assert response.json()["aggregates"]


def test_attention_and_global_health_use_actionable_server_rules(
    client: TestClient, owner_token: str
) -> None:
    now = datetime.now(UTC)
    with SessionLocal() as db:
        host = Host(
            name="offline-enrolled",
            address="192.0.2.21",
            status="offline",
            data_state="offline",
            enrolled_at=now - timedelta(days=1),
        )
        db.add(host)
        db.flush()
        db.add(
            Agent(
                host_id=host.id,
                signing_public_key="BB" * 32,
                certificate_fingerprint="22" * 32,
                last_heartbeat_at=now - timedelta(minutes=30),
            )
        )
        db.commit()

    response = client.get("/api/v1/attention", headers=auth(owner_token))
    assert response.status_code == 200
    assert response.json()["global_health"] == "critical"
    item = next(
        item for item in response.json()["items"] if item["type"] == "host_offline"
    )
    assert item["object"] == "offline-enrolled"
    assert item["suggested_action"]
    assert item["href"].startswith("/hosts/")


def test_incident_transition_requires_resolution_and_records_timeline(
    client: TestClient, owner_token: str
) -> None:
    with SessionLocal() as db:
        incident = Incident(title="API outage", fault_type="service_down")
        db.add(incident)
        db.commit()
        incident_id = incident.id

    invalid = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=auth(owner_token),
        json={"status": "resolved"},
    )
    assert invalid.status_code == 409

    acknowledged = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=auth(owner_token),
        json={"status": "acknowledged", "note": "triage started"},
    )
    assert acknowledged.status_code == 200
    assert acknowledged.json()["acknowledged_at"] is not None

    assert (
        client.patch(
            f"/api/v1/incidents/{incident_id}",
            headers=auth(owner_token),
            json={"status": "investigating", "note": "checking dependencies"},
        ).status_code
        == 200
    )
    resolved = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=auth(owner_token),
        json={
            "status": "resolved",
            "resolution_summary": "Recovered the bounded service dependency.",
            "postmortem": "Follow-up owner assigned.",
        },
    )
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved"
    assert len(resolved.json()["timeline"]) == 3


def test_alert_assignment_close_and_notification_dead_letter_retry(
    client: TestClient, owner: User, owner_token: str
) -> None:
    with SessionLocal() as db:
        rule = AlertRule(
            name="phase4-close",
            source_type="host_liveness",
            source_id="host-test",
        )
        db.add(rule)
        db.flush()
        alert = AlertInstance(
            rule_id=rule.id,
            fingerprint="d" * 64,
            state="resolved",
            summary="host recovered",
        )
        channel = NotificationChannel(
            name="discord-local",
            kind="discord",
            configuration={"endpoint_env": "GUARDIAN_TEST_DISCORD_URL"},
            retry_policy={"max_attempts": 2, "base_delay_seconds": 5},
        )
        db.add_all([alert, channel])
        db.flush()
        delivery = NotificationDelivery(
            channel_id=channel.id,
            alert_id=alert.id,
            event_type="resolved",
            status="dead_letter",
            attempt_count=2,
            next_attempt_at=datetime.now(UTC),
            error_summary="RuntimeError",
        )
        db.add(delivery)
        db.commit()
        alert_id = alert.id
        delivery_id = delivery.id

    closed = client.patch(
        f"/api/v1/alerts/{alert_id}",
        headers=auth(owner_token),
        json={"assigned_to": owner.id, "close": True, "note": "verified recovered"},
    )
    assert closed.status_code == 200
    assert closed.json()["state"] == "closed"
    assert closed.json()["assigned_to"] == owner.id

    retried = client.post(
        f"/api/v1/notification-deliveries/{delivery_id}/retry",
        headers=auth(owner_token),
    )
    assert retried.status_code == 200
    assert retried.json()["status"] == "pending"
    assert retried.json()["error_summary"] is None


def test_check_result_history_is_bounded_and_filterable(
    client: TestClient, owner_token: str
) -> None:
    now = datetime.now(UTC)
    with SessionLocal() as db:
        check = ServiceCheck(
            name="history-check",
            kind="http",
            configuration={"target": "https://example.test/health"},
        )
        other = ServiceCheck(
            name="other-check",
            kind="tcp",
            configuration={"target": "example.test", "port": 443},
        )
        db.add_all([check, other])
        db.flush()
        for index in range(3):
            db.add(
                ServiceCheckResult(
                    check_id=check.id,
                    status="ok" if index < 2 else "failed",
                    checked_at=now - timedelta(minutes=index),
                )
            )
        db.add(
            ServiceCheckResult(
                check_id=other.id,
                status="ok",
                checked_at=now,
            )
        )
        db.commit()
        check_id = check.id

    response = client.get(
        f"/api/v1/service-check-results?check_id={check_id}&limit=2",
        headers=auth(owner_token),
    )
    assert response.status_code == 200
    assert len(response.json()) == 2
    assert {item["check_id"] for item in response.json()} == {check_id}
    second_page = client.get(
        f"/api/v1/service-check-results?check_id={check_id}&limit=2&offset=2",
        headers=auth(owner_token),
    )
    assert second_page.status_code == 200
    assert len(second_page.json()) == 1
    assert second_page.json()[0]["id"] not in {
        item["id"] for item in response.json()
    }
