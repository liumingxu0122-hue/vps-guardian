from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from guardian.database import SessionLocal
from guardian.models import (
    Agent,
    AgentTask,
    AlertInstance,
    AlertRule,
    Approval,
    AuditLog,
    EnrollmentToken,
    Host,
    Incident,
    User,
)
from sqlalchemy import func, select


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_host_lifecycle_and_one_time_agent_enrollment(
    client: TestClient, owner_token: str
) -> None:
    created = client.post(
        "/api/v1/hosts",
        headers=auth(owner_token),
        json={
            "name": "phase4b-node",
            "address": "192.0.2.88",
            "group_name": "edge",
            "tags": ["linux", "staging"],
        },
    )
    assert created.status_code == 201
    host_id = created.json()["id"]
    issued = client.post(
        f"/api/v1/hosts/{host_id}/enrollment-token",
        headers=auth(owner_token),
        json={"expires_in_minutes": 10},
    )
    assert issued.status_code == 201
    one_time_token = issued.json()["token"]
    assert one_time_token not in issued.json()["install_command"]
    assert "--enrollment-token-file" in issued.json()["install_command"]

    private_key = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(private_key.public_key().public_bytes_raw()).decode()
    payload = {
        "host": {"name": "phase4b-node", "address": "192.0.2.88"},
        "signing_public_key": public_key,
        "certificate_fingerprint": "AB:" * 31 + "AB",
        "version": "0.2.0-test",
    }
    enrolled = client.post(
        "/api/v1/agents/enroll",
        headers={"X-Enrollment-Token": one_time_token},
        json=payload,
    )
    assert enrolled.status_code == 200
    replay = client.post(
        "/api/v1/agents/enroll",
        headers={"X-Enrollment-Token": one_time_token},
        json={**payload, "certificate_fingerprint": "AC:" * 31 + "AC"},
    )
    assert replay.status_code == 401
    deletion = client.delete(f"/api/v1/hosts/{host_id}", headers=auth(owner_token))
    assert deletion.status_code == 409

    with SessionLocal() as db:
        token_hash = db.scalar(select(EnrollmentToken.token_hash))
        assert token_hash is not None and one_time_token not in token_hash
        audit_details = list(db.scalars(select(AuditLog.details)).all())
        assert all(one_time_token not in str(details) for details in audit_details)


def test_inactive_host_can_be_filtered_updated_and_deleted(
    client: TestClient, owner_token: str
) -> None:
    created = client.post(
        "/api/v1/hosts",
        headers=auth(owner_token),
        json={"name": "unused-node", "address": "192.0.2.89", "tags": ["unused"]},
    )
    host_id = created.json()["id"]
    disabled = client.patch(
        f"/api/v1/hosts/{host_id}",
        headers=auth(owner_token),
        json={"enabled": False, "group_name": "archive"},
    )
    assert disabled.status_code == 200
    assert disabled.json()["data_state"] == "no_data"
    filtered = client.get(
        "/api/v1/hosts?enabled=false&group=archive&tag=unused",
        headers=auth(owner_token),
    )
    assert [host["id"] for host in filtered.json()] == [host_id]
    assert client.delete(f"/api/v1/hosts/{host_id}", headers=auth(owner_token)).status_code == 204


def test_service_check_and_notification_configuration_reject_embedded_secrets(
    client: TestClient, owner_token: str
) -> None:
    unsafe = client.post(
        "/api/v1/service-checks",
        headers=auth(owner_token),
        json={
            "name": "unsafe-http",
            "kind": "http",
            "configuration": {
                "target": "https://example.test/health",
                "authorization": "Bearer forbidden",
            },
        },
    )
    assert unsafe.status_code == 422
    created = client.post(
        "/api/v1/service-checks",
        headers=auth(owner_token),
        json={
            "name": "public-api",
            "kind": "https",
            "configuration": {
                "target": "https://example.test/health",
                "expected_statuses": [200],
            },
        },
    )
    assert created.status_code == 201
    with SessionLocal() as db:
        assert db.scalar(select(func.count(AlertRule.id))) == 1

    embedded = client.post(
        "/api/v1/notification-channels",
        headers=auth(owner_token),
        json={
            "name": "unsafe-channel",
            "kind": "webhook",
            "configuration": {"endpoint": "https://example.test/hook?token=forbidden"},
        },
    )
    assert embedded.status_code == 422
    protected = client.post(
        "/api/v1/notification-channels",
        headers=auth(owner_token),
        json={
            "name": "mock-channel",
            "kind": "webhook",
            "configuration": {"endpoint_env": "GUARDIAN_TEST_WEBHOOK_URL"},
        },
    )
    assert protected.status_code == 201


def test_alert_acknowledgement_and_high_risk_self_approval_gate(
    client: TestClient, owner_token: str
) -> None:
    with SessionLocal() as db:
        owner = db.scalar(select(User).where(User.email == "owner@example.test"))
        assert owner is not None
        rule = AlertRule(
            name="phase4b-alert",
            source_type="host_liveness",
            source_id="host-test",
        )
        db.add(rule)
        db.flush()
        alert = AlertInstance(
            rule_id=rule.id,
            fingerprint="a" * 64,
            state="firing",
            summary="offline",
        )
        incident = Incident(title="repair", fault_type="service_down")
        db.add_all([alert, incident])
        db.flush()
        approval = Approval(
            incident_id=incident.id,
            action_name="restart_systemd",
            risk_level=2,
            requested_by=owner.id,
            target_host_id=None,
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        db.add(approval)
        db.commit()
        alert_id = alert.id
        approval_id = approval.id

    acknowledged = client.post(
        f"/api/v1/alerts/{alert_id}/acknowledge", headers=auth(owner_token)
    )
    assert acknowledged.status_code == 200
    assert acknowledged.json()["state"] == "acknowledged"
    self_approval = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        headers=auth(owner_token),
        json={"decision": "approved", "confirmation": "approve own request"},
    )
    assert self_approval.status_code == 403


def test_approved_plan_dispatches_signed_task_with_approval_metadata(
    client: TestClient, owner_token: str
) -> None:
    with SessionLocal() as db:
        owner = db.scalar(select(User).where(User.email == "owner@example.test"))
        assert owner is not None
        host = Host(name="approval-target", address="192.0.2.99")
        db.add(host)
        db.flush()
        agent = Agent(
            host_id=host.id,
            signing_public_key="AA" * 32,
            certificate_fingerprint="12" * 32,
        )
        incident = Incident(title="restart", fault_type="service_down")
        db.add_all([agent, incident])
        db.flush()
        approval = Approval(
            incident_id=incident.id,
            action_name="restart_systemd",
            risk_level=1,
            parameters={
                "agent_id": agent.id,
                "actions": [
                    {"type": "restart_systemd", "parameters": {"target": "guardian"}}
                ],
            },
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            requested_by=None,
            target_host_id=host.id,
        )
        db.add(approval)
        db.commit()
        approval_id = approval.id
        agent_id = agent.id

    response = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        headers=auth(owner_token),
        json={"decision": "approved", "confirmation": "approve plan"},
    )
    assert response.status_code == 200
    with SessionLocal() as db:
        task = db.scalar(select(AgentTask).where(AgentTask.agent_id == agent_id))
        assert task is not None
        assert task.approval_id == approval_id
        assert task.approver_id is not None
        assert task.target_host_id is not None
        assert task.parameters["dry_run"] == "false"
