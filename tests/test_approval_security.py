from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from guardian.database import SessionLocal
from guardian.models import AgentTask, Approval, AuditLog, Host, Incident, User
from sqlalchemy.exc import StatementError


def seed_approval(*, expires_at: datetime) -> str:
    with SessionLocal() as database:
        incident = Incident(
            title="Approval security gate",
            fault_type="database_corruption",
            severity=5,
            status="open",
        )
        database.add(incident)
        database.flush()
        approval = Approval(
            incident_id=incident.id,
            action_name="restore_database",
            risk_level=3,
            expires_at=expires_at,
        )
        database.add(approval)
        database.commit()
        return approval.id


def test_expired_approval_is_rejected_and_audited(client: TestClient, owner_token: str) -> None:
    approval_id = seed_approval(expires_at=datetime.now(UTC) - timedelta(seconds=1))

    response = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"decision": "approved", "confirmation": "approve expired request"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "approval expired"
    with SessionLocal() as database:
        approval = database.get(Approval, approval_id)
        assert approval and approval.status == "expired"
        assert approval.decided_at is not None
        audit = (
            database.query(AuditLog)
            .filter_by(action="approval.expired", resource_id=approval_id)
            .one()
        )
        assert audit.outcome == "rejected"


def test_listing_marks_stale_pending_approval_expired(client: TestClient, owner_token: str) -> None:
    approval_id = seed_approval(expires_at=datetime.now(UTC) - timedelta(seconds=1))

    response = client.get("/api/v1/approvals", headers={"Authorization": f"Bearer {owner_token}"})

    assert response.status_code == 200
    approval = next(item for item in response.json() if item["id"] == approval_id)
    assert approval["status"] == "expired"
    assert approval["expires_at"]
    assert approval["decided_at"]


def test_presentation_uses_explicit_fields_and_scoped_redacted_evidence(
    client: TestClient, owner_token: str, owner: User
) -> None:
    with SessionLocal() as database:
        host = Host(name="staging-node", address="192.0.2.80")
        incident = Incident(
            title="Approval presentation",
            fault_type="service_degraded",
            severity=4,
            status="open",
        )
        database.add_all([host, incident])
        database.flush()
        approval = Approval(
            incident_id=incident.id,
            action_name="service_restart",
            risk_level=2,
            requested_by=owner.id,
            target_host_id=host.id,
            parameters={
                "agent_id": "agent-1",
                "token": "must-not-leak",
                "actions": [
                    {
                        "type": "service_restart",
                        "parameters": {"target": "api.service", "dry_run": "true"},
                    }
                ],
            },
            impact={
                "service": "api",
                "scope": "staging",
                "dry_run_available": True,
                "secret": "must-not-leak",
            },
            rollback_plan=["restart the previous unit"],
        )
        database.add(approval)
        database.commit()
        approval_id = approval.id

    headers = {"Authorization": f"Bearer {owner_token}"}
    listing = client.get("/api/v1/approvals/presentation", headers=headers)
    assert listing.status_code == 200
    summary = next(item for item in listing.json() if item["id"] == approval_id)
    assert summary["target"] == {
        "host": "staging-node",
        "service": "api",
        "scope": "staging",
    }
    assert "parameters" not in summary
    assert "impact" not in summary
    assert "token" not in str(summary)

    detail = client.get(f"/api/v1/approvals/{approval_id}/presentation", headers=headers)
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["steps"][0] == {
        "order": 1,
        "action": "service_restart",
        "target": "api.service",
        "dry_run": True,
    }
    assert "parameters" not in payload
    assert "must-not-leak" not in str(payload)

    evidence = client.get(f"/api/v1/approvals/{approval_id}/evidence", headers=headers)
    assert evidence.status_code == 200
    assert evidence.json()["parameters"]["token"] == "[REDACTED]"
    assert evidence.json()["impact"]["secret"] == "[REDACTED]"


def test_request_changes_closes_without_creating_agent_tasks(
    client: TestClient, owner_token: str
) -> None:
    approval_id = seed_approval(expires_at=datetime.now(UTC) + timedelta(minutes=5))
    response = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"decision": "changes_requested", "confirmation": "provide impact evidence"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "changes_requested"


def test_high_risk_approval_requires_rollback_confirmation_and_reauthentication(
    client: TestClient, owner_token: str
) -> None:
    approval_id = seed_approval(expires_at=datetime.now(UTC) + timedelta(minutes=5))
    headers = {"Authorization": f"Bearer {owner_token}"}
    missing_rollback = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        headers=headers,
        json={"decision": "approved", "confirmation": "approve high-risk request"},
    )
    assert missing_rollback.status_code == 422
    assert missing_rollback.json()["detail"] == (
        "high-risk approval requires rollback confirmation"
    )

    missing_password = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        headers=headers,
        json={
            "decision": "approved",
            "confirmation": "approve high-risk request",
            "rollback_confirmed": True,
        },
    )
    assert missing_password.status_code == 422
    assert missing_password.json()["detail"] == ("high-risk approval requires reauthentication")


def test_conditional_approval_records_decision_without_dispatching_tasks(
    client: TestClient, owner_token: str
) -> None:
    approval_id = seed_approval(expires_at=datetime.now(UTC) + timedelta(minutes=5))
    response = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={
            "decision": "approved_with_conditions",
            "confirmation": "proceed only inside the approved maintenance window",
            "current_password": "correct-horse-battery-staple",
            "rollback_confirmed": True,
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "approved_with_conditions"
    with SessionLocal() as database:
        assert database.query(AgentTask).filter_by(approval_id=approval_id).count() == 0


def test_audit_records_cannot_be_changed_or_deleted_through_orm(
    client: TestClient, owner_token: str
) -> None:
    created = client.post(
        "/api/v1/hosts",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"name": "audit-immutable", "address": "192.0.2.240"},
    )
    assert created.status_code == 201

    with SessionLocal() as database:
        audit = database.query(AuditLog).filter_by(action="host.create").one()
        audit.outcome = "tampered"
        with pytest.raises((ValueError, StatementError), match="append-only"):
            database.commit()
        database.rollback()

        audit = database.query(AuditLog).filter_by(action="host.create").one()
        database.delete(audit)
        with pytest.raises((ValueError, StatementError), match="append-only"):
            database.commit()
        database.rollback()

    audit_id = client.get(
        "/api/v1/audit", headers={"Authorization": f"Bearer {owner_token}"}
    ).json()[0]["id"]
    for method in ("put", "patch", "delete"):
        response = client.request(
            method.upper(),
            f"/api/v1/audit/{audit_id}",
            headers={"Authorization": f"Bearer {owner_token}"},
            json={} if method != "delete" else None,
        )
        assert response.status_code in {404, 405}
