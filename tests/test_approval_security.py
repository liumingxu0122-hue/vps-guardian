from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from guardian.database import SessionLocal
from guardian.models import Approval, AuditLog, Incident
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


def test_expired_approval_is_rejected_and_audited(
    client: TestClient, owner_token: str
) -> None:
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
        audit = database.query(AuditLog).filter_by(
            action="approval.expired", resource_id=approval_id
        ).one()
        assert audit.outcome == "rejected"


def test_listing_marks_stale_pending_approval_expired(
    client: TestClient, owner_token: str
) -> None:
    approval_id = seed_approval(expires_at=datetime.now(UTC) - timedelta(seconds=1))

    response = client.get(
        "/api/v1/approvals", headers={"Authorization": f"Bearer {owner_token}"}
    )

    assert response.status_code == 200
    approval = next(item for item in response.json() if item["id"] == approval_id)
    assert approval["status"] == "expired"
    assert approval["expires_at"]
    assert approval["decided_at"]


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
