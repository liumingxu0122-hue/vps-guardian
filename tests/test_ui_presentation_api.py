from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from guardian.database import SessionLocal
from guardian.models import Agent, AuditLog, Host, User
from guardian.security import hash_password


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_host_presentation_is_bounded_explicit_and_hides_internal_tags(
    client: TestClient, owner_token: str
) -> None:
    now = datetime.now(UTC)
    with SessionLocal() as db:
        host = Host(
            name="edge-hk-1",
            address="192.0.2.40",
            location="hk",
            group_name="edge",
            status="healthy",
            data_state="normal",
            tags=["public-web", "komari-import", "pending-enrollment"],
            labels={"purpose": "customer-edge", "private_note": "must-not-leak"},
            last_seen_at=now,
            enrolled_at=now,
        )
        db.add(host)
        db.flush()
        db.add(
            Agent(
                host_id=host.id,
                signing_public_key="AA" * 32,
                certificate_fingerprint="12" * 32,
                last_heartbeat_at=now - timedelta(seconds=30),
                version="0.4.0",
            )
        )
        db.commit()

    response = client.get("/api/v1/hosts/presentation", headers=auth(owner_token))
    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 1
    assert set(payload[0]) == {
        "id",
        "name",
        "primary_address",
        "os_name",
        "region",
        "group",
        "provider",
        "purpose",
        "display_tags",
        "health",
        "data_state",
        "enabled",
        "management",
        "agent_state",
        "agent_version",
        "last_heartbeat_at",
        "last_seen_at",
        "enrolled_at",
        "data_reason",
        "resource_summary",
        "technical_evidence_available",
    }
    assert payload[0]["display_tags"] == ["public-web"]
    assert payload[0]["management"] == "guardian_and_komari"
    assert payload[0]["agent_state"] == "online"
    assert "labels" not in payload[0]


def test_audit_presentation_keeps_raw_evidence_out_of_the_index(
    client: TestClient, owner: User, owner_token: str
) -> None:
    with SessionLocal() as db:
        host = Host(name="edge-hk-2", address="192.0.2.41")
        db.add(host)
        db.flush()
        entry = AuditLog(
            actor_id=owner.id,
            action="host.update",
            resource_type="host",
            resource_id=host.id,
            outcome="success",
            details={
                "request_id": "request-123",
                "password": "must-not-leak",
                "safe_change": "enabled",
            },
            source_ip="172.19.0.4",
        )
        db.add(entry)
        db.commit()
        entry_id = entry.id

    index = client.get("/api/v1/audit/presentation", headers=auth(owner_token))
    assert index.status_code == 200
    item = next(value for value in index.json() if value["event_id"] == entry_id)
    assert item["display_action"] == "Updated host"
    assert item["resource_display"] == "edge-hk-2"
    assert item["actor_display"] == owner.email
    assert item["source_display"] == "Private network client"
    assert item["request_id"] == "request-123"
    assert "details" not in item
    assert "source_ip" not in item
    assert "resource_id" not in item
    assert "actor_id" not in item
    assert "changes" not in item

    evidence = client.get(
        f"/api/v1/audit/{entry_id}/evidence",
        headers=auth(owner_token),
    )
    assert evidence.status_code == 200
    assert evidence.json()["changes"]["password"] == "[REDACTED]"
    assert evidence.json()["changes"]["safe_change"] == "enabled"

    exported = client.get(
        "/api/v1/audit/export?format=csv&resource_type=host&query=edge-hk-2",
        headers=auth(owner_token),
    )
    assert exported.status_code == 200
    assert "Updated host" in exported.text
    assert "edge-hk-2" in exported.text
    assert "must-not-leak" not in exported.text
    assert "172.19.0.4" not in exported.text
    with SessionLocal() as db:
        assert db.query(AuditLog).filter(AuditLog.action == "audit.export").count() == 1


def test_presentation_endpoints_preserve_role_boundaries(
    client: TestClient, owner_token: str
) -> None:
    with SessionLocal() as db:
        db.add(
            User(
                email="viewer-presentation@example.test",
                password_hash=hash_password("viewer-presentation-secure-passphrase"),
                role="viewer",
            )
        )
        db.commit()
    login = client.post(
        "/api/v1/auth/login",
        json={
            "email": "viewer-presentation@example.test",
            "password": "viewer-presentation-secure-passphrase",
        },
    )
    viewer_token = login.json()["access_token"]
    assert (
        client.get("/api/v1/hosts/presentation", headers=auth(viewer_token)).status_code
        == 200
    )
    assert (
        client.get("/api/v1/audit/presentation", headers=auth(viewer_token)).status_code
        == 403
    )


def test_host_batch_update_preserves_internal_tags_and_is_audited(
    client: TestClient, owner_token: str
) -> None:
    with SessionLocal() as db:
        host = Host(
            name="batch-edge",
            address="192.0.2.60",
            tags=["komari-import", "existing"],
        )
        db.add(host)
        db.commit()
        host_id = host.id

    updated = client.patch(
        "/api/v1/hosts/batch",
        headers=auth(owner_token),
        json={
            "host_ids": [host_id],
            "enabled": False,
            "group_name": "archive",
            "add_tags": ["reviewed"],
        },
    )
    assert updated.status_code == 200
    assert updated.json() == {"updated": 1}
    with SessionLocal() as db:
        host = db.get(Host, host_id)
        assert host is not None
        assert host.enabled is False
        assert host.group_name == "archive"
        assert host.tags == ["existing", "komari-import", "reviewed"]
        audit = db.query(AuditLog).filter(AuditLog.action == "host.batch_update").one()
        assert audit.details["host_count"] == 1
