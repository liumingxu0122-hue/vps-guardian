from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from guardian.database import SessionLocal
from guardian.enrollment import issue_enrollment_token
from guardian.models import (
    Agent,
    AgentIdentity,
    AgentIdentityState,
    AgentMaintenanceSession,
    AgentTask,
    Approval,
    ApprovalStatus,
    AuditLog,
    Host,
    Incident,
    Role,
    User,
)
from guardian.security import hash_password


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def login(client: TestClient, email: str) -> str:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 200
    return str(response.json()["access_token"])


def managed_host() -> tuple[str, str, str]:
    with SessionLocal() as db:
        host = Host(
            name="maintenance-node",
            address="192.0.2.44",
            enabled=True,
            enrolled_at=datetime.now(UTC),
        )
        db.add(host)
        db.flush()
        agent = Agent(
            host_id=host.id,
            signing_public_key="test-signing-key",
            certificate_fingerprint="A" * 64,
            certificate_serial="A044",
            identity_version=1,
            last_heartbeat_at=datetime.now(UTC),
        )
        db.add(agent)
        db.flush()
        identity = AgentIdentity(
            agent_id=agent.id,
            generation=1,
            state=AgentIdentityState.active.value,
            signing_public_key=agent.signing_public_key,
            certificate_fingerprint=agent.certificate_fingerprint,
            certificate_serial=agent.certificate_serial,
            activated_at=datetime.now(UTC),
        )
        db.add(identity)
        db.commit()
        return host.id, agent.id, identity.id


def extract_credential(command: str) -> str:
    match = re.search(r"printf %s ([A-Za-z0-9._~-]{32,512}) ", command)
    assert match
    return match.group(1)


def issue(
    client: TestClient,
    owner_token: str,
    host_id: str,
    kind: str = "repair",
    **extra: object,
) -> dict[str, object]:
    response = client.post(
        f"/api/v1/hosts/{host_id}/maintenance-sessions",
        headers=auth(owner_token),
        json={"kind": kind, **extra},
    )
    assert response.status_code == 201, response.text
    return response.json()


def start(
    client: TestClient, command: str, kind: str
) -> tuple[dict[str, object], dict[str, str]]:
    token = extract_credential(command)
    response = client.post(
        "/api/v1/agents/maintenance/start",
        headers={"X-Maintenance-Token": token},
        json={"kind": kind},
    )
    assert response.status_code == 200, response.text
    return response.json(), {"X-Maintenance-Progress": response.json()["progress_token"]}


def progress(
    client: TestClient, headers: dict[str, str], kind: str, status: str
) -> None:
    response = client.post(
        "/api/v1/agents/maintenance/progress",
        headers=headers,
        json={"kind": kind, "status": status},
    )
    assert response.status_code == 202, response.text


def test_repair_is_one_time_hash_only_monotonic_and_heartbeat_gated(
    client: TestClient, owner_token: str
) -> None:
    host_id, agent_id, _ = managed_host()
    issued = issue(client, owner_token, host_id)
    command = str(issued["command"])
    token = extract_credential(command)
    with SessionLocal() as db:
        stored = db.get(AgentMaintenanceSession, str(issued["id"]))
        assert stored is not None
        assert token not in stored.token_hash
        assert stored.expires_at <= stored.created_at + timedelta(minutes=10)

    wrong_certificate = client.post(
        "/api/v1/agents/maintenance/start",
        headers={
            "X-Maintenance-Token": token,
            "X-Client-Cert-Fingerprint": "B" * 64,
        },
        json={"kind": "repair"},
    )
    assert wrong_certificate.status_code == 401
    start_payload, progress_headers = start(client, command, "repair")
    replay = client.post(
        "/api/v1/agents/maintenance/start",
        headers={"X-Maintenance-Token": token},
        json={"kind": "repair"},
    )
    assert replay.status_code == 401
    progress(client, progress_headers, "repair", "artifact_verified")
    progress(client, progress_headers, "repair", "service_stopped")
    progress(client, progress_headers, "repair", "service_started")
    early = client.post(
        "/api/v1/agents/maintenance/progress",
        headers=progress_headers,
        json={"kind": "repair", "status": "heartbeat_verified"},
    )
    assert early.status_code == 409
    with SessionLocal() as db:
        agent = db.get(Agent, agent_id)
        assert agent is not None
        agent.last_heartbeat_at = datetime.now(UTC) + timedelta(seconds=1)
        db.commit()
    progress(client, progress_headers, "repair", "heartbeat_verified")
    progress(client, progress_headers, "repair", "completed")
    latest = client.get(
        f"/api/v1/hosts/{host_id}/maintenance-sessions/latest",
        headers=auth(owner_token),
    )
    assert latest.status_code == 200
    assert latest.json()["status"] == "completed"
    assert token not in latest.text
    assert str(start_payload["progress_token"]) not in latest.text


def test_credential_types_and_rbac_are_isolated(
    client: TestClient, owner: User, owner_token: str
) -> None:
    host_id, _, _ = managed_host()
    with SessionLocal() as db:
        db.add_all(
            [
                User(
                    email="operator-maint@example.test",
                    password_hash=hash_password("correct-horse-battery-staple"),
                    role=Role.operator.value,
                ),
                User(
                    email="viewer-maint@example.test",
                    password_hash=hash_password("correct-horse-battery-staple"),
                    role=Role.viewer.value,
                ),
                User(
                    email="auditor-maint@example.test",
                    password_hash=hash_password("correct-horse-battery-staple"),
                    role=Role.auditor.value,
                ),
            ]
        )
        enrollment_host = Host(name="pending-token-node", address="pending-enrollment")
        db.add(enrollment_host)
        db.flush()
        actor = db.merge(owner)
        enrollment = issue_enrollment_token(db, host=enrollment_host, actor=actor)
        db.commit()
    wrong_type = client.post(
        "/api/v1/agents/maintenance/start",
        headers={"X-Maintenance-Token": enrollment.value},
        json={"kind": "repair"},
    )
    assert wrong_type.status_code == 401
    operator = login(client, "operator-maint@example.test")
    viewer = login(client, "viewer-maint@example.test")
    auditor = login(client, "auditor-maint@example.test")
    assert (
        client.post(
            f"/api/v1/hosts/{host_id}/maintenance-sessions",
            headers=auth(operator),
            json={"kind": "repair"},
        ).status_code
        == 201
    )
    assert (
        client.post(
            f"/api/v1/hosts/{host_id}/maintenance-sessions",
            headers=auth(operator),
            json={"kind": "reinstall"},
        ).status_code
        == 403
    )
    assert (
        client.get(
            f"/api/v1/hosts/{host_id}/maintenance-sessions/latest",
            headers=auth(viewer),
        ).status_code
        == 403
    )
    assert (
        client.get(
            f"/api/v1/hosts/{host_id}/maintenance-sessions/latest",
            headers=auth(auditor),
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/v1/hosts/{host_id}/maintenance-sessions",
            headers=auth(auditor),
            json={"kind": "repair"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/v1/hosts/{host_id}/maintenance-sessions",
            headers=auth(viewer),
            json={"kind": "repair"},
        ).status_code
        == 403
    )


def test_decommission_requires_separation_crl_and_retains_history(
    client: TestClient, owner: User, owner_token: str
) -> None:
    host_id, agent_id, identity_id = managed_host()
    with SessionLocal() as db:
        requester = User(
            email="requester@example.test",
            password_hash=hash_password("correct-horse-battery-staple"),
            role=Role.admin.value,
        )
        approver = User(
            email="approver@example.test",
            password_hash=hash_password("correct-horse-battery-staple"),
            role=Role.owner.value,
        )
        incident = Incident(
            title="Agent retirement",
            fault_type="planned_decommission",
            affected_hosts=[host_id],
        )
        db.add_all([requester, approver, incident])
        db.flush()
        approval = Approval(
            incident_id=incident.id,
            action_name="agent.decommission",
            risk_level=3,
            status=ApprovalStatus.approved.value,
            requested_by=requester.id,
            decided_by=approver.id,
            target_host_id=host_id,
        )
        db.add(approval)
        db.commit()
        approval_id = approval.id

    issued = issue(
        client,
        owner_token,
        host_id,
        "decommission",
        approval_id=approval_id,
        confirmation="DECOMMISSION maintenance-node",
        purge_local_state=False,
    )
    _, progress_headers = start(client, str(issued["command"]), "decommission")
    for status in ("artifact_verified", "service_stopped", "confirmation_pending"):
        progress(client, progress_headers, "decommission", status)
    missing_crl = client.post(
        f"/api/v1/hosts/{host_id}/maintenance-sessions/{issued['id']}/finalize",
        headers=auth(owner_token),
        json={
            "confirmation": "FINALIZE maintenance-node",
            "expected_identity_version": 1,
        },
    )
    assert missing_crl.status_code == 409
    with SessionLocal() as db:
        db.add(
            AuditLog(
                actor_id=None,
                action="gateway.crl_publication",
                resource_type="crl",
                resource_id="9",
                outcome="success",
                details={"sha256": "b" * 64, "certificate_serial": "A044"},
            )
        )
        db.add(
            AgentTask(
                agent_id=agent_id,
                action="collect_diagnostics",
                status="pending",
                nonce="decommission-test-nonce",
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
                signature="test",
            )
        )
        db.commit()
    finalized = client.post(
        f"/api/v1/hosts/{host_id}/maintenance-sessions/{issued['id']}/finalize",
        headers=auth(owner_token),
        json={
            "confirmation": "FINALIZE maintenance-node",
            "expected_identity_version": 1,
            "crl_number": 9,
            "crl_sha256": "b" * 64,
        },
    )
    assert finalized.status_code == 200, finalized.text
    with SessionLocal() as db:
        host = db.get(Host, host_id)
        agent = db.get(Agent, agent_id)
        identity = db.get(AgentIdentity, identity_id)
        task = db.query(AgentTask).filter_by(nonce="decommission-test-nonce").one()
        assert host is not None and not host.enabled
        assert agent is not None and agent.revoked_at is not None
        assert identity is not None and identity.state == AgentIdentityState.revoked.value
        assert task.status == "cancelled"
        assert db.query(AuditLog).filter_by(resource_id=str(issued["id"])).count() >= 1


def test_maintenance_scripts_fail_closed_and_destroy_plaintext() -> None:
    installer = open("scripts/install-agent.sh", encoding="utf-8").read()
    maintainer = open("scripts/maintain-agent.sh", encoding="utf-8").read()
    command_builder = open(
        "controller/guardian/agent_installation.py", encoding="utf-8"
    ).read()
    assert "openssl pkeyutl -verify" in installer
    assert installer.index("openssl pkeyutl -verify") < installer.index(
        'failure_step="Agent download"'
    )
    assert "release manifest signature verification failed" in installer
    assert "version mismatch or replay detected" in installer
    assert "trap rollback EXIT" in maintainer
    assert "trap 'exit 130' INT" in maintainer
    assert 'rm -f -- "$token_file"' in maintainer
    assert "--maintenance-token-file" in command_builder
    assert "?token=" not in maintainer and "--maintenance-token " not in command_builder
    assert "rm -rf /var/lib/vps-guardian-agent" in maintainer
    assert maintainer.index('if [ "$purge_local_state" = true ]') < maintainer.index(
        "rm -rf /var/lib/vps-guardian-agent"
    )
