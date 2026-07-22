from __future__ import annotations

import base64
import json
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from fastapi.testclient import TestClient
from guardian.agent_security import build_agent_signing_message
from guardian.api import claim_agent_identity_version
from guardian.database import SessionLocal
from guardian.models import (
    Agent,
    AgentIdentity,
    AgentIdentityState,
    AgentTask,
    AuditLog,
    Host,
    MetricSnapshot,
)


def public_key_base64(private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode()


def seed_agent(
    *,
    name: str = "rotation-node",
    fingerprint: str = "AA" * 32,
    serial: str = "1000",
) -> tuple[str, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    with SessionLocal() as database:
        host = Host(name=name, address="192.0.2.90")
        database.add(host)
        database.flush()
        agent = Agent(
            host_id=host.id,
            signing_public_key=public_key_base64(private_key),
            certificate_fingerprint=fingerprint,
            certificate_serial=serial,
        )
        database.add(agent)
        database.flush()
        now = datetime.now(UTC)
        database.add(
            AgentIdentity(
                agent_id=agent.id,
                generation=1,
                state=AgentIdentityState.active.value,
                signing_public_key=agent.signing_public_key,
                certificate_fingerprint=fingerprint,
                certificate_serial=serial,
                verified_at=now,
                activated_at=now,
            )
        )
        database.commit()
        return agent.id, private_key


def signed_headers(
    *,
    agent_id: str,
    private_key: Ed25519PrivateKey,
    fingerprint: str,
    payload: bytes,
) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    signature = base64.b64encode(
        private_key.sign(build_agent_signing_message(agent_id, timestamp, nonce, payload))
    ).decode()
    return {
        "Content-Type": "application/json",
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": signature,
        "X-Client-Cert-Fingerprint": fingerprint,
    }


def send_heartbeat(
    client: TestClient,
    *,
    agent_id: str,
    private_key: Ed25519PrivateKey,
    fingerprint: str,
    events: list[dict[str, object]] | None = None,
) -> object:
    payload = json.dumps(
        {
            "collected_at": datetime.now(UTC).isoformat(),
            "version": "0.1.0",
            "metrics": {"cpu_percent": 10.0},
            "services": [],
            "events": events or [],
        },
        separators=(",", ":"),
    ).encode()
    return client.post(
        f"/api/v1/agents/{agent_id}/heartbeat",
        headers=signed_headers(
            agent_id=agent_id,
            private_key=private_key,
            fingerprint=fingerprint,
            payload=payload,
        ),
        content=payload,
    )


def prepare_identity(
    client: TestClient,
    *,
    agent_id: str,
    owner_token: str,
    private_key: Ed25519PrivateKey,
    fingerprint: str = "BB" * 32,
    serial: str = "2000",
    expected_version: int = 1,
    rotation_id: str | None = None,
) -> object:
    return client.post(
        f"/api/v1/agents/{agent_id}/identities/pending",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={
            "rotation_id": rotation_id or str(uuid.uuid4()),
            "expected_version": expected_version,
            "signing_public_key": public_key_base64(private_key),
            "certificate_fingerprint": fingerprint,
            "certificate_serial": serial,
        },
    )


def test_pending_identity_preserves_active_until_verified_and_activated(
    client: TestClient, owner_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent_id, old_key = seed_agent()
    new_key = Ed25519PrivateKey.generate()
    pending = prepare_identity(
        client,
        agent_id=agent_id,
        owner_token=owner_token,
        private_key=new_key,
    )

    assert pending.status_code == 200
    assert pending.json()["state"] == AgentIdentityState.pending.value
    assert pending.json()["generation"] == 2
    pending_id = pending.json()["id"]

    old_heartbeat = send_heartbeat(
        client,
        agent_id=agent_id,
        private_key=old_key,
        fingerprint="AA" * 32,
    )
    wrong_signing_key = send_heartbeat(
        client,
        agent_id=agent_id,
        private_key=Ed25519PrivateKey.generate(),
        fingerprint="BB" * 32,
    )

    assert old_heartbeat.status_code == 202
    assert old_heartbeat.json()["identity_state"] == AgentIdentityState.active.value
    assert wrong_signing_key.status_code == 401
    assert wrong_signing_key.json()["detail"] == "invalid agent signature"
    with SessionLocal() as database:
        agent_before = database.get(Agent, agent_id)
        assert agent_before
        task = AgentTask(
            agent_id=agent_id,
            action="local_health_check",
            parameters={"dry_run": "true"},
            status="pending",
            nonce=secrets.token_urlsafe(24),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            signature="pending-proof-must-not-deliver",
        )
        database.add(task)
        database.commit()
        task_id = task.id
        heartbeat_before = agent_before.last_heartbeat_at
        version_before = agent_before.version
        host_seen_before = agent_before.host.last_seen_at
        host_status_before = agent_before.host.status

    def reject_reconciliation(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("pending identity heartbeat reached reconciliation")

    pending_result = {
        "type": "action_result",
        "result": {
            "task_id": task_id,
            "action": "local_health_check",
            "success": True,
            "dry_run": True,
            "before": {},
            "after": {},
            "message": "must not be processed",
            "finished_at": datetime.now(UTC).isoformat(),
        },
    }
    with monkeypatch.context() as context:
        context.setattr("guardian.api.reconcile_staging_heartbeat", reject_reconciliation)
        new_heartbeat = send_heartbeat(
            client,
            agent_id=agent_id,
            private_key=new_key,
            fingerprint="BB" * 32,
            events=[pending_result],
        )

    assert new_heartbeat.status_code == 425
    assert new_heartbeat.json()["accepted"] is False
    assert new_heartbeat.json()["identity_state"] == AgentIdentityState.pending.value
    assert new_heartbeat.json()["tasks"] == []
    with SessionLocal() as database:
        assert database.query(MetricSnapshot).count() == 1
        pending_identity = database.get(AgentIdentity, pending_id)
        assert pending_identity and pending_identity.verified_at is not None
        agent_after = database.get(Agent, agent_id)
        task_after = database.get(AgentTask, task_id)
        assert agent_after
        assert agent_after.last_heartbeat_at == heartbeat_before
        assert agent_after.version == version_before
        assert agent_after.host.last_seen_at == host_seen_before
        assert agent_after.host.status == host_status_before
        assert task_after and task_after.status == "pending"
        assert task_after.result is None
        assert not database.query(AuditLog).filter_by(action="agent.task_result").first()

    second_new_heartbeat = send_heartbeat(
        client,
        agent_id=agent_id,
        private_key=new_key,
        fingerprint="BB" * 32,
    )
    assert second_new_heartbeat.status_code == 425

    activated = client.post(
        f"/api/v1/agents/{agent_id}/identities/{pending_id}/activate",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"expected_version": 2},
    )
    assert activated.status_code == 200
    assert activated.json()["state"] == AgentIdentityState.active.value

    retired_heartbeat = send_heartbeat(
        client,
        agent_id=agent_id,
        private_key=old_key,
        fingerprint="AA" * 32,
    )
    active_heartbeat = send_heartbeat(
        client,
        agent_id=agent_id,
        private_key=new_key,
        fingerprint="BB" * 32,
    )
    assert retired_heartbeat.status_code == 202
    assert retired_heartbeat.json()["identity_state"] == AgentIdentityState.retiring.value
    assert active_heartbeat.status_code == 202
    assert active_heartbeat.json()["identity_state"] == AgentIdentityState.active.value

    with SessionLocal() as database:
        agent = database.get(Agent, agent_id)
        assert agent and agent.identity_version == 3
        assert agent.certificate_fingerprint == "BB" * 32
        identities = list(
            database.query(AgentIdentity)
            .filter(AgentIdentity.agent_id == agent_id)
            .order_by(AgentIdentity.generation)
        )
        assert [identity.state for identity in identities] == [
            AgentIdentityState.retiring.value,
            AgentIdentityState.active.value,
        ]
        assert identities[0].retiring_at is not None
        assert identities[1].verified_at is not None
        assert identities[1].successful_heartbeats == 2
        actions = {entry.action for entry in database.query(AuditLog).all()}
        assert {
            "agent.identity_pending_created",
            "agent.identity_possession_verified",
            "agent.identity_activated",
        } <= actions


def test_activation_requires_proof_and_cas_then_pending_can_be_retired(
    client: TestClient, owner_token: str
) -> None:
    agent_id, old_key = seed_agent()
    pending_key = Ed25519PrivateKey.generate()
    pending = prepare_identity(
        client,
        agent_id=agent_id,
        owner_token=owner_token,
        private_key=pending_key,
    )
    pending_id = pending.json()["id"]
    headers = {"Authorization": f"Bearer {owner_token}"}

    unverified = client.post(
        f"/api/v1/agents/{agent_id}/identities/{pending_id}/activate",
        headers=headers,
        json={"expected_version": 2},
    )
    stale_retire = client.post(
        f"/api/v1/agents/{agent_id}/identities/{pending_id}/retire",
        headers=headers,
        json={"expected_version": 1, "reason_code": "rotation.cancelled"},
    )
    duplicate_pending = prepare_identity(
        client,
        agent_id=agent_id,
        owner_token=owner_token,
        private_key=Ed25519PrivateKey.generate(),
        fingerprint="CC" * 32,
        serial="3000",
        expected_version=2,
    )

    assert unverified.status_code == 409
    assert unverified.json()["detail"] == (
        "pending identity requires two consecutive authenticated heartbeats"
    )
    assert stale_retire.status_code == 409
    assert stale_retire.json()["detail"] == "stale agent identity version"
    assert duplicate_pending.status_code == 409
    assert duplicate_pending.json()["detail"] == "agent already has a pending identity"

    retired = client.post(
        f"/api/v1/agents/{agent_id}/identities/{pending_id}/retire",
        headers=headers,
        json={"expected_version": 2, "reason_code": "rotation.cancelled"},
    )
    assert retired.status_code == 200
    assert retired.json()["state"] == AgentIdentityState.retired.value
    assert send_heartbeat(
        client,
        agent_id=agent_id,
        private_key=old_key,
        fingerprint="AA" * 32,
    ).status_code == 202
    assert send_heartbeat(
        client,
        agent_id=agent_id,
        private_key=pending_key,
        fingerprint="BB" * 32,
    ).status_code == 401


def test_identity_version_cas_rejects_a_competing_stale_writer() -> None:
    agent_id, _ = seed_agent()
    with SessionLocal() as winner:
        winning_agent = winner.get(Agent, agent_id)
        assert winning_agent
        assert claim_agent_identity_version(winner, winning_agent, 1) == 2
        winner.commit()

    with SessionLocal() as loser:
        losing_agent = loser.get(Agent, agent_id)
        assert losing_agent
        with pytest.raises(HTTPException) as conflict:
            claim_agent_identity_version(loser, losing_agent, 1)
        assert conflict.value.status_code == 409
        assert conflict.value.detail == "stale agent identity version"


def test_rotation_id_is_idempotent_and_old_identity_is_revoked_after_crl(
    client: TestClient, owner_token: str
) -> None:
    agent_id, old_key = seed_agent()
    new_key = Ed25519PrivateKey.generate()
    rotation_id = str(uuid.uuid4())
    first = prepare_identity(
        client,
        agent_id=agent_id,
        owner_token=owner_token,
        private_key=new_key,
        rotation_id=rotation_id,
    )
    replay = prepare_identity(
        client,
        agent_id=agent_id,
        owner_token=owner_token,
        private_key=new_key,
        rotation_id=rotation_id,
    )
    conflict = prepare_identity(
        client,
        agent_id=agent_id,
        owner_token=owner_token,
        private_key=Ed25519PrivateKey.generate(),
        fingerprint="CC" * 32,
        serial="3000",
        rotation_id=rotation_id,
    )

    assert first.status_code == 200
    assert replay.status_code == 200
    assert replay.json()["id"] == first.json()["id"]
    assert conflict.status_code == 409
    assert conflict.json()["detail"] == "rotation id payload conflict"

    for _ in range(2):
        pending = send_heartbeat(
            client,
            agent_id=agent_id,
            private_key=new_key,
            fingerprint="BB" * 32,
        )
        assert pending.status_code == 425

    identity_id = first.json()["id"]
    activated = client.post(
        f"/api/v1/agents/{agent_id}/identities/{identity_id}/activate",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"expected_version": 2},
    )
    assert activated.status_code == 200
    with SessionLocal() as database:
        retiring = database.query(AgentIdentity).filter_by(
            agent_id=agent_id,
            state=AgentIdentityState.retiring.value,
        ).one()
        retiring_id = retiring.id

    unverified = client.post(
        f"/api/v1/agents/{agent_id}/identities/{retiring_id}/revoke",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={
            "expected_version": 3,
            "crl_number": 4102,
            "crl_sha256": "ab" * 32,
        },
    )
    assert unverified.status_code == 409
    assert unverified.json()["detail"] == "matching CRL publication is not verified"
    with SessionLocal() as database:
        database.add(
            AuditLog(
                actor_id=None,
                action="gateway.crl_publication",
                resource_type="agent_ca_crl",
                resource_id="4102",
                outcome="success",
                details={
                    "crl_number": "4102",
                    "sha256": "ab" * 32,
                    "certificate_serial": "1000",
                },
            )
        )
        database.commit()
    revoked = client.post(
        f"/api/v1/agents/{agent_id}/identities/{retiring_id}/revoke",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={
            "expected_version": 3,
            "crl_number": 4102,
            "crl_sha256": "ab" * 32,
        },
    )
    assert revoked.status_code == 200
    assert revoked.json()["state"] == AgentIdentityState.revoked.value
    assert send_heartbeat(
        client,
        agent_id=agent_id,
        private_key=old_key,
        fingerprint="AA" * 32,
    ).status_code == 401

    with SessionLocal() as database:
        actions = [entry.action for entry in database.query(AuditLog).all()]
        assert "agent.identity_rotation_replayed" in actions
        assert "agent.identity_rotation_conflict" in actions
        assert "agent.identity_heartbeat_threshold_met" in actions
        assert "agent.identity_revoked" in actions


def test_pending_identity_can_prove_possession_on_validation_endpoint(
    client: TestClient, owner_token: str
) -> None:
    agent_id, _ = seed_agent()
    pending_key = Ed25519PrivateKey.generate()
    pending = prepare_identity(
        client,
        agent_id=agent_id,
        owner_token=owner_token,
        private_key=pending_key,
    )
    identity_id = pending.json()["id"]
    payload = b'{"expected_version":2}'

    validated = client.post(
        f"/api/v1/agents/{agent_id}/identities/{identity_id}/validate",
        headers=signed_headers(
            agent_id=agent_id,
            private_key=pending_key,
            fingerprint="BB" * 32,
            payload=payload,
        ),
        content=payload,
    )

    assert validated.status_code == 200
    assert validated.json()["verified_at"] is not None
    assert validated.json()["state"] == AgentIdentityState.pending.value


def test_expired_pending_identity_is_rejected_and_retired_on_activation(
    client: TestClient, owner_token: str
) -> None:
    agent_id, old_key = seed_agent()
    pending_key = Ed25519PrivateKey.generate()
    pending = prepare_identity(
        client,
        agent_id=agent_id,
        owner_token=owner_token,
        private_key=pending_key,
    )
    identity_id = pending.json()["id"]
    with SessionLocal() as database:
        identity = database.get(AgentIdentity, identity_id)
        assert identity
        identity.expires_at = datetime(2020, 1, 1, tzinfo=UTC)
        identity.verified_at = datetime.now(UTC)
        database.commit()

    expired_heartbeat = send_heartbeat(
        client,
        agent_id=agent_id,
        private_key=pending_key,
        fingerprint="BB" * 32,
    )
    active_heartbeat = send_heartbeat(
        client,
        agent_id=agent_id,
        private_key=old_key,
        fingerprint="AA" * 32,
    )
    activation = client.post(
        f"/api/v1/agents/{agent_id}/identities/{identity_id}/activate",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"expected_version": 2},
    )

    assert expired_heartbeat.status_code == 401
    assert active_heartbeat.status_code == 202
    assert activation.status_code == 409
    assert activation.json()["detail"] == "pending identity expired and was retired"
    with SessionLocal() as database:
        identity = database.get(AgentIdentity, identity_id)
        agent = database.get(Agent, agent_id)
        assert identity and identity.state == AgentIdentityState.retired.value
        assert identity.retired_at is not None
        assert agent and agent.identity_version == 3


def test_prepare_atomically_retires_an_expired_pending_identity(
    client: TestClient, owner_token: str
) -> None:
    agent_id, _ = seed_agent()
    first = prepare_identity(
        client,
        agent_id=agent_id,
        owner_token=owner_token,
        private_key=Ed25519PrivateKey.generate(),
    )
    with SessionLocal() as database:
        identity = database.get(AgentIdentity, first.json()["id"])
        assert identity
        identity.expires_at = datetime(2020, 1, 1, tzinfo=UTC)
        database.commit()

    replacement = prepare_identity(
        client,
        agent_id=agent_id,
        owner_token=owner_token,
        private_key=Ed25519PrivateKey.generate(),
        fingerprint="CC" * 32,
        serial="3000",
        expected_version=2,
    )

    assert replacement.status_code == 200
    assert replacement.json()["generation"] == 3
    with SessionLocal() as database:
        first_identity = database.get(AgentIdentity, first.json()["id"])
        replacement_identity = database.get(AgentIdentity, replacement.json()["id"])
        assert first_identity and first_identity.state == AgentIdentityState.retired.value
        assert replacement_identity
        assert replacement_identity.state == AgentIdentityState.pending.value
        assert replacement_identity.expires_at is not None


def test_agent_rotation_rejects_duplicate_historical_certificate_serial(
    client: TestClient, owner_token: str
) -> None:
    first_agent_id, _ = seed_agent()
    second_agent_id, _ = seed_agent(
        name="second-rotation-node",
        fingerprint="CC" * 32,
        serial="2000",
    )

    response = prepare_identity(
        client,
        agent_id=second_agent_id,
        owner_token=owner_token,
        private_key=Ed25519PrivateKey.generate(),
        fingerprint="DD" * 32,
        serial="00001000",
    )

    assert first_agent_id != second_agent_id
    assert response.status_code == 409
    assert response.json()["detail"] == "certificate serial already enrolled"


def test_owner_can_list_identities_without_public_keys_and_revoke_agent(
    client: TestClient, owner_token: str
) -> None:
    agent_id, old_key = seed_agent()
    headers = {"Authorization": f"Bearer {owner_token}"}
    with SessionLocal() as database:
        database.add(
            AuditLog(
                actor_id=None,
                action="gateway.crl_publication",
                resource_type="agent_ca_crl",
                resource_id="5102",
                outcome="success",
                details={
                    "crl_number": "5102",
                    "sha256": "cd" * 32,
                    "certificate_serial": "1000",
                },
            )
        )
        database.commit()

    listed = client.get(f"/api/v1/agents/{agent_id}/identities", headers=headers)
    revoked = client.post(
        f"/api/v1/agents/{agent_id}/revoke",
        headers=headers,
        json={
            "expected_version": 1,
            "crl_number": 5102,
            "crl_sha256": "cd" * 32,
        },
    )

    assert listed.status_code == 200
    assert listed.json()[0]["state"] == AgentIdentityState.active.value
    assert "signing_public_key" not in listed.json()[0]
    assert revoked.status_code == 204
    assert send_heartbeat(
        client,
        agent_id=agent_id,
        private_key=old_key,
        fingerprint="AA" * 32,
    ).status_code == 404


def test_legacy_single_step_rotation_fails_loudly(
    client: TestClient, owner_token: str
) -> None:
    agent_id, _ = seed_agent()

    response = client.post(
        f"/api/v1/agents/{agent_id}/rotate",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={},
    )

    assert response.status_code == 410
    assert "single-step rotation is disabled" in response.json()["detail"]


@pytest.mark.parametrize("fingerprint", ["AA" * 16, ":" * 64, "AA" * 33])
def test_agent_enrollment_rejects_invalid_normalized_fingerprint(
    client: TestClient,
    fingerprint: str,
) -> None:
    response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-Enrollment-Token": "test-enrollment-token"},
        json={
            "host": {"name": "invalid-fingerprint-node", "address": "192.0.2.92"},
            "signing_public_key": public_key_base64(Ed25519PrivateKey.generate()),
            "certificate_fingerprint": fingerprint,
            "version": "0.1.0",
        },
    )

    assert response.status_code == 422


def test_agent_rotation_rejects_invalid_normalized_fingerprint(
    client: TestClient,
    owner_token: str,
) -> None:
    agent_id, _ = seed_agent()

    response = prepare_identity(
        client,
        agent_id=agent_id,
        owner_token=owner_token,
        private_key=Ed25519PrivateKey.generate(),
        fingerprint="AA" * 16,
        serial="3000",
    )

    assert response.status_code == 422
