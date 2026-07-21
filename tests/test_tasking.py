from __future__ import annotations

import base64
import json
from datetime import UTC

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from guardian.config import Settings
from guardian.database import SessionLocal
from guardian.tasking import create_agent_task, task_signing_payload


def test_task_signature_is_compatible_and_registered(tmp_path) -> None:  # type: ignore[no-untyped-def]
    settings = Settings(
        environment="test",
        controller_signing_key_file=tmp_path / "controller.pem",
    )
    with SessionLocal() as db:
        task = create_agent_task(
            db,
            agent_id="agent-id",
            action="local_health_check",
            parameters={"target": "http://127.0.0.1:8080/health", "dry_run": "true"},
            settings=settings,
        )
        payload = task_signing_payload(
            task_id=task.id,
            action=task.action,
            parameters=task.parameters,
            nonce=task.nonce,
            expires_at=int(task.expires_at.replace(tzinfo=UTC).timestamp()),
        )
        raw_key = settings.controller_signing_key_file.read_bytes()
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_private_key(raw_key, password=None)
        assert isinstance(key, Ed25519PrivateKey)
        key.public_key().verify(base64.b64decode(task.signature), payload)
        document = json.loads(payload)
        assert list(document) == ["id", "action", "parameters", "nonce", "expires_at"]


def test_unregistered_task_is_rejected(tmp_path) -> None:  # type: ignore[no-untyped-def]
    settings = Settings(
        environment="test",
        controller_signing_key_file=tmp_path / "controller.pem",
    )
    with SessionLocal() as db:
        try:
            create_agent_task(
                db,
                agent_id="agent-id",
                action="shell",
                parameters={"command": "whoami"},
                settings=settings,
            )
        except ValueError as exc:
            assert str(exc) == "action is not registered"
        else:
            raise AssertionError("unregistered task was accepted")
