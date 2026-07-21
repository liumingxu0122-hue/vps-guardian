from __future__ import annotations

import base64
import json
import os
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.orm import Session

from guardian.config import Settings
from guardian.models import AgentTask

REGISTERED_ACTIONS = {
    "restart_container",
    "restart_systemd",
    "validate_caddy",
    "reload_caddy",
    "local_health_check",
    "cleanup_cache",
    "rollback_caddy_config",
}


def _write_private_key(path: Path, key: Ed25519PrivateKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


def load_controller_signing_key(settings: Settings) -> Ed25519PrivateKey:
    path = settings.controller_signing_key_file
    if not path.exists():
        if settings.environment == "production":
            raise RuntimeError("controller signing key is missing")
        _write_private_key(path, Ed25519PrivateKey.generate())
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("controller signing key is not Ed25519")
    return key


def controller_public_key_base64(settings: Settings) -> str:
    raw = (
        load_controller_signing_key(settings)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    return base64.b64encode(raw).decode()


def task_signing_payload(
    *,
    task_id: str,
    action: str,
    parameters: dict[str, str],
    nonce: str,
    expires_at: int,
) -> bytes:
    payload = {
        "id": task_id,
        "action": action,
        "parameters": dict(sorted(parameters.items())),
        "nonce": nonce,
        "expires_at": expires_at,
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()


def create_agent_task(
    db: Session,
    *,
    agent_id: str,
    action: str,
    parameters: dict[str, str],
    settings: Settings,
    ttl_seconds: int = 300,
) -> AgentTask:
    if action not in REGISTERED_ACTIONS:
        raise ValueError("action is not registered")
    if not 30 <= ttl_seconds <= 900:
        raise ValueError("task TTL is outside the permitted range")
    if len(parameters) > 16 or any(
        len(key) > 64 or len(value) > 1024 for key, value in parameters.items()
    ):
        raise ValueError("task parameters exceed limits")
    task_id = str(uuid.uuid4())
    nonce = secrets.token_urlsafe(24)
    expires_at = datetime.now(UTC) + timedelta(seconds=ttl_seconds)
    payload = task_signing_payload(
        task_id=task_id,
        action=action,
        parameters=parameters,
        nonce=nonce,
        expires_at=int(expires_at.timestamp()),
    )
    signature = load_controller_signing_key(settings).sign(payload)
    task = AgentTask(
        id=task_id,
        agent_id=agent_id,
        action=action,
        parameters=parameters,
        nonce=nonce,
        expires_at=expires_at,
        signature=base64.b64encode(signature).decode(),
    )
    db.add(task)
    db.flush()
    return task


def serialize_agent_task(task: AgentTask) -> dict[str, object]:
    return {
        "id": task.id,
        "action": task.action,
        "parameters": task.parameters,
        "nonce": task.nonce,
        "expires_at": int(task.expires_at.replace(tzinfo=UTC).timestamp()),
        "signature": task.signature,
    }
