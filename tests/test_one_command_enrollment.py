from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from guardian.agent_installation import build_one_command_install
from guardian.config import Settings, get_settings
from guardian.database import SessionLocal
from guardian.enrollment import (
    EnrollmentTokenError,
    advance_enrollment,
    authenticate_enrollment_token,
    issue_enrollment_token,
)
from guardian.models import EnrollmentStatus, EnrollmentToken, Host, Role, User
from guardian.security import hash_password
from pydantic import SecretStr, ValidationError
from sqlalchemy import select


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def command_token(command: str) -> str:
    match = re.search(r"printf %s ([A-Za-z0-9._~-]{32,512}) ", command)
    assert match is not None
    return match.group(1)


def login(client: TestClient, email: str) -> str:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 200
    return str(response.json()["access_token"])


def test_one_command_is_fixed_verified_and_contains_token_once() -> None:
    settings = get_settings()
    token = "enrollment-token-value-that-is-long-enough"
    command = build_one_command_install(
        settings=settings,
        host_id="19ca9b96-a220-44ce-b37d-e27ca4a77701",
        enrollment_token=token,
        os_family="debian",
    )

    assert command.count(token) == 1
    assert "curl --config \"$guardian_tmp/curl.conf\"" in command
    assert "enrollment-https-ca-bundle.pem" in command
    assert "base64 -d" in command
    assert "sha256sum --check --status" in command
    assert "trap 'rm -rf -- \"$guardian_tmp\"' EXIT HUP INT TERM" in command
    assert "latest" not in command
    assert "?token=" not in command
    assert "curl | sh" not in command and "curl|sh" not in command
    assert settings.agent_install_release_version in command
    assert settings.agent_enrollment_https_ca_bundle_url not in command


def test_one_command_fails_closed_for_missing_or_mismatched_embedded_ca(
    tmp_path: Path,
) -> None:
    settings = get_settings()
    missing = settings.model_copy(
        update={"agent_enrollment_https_ca_bundle_file": tmp_path / "missing.pem"}
    )
    with pytest.raises(ValueError, match="missing or unsafe"):
        build_one_command_install(
            settings=missing,
            host_id="19ca9b96-a220-44ce-b37d-e27ca4a77701",
            enrollment_token="enrollment-token-value-that-is-long-enough",
            os_family="debian",
        )

    source = Path(settings.agent_enrollment_https_ca_bundle_file)
    bundle = tmp_path / "transport-ca.pem"
    bundle.write_bytes(source.read_bytes())
    mismatch = settings.model_copy(
        update={
            "agent_enrollment_https_ca_bundle_file": bundle,
            "agent_enrollment_https_ca_bundle_sha256": hashlib.sha256(
                b"wrong"
            ).hexdigest(),
        }
    )
    with pytest.raises(ValueError, match="does not match"):
        build_one_command_install(
            settings=mismatch,
            host_id="19ca9b96-a220-44ce-b37d-e27ca4a77701",
            enrollment_token="enrollment-token-value-that-is-long-enough",
            os_family="debian",
        )


def test_one_command_configuration_fails_closed() -> None:
    with pytest.raises(ValidationError, match="non-placeholder SHA-256"):
        Settings(
            one_command_install_enabled=True,
            agent_installer_sha256="0" * 64,
            agent_binary_amd64_sha256="2" * 64,
            agent_binary_arm64_sha256="3" * 64,
            agent_enrollment_https_ca_bundle_sha256="4" * 64,
            agent_controller_public_key_sha256="5" * 64,
        )


def test_regeneration_revokes_old_token_and_source_binding_is_enforced(
    owner: User,
) -> None:
    now = datetime.now(UTC)
    with SessionLocal() as db:
        host = Host(name="regeneration-node", address="pending-enrollment")
        actor = db.merge(owner)
        db.add(host)
        db.flush()
        first = issue_enrollment_token(
            db,
            host=host,
            actor=actor,
            source_cidr="192.0.2.40/32",
            now=now,
        )
        second = issue_enrollment_token(
            db,
            host=host,
            actor=actor,
            source_cidr="192.0.2.40/32",
            now=now + timedelta(seconds=1),
        )
        db.commit()

        with pytest.raises(EnrollmentTokenError, match="revoked"):
            authenticate_enrollment_token(
                db, value=first.value, source_ip="192.0.2.40"
            )
        with pytest.raises(EnrollmentTokenError, match="source"):
            authenticate_enrollment_token(
                db, value=second.value, source_ip="192.0.2.41"
            )
        current, _ = authenticate_enrollment_token(
            db, value=second.value, source_ip="192.0.2.40"
        )
        assert current.status == EnrollmentStatus.waiting.value
        assert first.value not in " ".join(
            db.scalars(select(EnrollmentToken.token_hash)).all()
        )
        assert second.value not in " ".join(
            db.scalars(select(EnrollmentToken.token_hash)).all()
        )


def test_progress_is_monotonic_and_completion_requires_heartbeat(owner: User) -> None:
    with SessionLocal() as db:
        host = Host(name="progress-node", address="pending-enrollment")
        actor = db.merge(owner)
        db.add(host)
        db.flush()
        issued = issue_enrollment_token(db, host=host, actor=actor)
        enrollment, _ = authenticate_enrollment_token(db, value=issued.value)

        assert advance_enrollment(
            db,
            token=enrollment,
            status=EnrollmentStatus.installer_verified.value,
        )
        with pytest.raises(EnrollmentTokenError, match="backwards"):
            advance_enrollment(
                db,
                token=enrollment,
                status=EnrollmentStatus.installer_downloaded.value,
            )
        with pytest.raises(EnrollmentTokenError, match="heartbeat"):
            advance_enrollment(
                db,
                token=enrollment,
                status=EnrollmentStatus.completed.value,
            )


def test_enrollment_rbac_and_group_scope_are_enforced(
    client: TestClient,
    owner_token: str,
) -> None:
    first = client.post(
        "/api/v1/hosts",
        headers=auth(owner_token),
        json={"name": "edge-node", "group_name": "edge"},
    )
    second = client.post(
        "/api/v1/hosts",
        headers=auth(owner_token),
        json={"name": "core-node", "group_name": "core"},
    )
    assert first.status_code == 201 and second.status_code == 201

    with SessionLocal() as db:
        db.add_all(
            [
                User(
                    email="operator@example.test",
                    password_hash=hash_password("correct-horse-battery-staple"),
                    role=Role.operator.value,
                ),
                User(
                    email="viewer@example.test",
                    password_hash=hash_password("correct-horse-battery-staple"),
                    role=Role.viewer.value,
                ),
                User(
                    email="edge-admin@example.test",
                    password_hash=hash_password("correct-horse-battery-staple"),
                    role=Role.admin.value,
                    scopes=["hosts:read", "hosts:write", "group:edge:enroll"],
                ),
            ]
        )
        db.commit()

    operator = login(client, "operator@example.test")
    viewer = login(client, "viewer@example.test")
    edge_admin = login(client, "edge-admin@example.test")
    endpoint = f"/api/v1/hosts/{first.json()['id']}/enrollment-token"
    operator_issue = client.post(endpoint, headers=auth(operator), json={})
    viewer_denied = client.post(endpoint, headers=auth(viewer), json={})
    allowed = client.post(endpoint, headers=auth(edge_admin), json={})
    wrong_group = client.post(
        f"/api/v1/hosts/{second.json()['id']}/enrollment-token",
        headers=auth(edge_admin),
        json={},
    )
    wrong_group_status = client.get(
        f"/api/v1/hosts/{second.json()['id']}/enrollment-sessions/latest",
        headers=auth(edge_admin),
    )

    assert operator_issue.status_code == 201
    assert viewer_denied.status_code == 403
    assert allowed.status_code == 201
    assert wrong_group.status_code == 403
    assert wrong_group_status.status_code == 403
    assert "token" not in allowed.json()
    token = command_token(str(allowed.json()["install_command"]))
    status = client.get(
        f"/api/v1/hosts/{first.json()['id']}/enrollment-sessions/latest",
        headers=auth(edge_admin),
    )
    assert status.status_code == 200
    assert token not in status.text
    operator_revoke = client.post(
        f"/api/v1/hosts/{first.json()['id']}/enrollment-tokens/{allowed.json()['id']}/revoke",
        headers=auth(operator),
    )
    assert operator_revoke.status_code == 403


def test_source_cidr_uses_forwarded_ip_only_from_authenticated_gateway(
    client: TestClient,
    owner_token: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy_secret = "test-private-gateway-authentication-value"
    monkeypatch.setattr(
        get_settings(),
        "trusted_proxy_cert_header_secret",
        SecretStr(proxy_secret),
    )

    def create(name: str) -> tuple[str, str]:
        host = client.post(
            "/api/v1/hosts",
            headers=auth(owner_token),
            json={"name": name},
        )
        issued = client.post(
            f"/api/v1/hosts/{host.json()['id']}/enrollment-token",
            headers=auth(owner_token),
            json={"source_cidr": "203.0.113.10/32"},
        )
        return host.json()["id"], command_token(issued.json()["install_command"])

    _, allowed_token = create("trusted-source-node")
    allowed = client.post(
        "/api/v1/agents/enrollment-progress",
        headers={
            "X-Enrollment-Token": allowed_token,
            "X-Guardian-Proxy-Auth": proxy_secret,
            "X-Forwarded-For": "203.0.113.10",
        },
        json={"status": "installer_downloaded"},
    )
    _, denied_token = create("spoofed-source-node")
    denied = client.post(
        "/api/v1/agents/enrollment-progress",
        headers={
            "X-Enrollment-Token": denied_token,
            "X-Guardian-Proxy-Auth": "wrong",
            "X-Forwarded-For": "203.0.113.10",
        },
        json={"status": "installer_downloaded"},
    )

    assert allowed.status_code == 202
    assert denied.status_code == 409
