from __future__ import annotations

import time
from datetime import UTC, datetime

import pyotp
from fastapi.testclient import TestClient
from guardian.database import SessionLocal
from guardian.models import AuditLog, RecoveryCode, Role, User, UserSession
from guardian.security import hash_password


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_recovery_user(
    client: TestClient,
    owner_token: str,
    *,
    email: str = "recovery-owner@example.test",
    role: str = "owner",
) -> tuple[str, str]:
    initial_password = "initial-recovery-owner-passphrase"
    response = client.post(
        "/api/v1/users",
        headers=auth(owner_token),
        json={
            "email": email,
            "password": initial_password,
            "role": role,
            "scopes": [],
        },
    )
    assert response.status_code == 201
    return str(response.json()["id"]), initial_password


def complete_identity_setup(
    client: TestClient,
    *,
    email: str,
    initial_password: str,
) -> tuple[str, str, list[str]]:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": initial_password},
    )
    assert login.status_code == 200
    assert login.json()["identity_setup_required"] is True
    old_token = str(login.json()["access_token"])
    assert client.get("/api/v1/overview", headers=auth(old_token)).status_code == 403

    new_password = "changed-recovery-owner-passphrase"
    changed = client.post(
        "/api/v1/auth/change-password",
        headers=auth(old_token),
        json={
            "current_password": initial_password,
            "new_password": new_password,
            "retain_current_session": True,
        },
    )
    assert changed.status_code == 200
    token = str(changed.json()["access_token"])
    assert client.get("/api/v1/auth/me", headers=auth(old_token)).status_code == 401
    assert changed.json()["identity_setup_required"] is True

    setup = client.post(
        "/api/v1/auth/totp/setup",
        headers=auth(token),
        json={"current_password": new_password},
    )
    assert setup.status_code == 200
    secret = str(setup.json()["secret"])
    enabled = client.post(
        "/api/v1/auth/totp/enable",
        headers=auth(token),
        json={
            "current_password": new_password,
            "totp_code": pyotp.TOTP(secret).now(),
        },
    )
    assert enabled.status_code == 200
    codes = [str(value) for value in enabled.json()["codes"]]
    assert len(codes) == 10
    assert len(set(codes)) == 10
    assert enabled.json()["displayed_once"] is True

    confirmed = client.post(
        "/api/v1/auth/recovery-codes/confirm",
        headers=auth(token),
        json={"confirmation": "I SAVED MY RECOVERY CODES"},
    )
    assert confirmed.status_code == 200
    assert client.get("/api/v1/overview", headers=auth(token)).status_code == 200
    return token, new_password, codes


def test_controlled_owner_creation_forced_setup_and_secret_hygiene(
    client: TestClient, owner_token: str
) -> None:
    user_id, initial_password = create_recovery_user(client, owner_token)
    with SessionLocal() as db:
        created = db.get(User, user_id)
        assert created is not None
        assert created.must_change_password is True
        assert created.created_by is not None
        audit = db.query(AuditLog).filter(AuditLog.action == "user.create").one()
        assert audit.details["identifier"] == "recovery-owner@example.test"
        assert initial_password not in str(audit.details)
    public_user = next(
        row
        for row in client.get("/api/v1/users", headers=auth(owner_token)).json()
        if row["id"] == user_id
    )
    assert {
        "password_hash",
        "totp_secret_encrypted",
        "totp_pending_secret_encrypted",
        "last_totp_counter",
    }.isdisjoint(public_user)

    _, _, codes = complete_identity_setup(
        client,
        email="recovery-owner@example.test",
        initial_password=initial_password,
    )
    with SessionLocal() as db:
        created = db.get(User, user_id)
        assert created is not None
        assert created.must_change_password is False
        assert created.totp_enabled is True
        assert created.password_changed_at is not None
        assert created.totp_enabled_at is not None
        assert created.recovery_codes_confirmed_at is not None
        rows = db.query(RecoveryCode).filter(RecoveryCode.user_id == user_id).all()
        assert len(rows) == 10
        assert all(len(row.code_hash) == 64 for row in rows)
        serialized = " ".join(row.code_hash for row in rows)
        assert not any(code.replace("-", "") in serialized for code in codes)
        audit_text = " ".join(str(row.details) for row in db.query(AuditLog).all())
        assert not any(code in audit_text for code in codes)


def test_recovery_code_is_single_use_and_reports_remaining(
    client: TestClient, owner_token: str
) -> None:
    _, initial_password = create_recovery_user(
        client,
        owner_token,
        email="single-use@example.test",
        role="admin",
    )
    _, password, codes = complete_identity_setup(
        client,
        email="single-use@example.test",
        initial_password=initial_password,
    )
    recovered = client.post(
        "/api/v1/auth/login",
        json={
            "email": "single-use@example.test",
            "password": password,
            "recovery_code": codes[0],
        },
    )
    assert recovered.status_code == 200
    assert recovered.json()["recovery_codes_remaining"] == 9
    replay = client.post(
        "/api/v1/auth/login",
        json={
            "email": "single-use@example.test",
            "password": password,
            "recovery_code": codes[0],
        },
    )
    assert replay.status_code == 401
    with SessionLocal() as db:
        used = db.query(RecoveryCode).filter(RecoveryCode.used_at.is_not(None)).one()
        assert used.used_at is not None
        audit = (
            db.query(AuditLog)
            .filter(
                AuditLog.action == "auth.recovery_code",
                AuditLog.outcome == "success",
            )
            .one()
        )
        assert audit.details["remaining"] == 9
        assert codes[0] not in str(audit.details)


def test_totp_missing_wrong_replay_and_explicit_invalid_factor_are_rejected(
    client: TestClient,
) -> None:
    password = "existing-totp-owner-passphrase"
    secret = pyotp.random_base32()
    from guardian.config import get_settings
    from guardian.security import encrypt_sensitive

    with SessionLocal() as db:
        user = User(
            email="totp-owner@example.test",
            password_hash=hash_password(password),
            role=Role.owner.value,
            totp_enabled=True,
            totp_secret_encrypted=encrypt_sensitive(secret, get_settings()),
            totp_enabled_at=datetime.now(UTC),
        )
        db.add(user)
        db.commit()

    assert (
        client.post(
            "/api/v1/auth/login",
            json={"email": "totp-owner@example.test", "password": password},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/auth/login",
            json={
                "email": "totp-owner@example.test",
                "password": password,
                "totp_code": "000000",
            },
        ).status_code
        == 401
    )
    code = pyotp.TOTP(secret).now()
    assert (
        client.post(
            "/api/v1/auth/login",
            json={
                "email": "totp-owner@example.test",
                "password": password,
                "totp_code": code,
            },
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/v1/auth/login",
            json={
                "email": "totp-owner@example.test",
                "password": password,
                "totp_code": code,
            },
        ).status_code
        == 401
    )


def test_session_rows_single_revoke_and_role_change_invalidate_tokens(
    client: TestClient,
) -> None:
    password = "session-lifecycle-passphrase"
    with SessionLocal() as db:
        user = User(
            email="sessions@example.test",
            password_hash=hash_password(password),
            role=Role.admin.value,
        )
        db.add(user)
        db.commit()
        user_id = user.id
    first = client.post(
        "/api/v1/auth/login",
        headers={"User-Agent": "first-browser"},
        json={"email": "sessions@example.test", "password": password},
    ).json()["access_token"]
    second = client.post(
        "/api/v1/auth/login",
        headers={"User-Agent": "second-browser"},
        json={"email": "sessions@example.test", "password": password},
    ).json()["access_token"]
    sessions = client.get("/api/v1/auth/sessions", headers=auth(first))
    assert sessions.status_code == 200
    assert len(sessions.json()) == 2
    other_id = next(row["id"] for row in sessions.json() if not row["current"])
    assert (
        client.delete(f"/api/v1/auth/sessions/{other_id}", headers=auth(first)).status_code
        == 204
    )
    assert client.get("/api/v1/auth/me", headers=auth(second)).status_code == 401
    assert client.get("/api/v1/auth/me", headers=auth(first)).status_code == 200
    with SessionLocal() as db:
        rows = db.query(UserSession).filter(UserSession.user_id == user_id).all()
        assert len(rows) == 2
        assert any(row.revoked_at is not None for row in rows)
        assert all(len(row.ip_digest) == 64 for row in rows)
        assert all(len(row.user_agent_digest) == 64 for row in rows)


def test_rbac_duplicate_normalization_and_authorization_changes(
    client: TestClient,
    owner_token: str,
) -> None:
    password = "existing-admin-secure-passphrase"
    with SessionLocal() as db:
        admin = User(
            email="existing-admin@example.test",
            password_hash=hash_password(password),
            role=Role.admin.value,
        )
        viewer = User(
            email="existing-viewer@example.test",
            password_hash=hash_password("existing-viewer-secure-passphrase"),
            role=Role.viewer.value,
        )
        db.add_all([admin, viewer])
        db.commit()
        admin_id = admin.id

    admin_token = client.post(
        "/api/v1/auth/login",
        json={"email": "existing-admin@example.test", "password": password},
    ).json()["access_token"]
    viewer_token = client.post(
        "/api/v1/auth/login",
        json={
            "email": "existing-viewer@example.test",
            "password": "existing-viewer-secure-passphrase",
        },
    ).json()["access_token"]
    owner_payload = {
        "email": "forbidden-owner@example.test",
        "password": "forbidden-owner-secure-passphrase",
        "role": "owner",
    }
    assert (
        client.post("/api/v1/users", headers=auth(admin_token), json=owner_payload).status_code
        == 403
    )
    assert (
        client.post("/api/v1/users", headers=auth(viewer_token), json=owner_payload).status_code
        == 403
    )

    created = client.post(
        "/api/v1/users",
        headers=auth(owner_token),
        json={
            "email": "  Normalized.User@Example.Test ",
            "password": "normalized-user-secure-passphrase",
            "role": "viewer",
        },
    )
    assert created.status_code == 201
    duplicate = client.post(
        "/api/v1/users",
        headers=auth(owner_token),
        json={
            "email": "normalized.user@example.test",
            "password": "another-normalized-secure-passphrase",
            "role": "viewer",
        },
    )
    assert duplicate.status_code == 409

    changed = client.patch(
        f"/api/v1/users/{admin_id}",
        headers=auth(owner_token),
        json={
            "role": "viewer",
            "scopes": ["alerts:read"],
            "current_password": "correct-horse-battery-staple",
        },
    )
    assert changed.status_code == 200
    assert client.get("/api/v1/auth/me", headers=auth(admin_token)).status_code == 401

    relogin = client.post(
        "/api/v1/auth/login",
        json={"email": "existing-admin@example.test", "password": password},
    )
    assert relogin.status_code == 200
    disabled = client.patch(
        f"/api/v1/users/{admin_id}",
        headers=auth(owner_token),
        json={
            "is_active": False,
            "current_password": "correct-horse-battery-staple",
        },
    )
    assert disabled.status_code == 200
    assert (
        client.get(
            "/api/v1/auth/me",
            headers=auth(relogin.json()["access_token"]),
        ).status_code
        == 401
    )


def test_last_owner_rejections_are_audited(
    client: TestClient, owner: User, owner_token: str
) -> None:
    disabled = client.patch(
        f"/api/v1/users/{owner.id}",
        headers=auth(owner_token),
        json={
            "is_active": False,
            "current_password": "correct-horse-battery-staple",
        },
    )
    assert disabled.status_code == 409
    revoked = client.post(
        f"/api/v1/users/{owner.id}/revoke-sessions",
        headers=auth(owner_token),
    )
    assert revoked.status_code == 409
    deleted = client.request(
        "DELETE",
        f"/api/v1/users/{owner.id}",
        headers=auth(owner_token),
        json={
            "current_password": "correct-horse-battery-staple",
            "confirmation": "DELETE USER",
        },
    )
    assert deleted.status_code == 409
    with SessionLocal() as db:
        rejected = (
            db.query(AuditLog)
            .filter(AuditLog.outcome == "rejected")
            .all()
        )
        assert {row.action for row in rejected} >= {
            "user.update",
            "user.sessions_revoke",
            "user.delete",
        }


def test_recovery_code_regeneration_revokes_previous_batch(
    client: TestClient, owner_token: str
) -> None:
    user_id, initial_password = create_recovery_user(
        client,
        owner_token,
        email="regenerate@example.test",
        role="admin",
    )
    token, password, old_codes = complete_identity_setup(
        client,
        email="regenerate@example.test",
        initial_password=initial_password,
    )
    with SessionLocal() as db:
        user = db.get(User, user_id)
        assert user is not None and user.totp_secret_encrypted
        from guardian.config import get_settings
        from guardian.security import decrypt_sensitive

        secret = decrypt_sensitive(user.totp_secret_encrypted, get_settings())
    next_code = pyotp.TOTP(secret).at(int(time.time()) + 30)
    regenerated = client.post(
        "/api/v1/auth/recovery-codes/regenerate",
        headers=auth(token),
        json={"current_password": password, "totp_code": next_code},
    )
    assert regenerated.status_code == 200
    assert set(regenerated.json()["codes"]).isdisjoint(old_codes)
    with SessionLocal() as db:
        old_batch = (
            db.query(RecoveryCode)
            .filter(
                RecoveryCode.user_id == user_id,
                RecoveryCode.revoked_at.is_not(None),
            )
            .all()
        )
        assert len(old_batch) == 10
