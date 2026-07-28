from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from guardian.config import Settings
from guardian.database import SessionLocal
from guardian.main import app
from guardian.models import User, UserSession
from pydantic import ValidationError
from sqlalchemy import select

PASSWORD = "correct-horse-battery-staple"
ORIGIN = "http://testserver"


def browser_login(
    client: TestClient,
    user: User,
    *,
    remember_me: bool = False,
) -> tuple[str, str]:
    response = client.post(
        "/api/v1/auth/browser/login",
        json={
            "email": user.email,
            "password": PASSWORD,
            "remember_me": remember_me,
            "device_name": "Test browser",
        },
        headers={"User-Agent": "Mozilla/5.0 Chrome/126"},
    )
    assert response.status_code == 200, response.text
    assert "access_token" not in response.json()
    session_secret = client.cookies.get("guardian_browser_session")
    csrf_secret = client.cookies.get("guardian_csrf")
    assert session_secret
    assert csrf_secret
    return session_secret, csrf_secret


def browser_headers(csrf_secret: str) -> dict[str, str]:
    return {"Origin": ORIGIN, "X-CSRF-Token": csrf_secret}


def test_session_configuration_rejects_inverted_lifetimes() -> None:
    with pytest.raises(ValidationError, match="DEFAULT_IDLE_HOURS"):
        Settings(session_default_idle_hours=168, session_default_absolute_days=1)
    with pytest.raises(ValidationError, match="REMEMBER_IDLE_DAYS"):
        Settings(session_remember_idle_days=30, session_remember_absolute_days=7)
    with pytest.raises(ValidationError, match="REMEMBER_ABSOLUTE_DAYS"):
        Settings(session_default_absolute_days=30, session_remember_absolute_days=7)


def current_row(user: User) -> UserSession:
    with SessionLocal() as db:
        return db.scalar(
            select(UserSession)
            .where(
                UserSession.user_id == user.id,
                UserSession.created_via != "api_token",
                UserSession.revoked_at.is_(None),
            )
            .order_by(UserSession.issued_at.desc())
        )  # type: ignore[return-value]


@pytest.mark.parametrize(
    ("remember_me", "minimum_idle", "minimum_absolute"),
    [
        (False, timedelta(hours=11), timedelta(days=6)),
        (True, timedelta(days=6), timedelta(days=29)),
    ],
)
def test_browser_session_lifetimes_and_hash_only_storage(
    client: TestClient,
    owner: User,
    remember_me: bool,
    minimum_idle: timedelta,
    minimum_absolute: timedelta,
) -> None:
    secret, _ = browser_login(client, owner, remember_me=remember_me)
    row = current_row(owner)
    now = datetime.now(UTC)
    assert row.remember_me is remember_me
    assert row.idle_expires_at.replace(tzinfo=UTC) - now >= minimum_idle
    assert row.absolute_expires_at.replace(tzinfo=UTC) - now >= minimum_absolute
    assert row.token_hash == hashlib.sha256(secret.encode()).hexdigest()
    assert secret not in row.token_hash
    assert row.user_agent_summary == "desktop:chrome"
    assert row.ip_summary == "protected"
    with SessionLocal() as db:
        assert db.scalar(
            select(UserSession).where(
                UserSession.user_id == owner.id,
                UserSession.created_via == "api_token",
            )
        ) is None


def test_invalid_bearer_never_falls_back_to_valid_browser_cookie(
    client: TestClient, owner: User
) -> None:
    browser_login(client, owner)
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer definitely-invalid"},
    )
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "SESSION_INVALID"


def test_preference_cookies_are_not_mistaken_for_authentication(
    client: TestClient,
) -> None:
    client.cookies.set("guardian_locale", "zh-CN")
    client.cookies.set("guardian_theme", "dark")
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "SESSION_MISSING"


def test_idle_and_absolute_expiry_have_stable_codes(
    client: TestClient, owner: User
) -> None:
    browser_login(client, owner)
    row = current_row(owner)
    with SessionLocal() as db:
        stored = db.get(UserSession, row.id)
        assert stored
        stored.idle_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "SESSION_IDLE_EXPIRED"

    client.cookies.clear()
    browser_login(client, owner)
    row = current_row(owner)
    with SessionLocal() as db:
        stored = db.get(UserSession, row.id)
        assert stored
        stored.absolute_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        stored.idle_expires_at = stored.absolute_expires_at
        db.commit()
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "SESSION_ABSOLUTE_EXPIRED"


def test_activity_touch_is_explicit_throttled_and_capped(
    client: TestClient, owner: User
) -> None:
    _, csrf = browser_login(client, owner)
    row = current_row(owner)
    original_seen = row.last_seen_at
    response = client.post(
        "/api/v1/auth/activity",
        headers={**browser_headers(csrf), "X-Guardian-Activity-Type": "pointer"},
    )
    assert response.status_code == 204
    assert current_row(owner).last_seen_at == original_seen
    unsupported = client.post(
        "/api/v1/auth/activity",
        headers={**browser_headers(csrf), "X-Guardian-Activity-Type": "network"},
    )
    assert unsupported.status_code == 422

    with SessionLocal() as db:
        stored = db.get(UserSession, row.id)
        assert stored
        stored.last_seen_at = datetime.now(UTC) - timedelta(minutes=6)
        stored.absolute_expires_at = datetime.now(UTC) + timedelta(minutes=10)
        stored.idle_expires_at = stored.absolute_expires_at
        db.commit()
    response = client.post(
        "/api/v1/auth/activity",
        headers={**browser_headers(csrf), "X-Guardian-Activity-Type": "keyboard"},
    )
    assert response.status_code == 204
    touched = current_row(owner)
    assert touched.last_seen_at > original_seen
    assert touched.idle_expires_at <= touched.absolute_expires_at
    assert touched.last_activity_type == "keyboard"


def test_step_up_is_current_session_only_and_password_change_rotates_secret(
    client: TestClient, owner: User
) -> None:
    old_secret, csrf = browser_login(client, owner)
    protected = client.post(
        "/api/v1/auth/sessions/revoke-others",
        headers=browser_headers(csrf),
    )
    assert protected.status_code == 403
    assert protected.json()["detail"]["code"] == "STEP_UP_REQUIRED"

    confirmed = client.post(
        "/api/v1/auth/step-up",
        json={"current_password": PASSWORD},
        headers=browser_headers(csrf),
    )
    assert confirmed.status_code == 200
    assert datetime.fromisoformat(confirmed.json()["step_up_until"]) > datetime.now(UTC)

    changed = client.post(
        "/api/v1/auth/change-password",
        json={
            "current_password": PASSWORD,
            "new_password": "a-new-correct-horse-battery-staple",
            "retain_current_session": True,
        },
        headers=browser_headers(csrf),
    )
    assert changed.status_code == 200, changed.text
    new_secret = client.cookies.get("guardian_browser_session")
    assert new_secret and new_secret != old_secret

    isolated = TestClient(app)
    isolated.cookies.set("guardian_browser_session", old_secret)
    response = isolated.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "SESSION_REVOKED"
