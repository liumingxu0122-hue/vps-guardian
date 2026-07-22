from __future__ import annotations

from fastapi.testclient import TestClient
from guardian.database import SessionLocal
from guardian.models import Role, User
from guardian.security import hash_password


def test_health_is_public(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.2.0a1"}


def test_readiness_is_public_and_queries_critical_tables(client: TestClient) -> None:
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.2.0a1"}


def test_login_sets_secure_shape_cookies(client: TestClient, owner: User) -> None:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": owner.email, "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 200
    cookies = response.headers.get_list("set-cookie")
    assert any("guardian_session=" in cookie and "HttpOnly" in cookie for cookie in cookies)
    assert any("SameSite=strict" in cookie for cookie in cookies)
    assert response.json()["token_type"] == "bearer"


def test_csrf_required_for_cookie_mutation(client: TestClient, owner: User) -> None:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": owner.email, "password": "correct-horse-battery-staple"},
    )
    assert login.status_code == 200
    response = client.post(
        "/api/v1/hosts",
        json={"name": "node-1", "address": "192.0.2.10"},
    )
    assert response.status_code == 403
    response = client.post(
        "/api/v1/hosts",
        json={"name": "node-1", "address": "192.0.2.10"},
        headers={"X-CSRF-Token": login.json()["csrf_token"]},
    )
    assert response.status_code == 201


def test_rbac_blocks_viewer_mutation(client: TestClient) -> None:
    with SessionLocal() as db:
        db.add(
            User(
                email="viewer@example.test",
                password_hash=hash_password("correct-horse-battery-staple"),
                role=Role.viewer.value,
            )
        )
        db.commit()
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@example.test", "password": "correct-horse-battery-staple"},
    )
    response = client.post(
        "/api/v1/hosts",
        json={"name": "node-1", "address": "192.0.2.10"},
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    assert response.status_code == 403


def test_login_rate_limit(client: TestClient, owner: User) -> None:
    for _ in range(5):
        response = client.post(
            "/api/v1/auth/login",
            json={"email": owner.email, "password": "incorrect-password"},
        )
        assert response.status_code == 401
    response = client.post(
        "/api/v1/auth/login",
        json={"email": owner.email, "password": "incorrect-password"},
    )
    assert response.status_code == 429
