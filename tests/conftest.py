from __future__ import annotations

import os

os.environ["GUARDIAN_ENVIRONMENT"] = "test"
os.environ["GUARDIAN_DATABASE_URL"] = "sqlite://"
os.environ["GUARDIAN_JWT_SECRET"] = "test-jwt-secret-that-is-longer-than-32-bytes"
os.environ["GUARDIAN_AGENT_ENROLLMENT_TOKEN"] = "test-enrollment-token"
os.environ["GUARDIAN_AUTO_CREATE_SCHEMA"] = "true"
os.environ["GUARDIAN_SECURE_COOKIES"] = "false"

import pytest
from fastapi.testclient import TestClient
from guardian.database import Base, SessionLocal, engine
from guardian.enrollment import enrollment_limiter
from guardian.main import app
from guardian.models import Role, User
from guardian.security import hash_password, login_limiter


@pytest.fixture(autouse=True)
def clean_database():  # type: ignore[no-untyped-def]
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    login_limiter._attempts.clear()
    enrollment_limiter.clear()
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def owner() -> User:
    with SessionLocal() as db:
        user = User(
            email="owner@example.test",
            password_hash=hash_password("correct-horse-battery-staple"),
            role=Role.owner.value,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user


@pytest.fixture
def owner_token(client: TestClient, owner: User) -> str:
    response = client.post(
        "/api/v1/auth/login",
        json={"email": owner.email, "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 200
    return str(response.json()["access_token"])
