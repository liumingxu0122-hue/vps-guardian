# Test configuration must be established before importing the application.
# ruff: noqa: E402

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import certifi

os.environ["GUARDIAN_ENVIRONMENT"] = "test"
os.environ["GUARDIAN_DATABASE_URL"] = "sqlite://"
os.environ["GUARDIAN_JWT_SECRET"] = "test-jwt-secret-that-is-longer-than-32-bytes"
os.environ["GUARDIAN_AGENT_ENROLLMENT_TOKEN"] = "test-enrollment-token"
os.environ["GUARDIAN_AUTO_CREATE_SCHEMA"] = "true"
os.environ["GUARDIAN_SECURE_COOKIES"] = "false"
os.environ["GUARDIAN_ONE_COMMAND_INSTALL_ENABLED"] = "true"
os.environ["GUARDIAN_AGENT_INSTALL_RELEASE_VERSION"] = "v0.4.0-test"
os.environ["GUARDIAN_AGENT_INSTALL_ASSETS_BASE_URL"] = (
    "https://releases.example.test/vps-guardian"
)
os.environ["GUARDIAN_AGENT_INSTALLER_SHA256"] = "1" * 64
os.environ["GUARDIAN_AGENT_MAINTENANCE_SCRIPT_SHA256"] = "6" * 64
os.environ["GUARDIAN_AGENT_BINARY_AMD64_SHA256"] = "2" * 64
os.environ["GUARDIAN_AGENT_BINARY_ARM64_SHA256"] = "3" * 64
os.environ["GUARDIAN_AGENT_ENROLLMENT_HTTPS_CA_BUNDLE_URL"] = (
    "https://controller.example.test/assets/enrollment-https-ca-bundle.pem"
)
test_https_ca_bundle = Path(certifi.where())
os.environ["GUARDIAN_AGENT_ENROLLMENT_HTTPS_CA_BUNDLE_FILE"] = str(
    test_https_ca_bundle
)
os.environ["GUARDIAN_AGENT_ENROLLMENT_HTTPS_CA_BUNDLE_SHA256"] = hashlib.sha256(
    test_https_ca_bundle.read_bytes()
).hexdigest()
os.environ["GUARDIAN_AGENT_CONTROLLER_PUBLIC_KEY_URL"] = (
    "https://controller.example.test/assets/controller-ed25519.pub"
)
os.environ["GUARDIAN_AGENT_CONTROLLER_PUBLIC_KEY_SHA256"] = "5" * 64
os.environ["GUARDIAN_AGENT_RELEASE_MANIFEST_URL"] = (
    "https://releases.example.test/vps-guardian/v0.4.0-test/SHA256SUMS"
)
os.environ["GUARDIAN_AGENT_RELEASE_MANIFEST_SIGNATURE_URL"] = (
    "https://releases.example.test/vps-guardian/v0.4.0-test/SHA256SUMS.sig"
)
os.environ["GUARDIAN_AGENT_RELEASE_SIGNING_PUBLIC_KEY_URL"] = (
    "https://releases.example.test/vps-guardian/release-signing-ed25519.pem"
)
os.environ["GUARDIAN_AGENT_RELEASE_SIGNING_PUBLIC_KEY_SHA256"] = "7" * 64

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
