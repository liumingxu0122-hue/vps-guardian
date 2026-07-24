from __future__ import annotations

import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from guardian.config import Settings, get_settings
from guardian.database import SessionLocal
from guardian.main import app
from guardian.models import Host, MetricSnapshot
from guardian.security import PUBLIC_ANONYMOUS_ROUTES
from pydantic import ValidationError


def anonymous_staging_settings() -> Settings:
    return Settings(
        environment="test",
        deployment_stage="staging",
        production_deployed=False,
        anonymous_read_only=True,
    )


@pytest.fixture
def anonymous_staging() -> None:
    app.dependency_overrides[get_settings] = anonymous_staging_settings
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_settings, None)


def seed_public_host() -> None:
    with SessionLocal() as db:
        host = Host(
            name="staging-node",
            address="10.20.30.40",
            os_name="Secret Linux",
            location="Hong Kong",
            status="healthy",
            data_state="normal",
            enabled=True,
            group_name="internal-control-plane",
            tags=["private"],
            labels={"internal": "do-not-publish"},
            last_seen_at=datetime.now(UTC),
        )
        db.add(host)
        db.flush()
        db.add(
            MetricSnapshot(
                host_id=host.id,
                collected_at=datetime.now(UTC),
                payload={
                    "cpu_percent": 12.5,
                    "memory_percent": 34.5,
                    "disk_percent": 56.5,
                    "secret": "never-publish",
                    "_services": [{"summary": "internal service"}],
                },
            )
        )
        db.commit()


def test_public_route_allowlist_is_exact() -> None:
    assert PUBLIC_ANONYMOUS_ROUTES == {
        (method, path)
        for path in (
            "/api/v1/public/session",
            "/api/v1/public/overview",
            "/api/v1/public/hosts",
        )
        for method in ("GET", "HEAD", "OPTIONS")
    }


def test_public_mode_is_hidden_when_disabled(client: TestClient) -> None:
    assert client.get("/api/v1/public/session").status_code == 404


def test_public_session_ignores_unrelated_cookies(
    client: TestClient, anonymous_staging: None
) -> None:
    response = client.get(
        "/api/v1/public/session",
        cookies={"guardian_locale": "zh-CN", "guardian_theme": "dark", "other": "value"},
    )
    assert response.status_code == 200
    assert response.json() == {
        "mode": "anonymous_read_only",
        "deployment_stage": "staging",
    }
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "headers",
    [
        {"Authorization": "Bearer invalid"},
        {"Authorization": "Bearer expired.invalid.token"},
    ],
)
def test_invalid_bearer_never_downgrades_to_public(
    client: TestClient,
    anonymous_staging: None,
    headers: dict[str, str],
) -> None:
    response = client.get("/api/v1/public/session", headers=headers)
    assert response.status_code == 401


def test_invalid_authentication_cookie_never_downgrades_to_public(
    client: TestClient, anonymous_staging: None
) -> None:
    response = client.get(
        "/api/v1/public/session",
        cookies={
            "guardian_session": "invalid",
            "guardian_locale": "en-US",
            "guardian_theme": "light",
        },
    )
    assert response.status_code == 401


def test_valid_bearer_can_read_the_public_projection(
    client: TestClient, anonymous_staging: None, owner_token: str
) -> None:
    response = client.get(
        "/api/v1/public/session",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert response.status_code == 200


def test_public_dtos_are_explicit_allowlists(
    client: TestClient, anonymous_staging: None
) -> None:
    seed_public_host()

    hosts = client.get("/api/v1/public/hosts")
    assert hosts.status_code == 200
    assert hosts.headers["cache-control"] == "no-store"
    assert len(hosts.json()) == 1
    host = hosts.json()[0]
    assert set(host) == {
        "name",
        "location",
        "status",
        "data_state",
        "last_seen_at",
        "resources",
    }
    assert set(host["resources"]) == {
        "cpu_percent",
        "memory_percent",
        "disk_percent",
        "collected_at",
    }
    serialized = hosts.text
    for forbidden in (
        "10.20.30.40",
        "Secret Linux",
        "internal-control-plane",
        "do-not-publish",
        "never-publish",
        "internal service",
    ):
        assert forbidden not in serialized

    overview = client.get("/api/v1/public/overview")
    assert overview.status_code == 200
    assert set(overview.json()) == {
        "generated_at",
        "global_health",
        "hosts",
        "host_rows",
    }
    assert set(overview.json()["hosts"]) == {
        "total",
        "healthy",
        "degraded",
        "offline",
        "unknown",
    }


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/auth/me",
        "/api/v1/hosts",
        "/api/v1/overview",
        "/api/v1/services",
        "/api/v1/service-checks",
        "/api/v1/alerts",
        "/api/v1/incidents",
        "/api/v1/approvals",
        "/api/v1/audit",
        "/api/v1/recovery-points",
        "/api/v1/settings/public",
        "/api/v1/agents",
        "/api/v1/events",
    ],
)
def test_existing_read_routes_remain_authenticated(
    client: TestClient, anonymous_staging: None, path: str
) -> None:
    assert client.get(path).status_code == 401


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("post", "/api/v1/hosts"),
        ("patch", "/api/v1/hosts/not-a-host"),
        ("delete", "/api/v1/hosts/not-a-host"),
        ("post", "/api/v1/service-checks"),
        ("post", "/api/v1/alerts/not-an-alert/acknowledge"),
        ("post", "/api/v1/approvals/not-an-approval/decision"),
        ("post", "/api/v1/recovery-points/not-a-point/verify"),
    ],
)
def test_existing_write_routes_remain_authenticated(
    client: TestClient,
    anonymous_staging: None,
    method: str,
    path: str,
) -> None:
    response = client.request(method.upper(), path, json={})
    assert response.status_code == 401


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/public/session",
        "/api/v1/public/overview",
        "/api/v1/public/hosts",
    ],
)
def test_public_method_boundary(
    client: TestClient, anonymous_staging: None, path: str
) -> None:
    assert client.head(path).status_code == 200
    assert client.options(path).status_code == 204
    assert client.post(path, json={}).status_code == 405


@pytest.mark.parametrize("stage", ["development", "test", "production"])
def test_anonymous_mode_is_rejected_outside_staging(stage: str) -> None:
    with pytest.raises(ValidationError, match="restricted to staging"):
        Settings(
            environment="test",
            deployment_stage=stage,
            production_deployed=False,
            anonymous_read_only=True,
        )


def test_anonymous_mode_is_rejected_when_production_is_deployed() -> None:
    with pytest.raises(ValidationError, match="forbidden when production is deployed"):
        Settings(
            environment="test",
            deployment_stage="staging",
            production_deployed=True,
            anonymous_read_only=True,
        )


def test_invalid_anonymous_configuration_refuses_application_startup() -> None:
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": str(Path(__file__).parents[1] / "controller"),
            "GUARDIAN_ENVIRONMENT": "test",
            "GUARDIAN_DATABASE_URL": "sqlite://",
            "GUARDIAN_DEPLOYMENT_STAGE": "production",
            "GUARDIAN_PRODUCTION_DEPLOYED": "false",
            "GUARDIAN_ANONYMOUS_READ_ONLY": "true",
        }
    )
    result = subprocess.run(
        [sys.executable, "-c", "import guardian.main"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=30,
    )
    assert result.returncode != 0
    assert "GUARDIAN_ANONYMOUS_READ_ONLY is restricted to staging" in result.stderr


def test_compose_defaults_fail_closed_and_forward_public_settings() -> None:
    root = Path(__file__).parents[1]
    environment = (root / ".env.example").read_text(encoding="utf-8")
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")

    assert "GUARDIAN_DEPLOYMENT_STAGE=production" in environment
    assert "GUARDIAN_PRODUCTION_DEPLOYED=false" in environment
    assert "GUARDIAN_ANONYMOUS_READ_ONLY=false" in environment
    assert (
        "GUARDIAN_DEPLOYMENT_STAGE: ${GUARDIAN_DEPLOYMENT_STAGE:-production}" in compose
    )
    assert (
        "GUARDIAN_PRODUCTION_DEPLOYED: ${GUARDIAN_PRODUCTION_DEPLOYED:-false}" in compose
    )
    assert (
        "GUARDIAN_ANONYMOUS_READ_ONLY: ${GUARDIAN_ANONYMOUS_READ_ONLY:-false}" in compose
    )
