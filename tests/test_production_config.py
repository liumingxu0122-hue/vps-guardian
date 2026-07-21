from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from guardian.config import Settings
from pydantic import ValidationError


@pytest.fixture(autouse=True)
def clear_legacy_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GUARDIAN_DATABASE_URL", raising=False)


def production_values(tmp_path: Path) -> dict[str, object]:
    key_file = tmp_path / "controller.pem"
    key_file.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    database_url_file = tmp_path / "database-url"
    database_url_file.write_text(
        "postgresql+psycopg://guardian@example/guardian\n", encoding="utf-8"
    )
    return {
        "environment": "production",
        "database_url_file": database_url_file,
        "jwt_secret": "j" * 48,
        "field_encryption_key": Fernet.generate_key().decode(),
        "agent_enrollment_token": "e" * 48,
        "trusted_proxy_cert_header_secret": "p" * 48,
        "controller_signing_key_file": key_file,
        "secure_cookies": True,
        "auto_create_schema": False,
        "allowed_origins": ["https://guardian.example.test"],
        "trusted_hosts": ["guardian.example.test", "agent.guardian.example.test"],
    }


def test_secure_production_configuration_is_accepted(tmp_path: Path) -> None:
    settings = Settings(**production_values(tmp_path))  # type: ignore[arg-type]
    assert settings.environment == "production"


def test_production_compose_requires_prebuilt_immutable_application_images() -> None:
    override = (Path(__file__).parents[1] / "deploy" / "production.compose.yml").read_text(
        encoding="utf-8"
    )
    environment = (
        Path(__file__).parents[1] / "deploy" / "production.env.example"
    ).read_text(encoding="utf-8")

    for variable in (
        "VPS_GUARDIAN_CONTROLLER_IMAGE",
        "VPS_GUARDIAN_BACKUP_IMAGE",
        "VPS_GUARDIAN_WEB_IMAGE",
    ):
        assert f"${{{variable}:?" in override
        assert f"{variable}=registry.example.com/" in environment
    assert override.count("build: !reset null") == 4
    assert "@sha256:" in environment


def test_controlled_database_url_is_the_validated_production_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url_file = tmp_path / "database-url"
    controlled_url = "postgresql+psycopg://guardian@database/guardian"
    monkeypatch.setattr(
        "guardian.backup.read_controlled_secret_file",
        lambda path, **_: controlled_url if path == database_url_file else "",
    )
    values = production_values(tmp_path)
    values["database_url_file"] = database_url_file

    settings = Settings(**values)  # type: ignore[arg-type]

    assert settings.database_url == controlled_url


def test_controlled_database_url_rejects_a_conflicting_legacy_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url_file = tmp_path / "database-url"
    controlled_url = "postgresql+psycopg://guardian@database/guardian"
    monkeypatch.setattr(
        "guardian.backup.read_controlled_secret_file",
        lambda path, **_: controlled_url if path == database_url_file else "",
    )
    values = production_values(tmp_path)
    values["database_url"] = controlled_url
    values["database_url_file"] = database_url_file

    with pytest.raises(ValidationError, match="must not be set"):
        Settings(**values)  # type: ignore[arg-type]


def test_controlled_database_url_cannot_bypass_the_production_database_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url_file = tmp_path / "database-url"
    monkeypatch.setattr(
        "guardian.backup.read_controlled_secret_file",
        lambda path, **_: "sqlite:///forbidden.db" if path == database_url_file else "",
    )
    values = production_values(tmp_path)
    values["database_url_file"] = database_url_file

    with pytest.raises(ValidationError, match="must use PostgreSQL"):
        Settings(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_enrollment_token", "short"),
        ("trusted_proxy_cert_header_secret", ""),
        ("field_encryption_key", "not-a-fernet-key"),
        ("secure_cookies", False),
        ("auto_create_schema", True),
        ("allowed_origins", ["http://guardian.example.test"]),
        ("trusted_hosts", ["*"]),
        ("database_url", "mysql+pymysql://guardian@example/guardian"),
    ],
)
def test_insecure_production_configuration_is_rejected(
    tmp_path: Path, field: str, value: object
) -> None:
    values = production_values(tmp_path)
    values[field] = value
    with pytest.raises(ValidationError):
        Settings(**values)  # type: ignore[arg-type]
