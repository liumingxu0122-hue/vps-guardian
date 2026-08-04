from __future__ import annotations

import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from cryptography.fernet import Fernet
from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _validate_agent_gateway_url(value: str) -> None:
    """Validate the gateway origin without importing model-dependent PKI code."""
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Agent gateway URL must be an HTTPS origin")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ValueError("Agent gateway URL must not include a path, query, or fragment")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="GUARDIAN_",
        case_sensitive=False,
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./controller/data/guardian.db"
    database_url_file: Path | None = None
    jwt_secret: SecretStr = SecretStr("development-only-change-me-32-bytes")
    jwt_ttl_minutes: int = Field(default=30, ge=5, le=1440)
    session_default_idle_hours: int = Field(default=12, ge=1, le=168)
    session_default_absolute_days: int = Field(default=7, ge=1, le=90)
    session_remember_idle_days: int = Field(default=7, ge=1, le=30)
    session_remember_absolute_days: int = Field(default=30, ge=1, le=90)
    session_activity_touch_interval_seconds: int = Field(default=300, ge=1, le=3600)
    session_step_up_minutes: int = Field(default=10, ge=1, le=30)
    field_encryption_key: SecretStr = SecretStr("")
    agent_enrollment_token: SecretStr = SecretStr("development-enrollment-token")
    controller_signing_key_file: Path = Path("./secrets/controller-ed25519.pem")
    runbook_directory: Path = Path("./runbooks")
    allowed_origins: list[str] = ["http://localhost:5173"]
    trusted_hosts: list[str] = ["localhost", "127.0.0.1", "testserver"]
    trusted_proxy_cert_header_secret: SecretStr = SecretStr("")
    auto_create_schema: bool = True
    secure_cookies: bool = False
    log_level: str = "INFO"
    max_incident_log_bytes: int = Field(default=2_000_000, ge=10_000, le=20_000_000)
    login_attempts_per_10m: int = Field(default=5, ge=2, le=20)
    nonce_ttl_seconds: int = Field(default=300, ge=30, le=3600)
    agent_offline_after_seconds: int = Field(default=90, ge=60, le=3600)
    metric_retention_days: int = Field(default=7, ge=1, le=365)
    service_result_retention_days: int = Field(default=30, ge=1, le=365)
    max_metric_rows_per_host: int = Field(default=10_080, ge=120, le=1_000_000)
    max_results_per_check: int = Field(default=43_200, ge=120, le=1_000_000)
    external_notifications_enabled: bool = False
    agent_pending_identity_ttl_minutes: int = Field(default=15, ge=5, le=60)
    agent_certificate_ttl_hours: int = Field(default=720, ge=24, le=2160)
    agent_ca_certificate_file: Path = Path("./secrets/pki/agent-ca.crt")
    agent_ca_private_key_file: Path = Path("./secrets/pki/private/agent-ca.key")
    agent_gateway_url: str = "https://agents.guardian.example.com"
    enrollment_attempts_per_10m: int = Field(default=10, ge=2, le=100)
    one_command_install_enabled: bool = False
    agent_install_release_version: str = Field(
        default="v0.4.0-alpha.1", pattern=r"^v[A-Za-z0-9._-]{1,63}$"
    )
    agent_install_assets_base_url: str = (
        "https://github.com/liumingxu0122-hue/vps-guardian/releases/download"
    )
    agent_installer_sha256: str = Field(default="", max_length=64)
    agent_maintenance_script_sha256: str = Field(default="", max_length=64)
    agent_binary_amd64_sha256: str = Field(default="", max_length=64)
    agent_binary_arm64_sha256: str = Field(default="", max_length=64)
    agent_release_manifest_url: str = (
        "https://github.com/liumingxu0122-hue/vps-guardian/releases/download/"
        "v0.4.0-alpha.1/vps-guardian-install-manifest-v0.4.0-alpha.1.txt"
    )
    agent_release_manifest_signature_url: str = (
        "https://github.com/liumingxu0122-hue/vps-guardian/releases/download/"
        "v0.4.0-alpha.1/vps-guardian-install-manifest-v0.4.0-alpha.1.txt.sig"
    )
    agent_release_signing_public_key_url: str = (
        "https://github.com/liumingxu0122-hue/vps-guardian/releases/download/"
        "v0.4.0-alpha.1/vps-guardian-release-signing-key-v0.4.0-alpha.1.pem"
    )
    agent_release_signing_public_key_sha256: str = Field(
        default="c9fe05398821dc580aaebcda4cea64f7bf9c998dc59c898b4fcdf79aacec37b4",
        max_length=64,
    )
    agent_release_signing_key_id: str = Field(
        default=(
            "ed25519-sha256:"
            "3e3d878e37f3ababd96827441be8dae17bb397b8012e8f7de65331f2356e524a"
        ),
        pattern=r"^ed25519-sha256:[a-f0-9]{64}$",
    )
    agent_enrollment_https_ca_bundle_url: str = (
        "https://downloads.example.com/enrollment-https-ca-bundle.pem"
    )
    agent_enrollment_https_ca_bundle_file: Path = Path(
        "/run/public/enrollment-https-ca-bundle.pem"
    )
    agent_enrollment_https_ca_bundle_sha256: str = Field(default="", max_length=64)
    agent_controller_public_key_url: str = (
        "https://downloads.example.com/controller-public-key.txt"
    )
    agent_controller_public_key_sha256: str = Field(default="", max_length=64)
    approval_ttl_minutes: int = Field(default=30, ge=5, le=1440)
    deployment_stage: Literal["development", "test", "staging", "production"] = "development"
    production_deployed: bool = False
    operations_gate_decision: str = Field(default="not_assessed", max_length=160)
    operations_rpo_seconds: int | None = Field(default=None, ge=0, le=86400)
    operations_rto_seconds: int | None = Field(default=None, ge=0, le=86400)
    operations_accepted_snapshot: str = Field(default="", max_length=128)
    operations_snapshot_count: int | None = Field(default=None, ge=0, le=1_000_000)
    operations_backup_status: Literal["healthy", "degraded", "unknown"] = "unknown"
    operations_backup_checked_at: datetime | None = None
    operations_restore_status: Literal["passed", "failed", "unknown"] = "unknown"
    operations_retention_policy: str = Field(default="not_configured", max_length=160)
    operations_security_scan_at: datetime | None = None
    operations_uncovered_critical: int | None = Field(default=None, ge=0, le=1_000_000)
    operations_uncovered_high: int | None = Field(default=None, ge=0, le=1_000_000)
    release_version: str = Field(default="0.4.0-alpha.1", max_length=64)
    deployment_commit: str = Field(default="unknown", max_length=64)
    deployed_at: datetime | None = None

    @model_validator(mode="after")
    def validate_production_secrets(self) -> Settings:
        default_idle_seconds = self.session_default_idle_hours * 3600
        default_absolute_seconds = self.session_default_absolute_days * 86400
        remember_idle_seconds = self.session_remember_idle_days * 86400
        remember_absolute_seconds = self.session_remember_absolute_days * 86400
        if default_idle_seconds > default_absolute_seconds:
            raise ValueError(
                "GUARDIAN_SESSION_DEFAULT_IDLE_HOURS must not exceed "
                "GUARDIAN_SESSION_DEFAULT_ABSOLUTE_DAYS"
            )
        if remember_idle_seconds > remember_absolute_seconds:
            raise ValueError(
                "GUARDIAN_SESSION_REMEMBER_IDLE_DAYS must not exceed "
                "GUARDIAN_SESSION_REMEMBER_ABSOLUTE_DAYS"
            )
        if remember_absolute_seconds < default_absolute_seconds:
            raise ValueError(
                "GUARDIAN_SESSION_REMEMBER_ABSOLUTE_DAYS must not be shorter than "
                "GUARDIAN_SESSION_DEFAULT_ABSOLUTE_DAYS"
            )
        if self.one_command_install_enabled:
            urls = (
                self.agent_install_assets_base_url,
                self.agent_enrollment_https_ca_bundle_url,
                self.agent_controller_public_key_url,
                self.agent_release_manifest_url,
                self.agent_release_manifest_signature_url,
                self.agent_release_signing_public_key_url,
            )
            for value in urls:
                parsed = urlparse(value)
                if (
                    parsed.scheme != "https"
                    or not parsed.hostname
                    or parsed.username
                    or parsed.password
                    or parsed.query
                    or parsed.fragment
                ):
                    raise ValueError(
                        "one-command Agent installation URLs must be credential-free HTTPS URLs"
                    )
            hashes = (
                self.agent_installer_sha256,
                self.agent_maintenance_script_sha256,
                self.agent_binary_amd64_sha256,
                self.agent_binary_arm64_sha256,
                self.agent_enrollment_https_ca_bundle_sha256,
                self.agent_controller_public_key_sha256,
                self.agent_release_signing_public_key_sha256,
            )
            if any(
                not re.fullmatch(r"[a-f0-9]{64}", value)
                or value in {"0" * 64, "a" * 64}
                for value in hashes
            ):
                raise ValueError(
                    "one-command Agent installation requires non-placeholder SHA-256 values"
                )
        if self.production_deployed:
            if self.environment != "production" or self.deployment_stage != "production":
                raise ValueError(
                    "production deployment requires both secure runtime and production stage"
                )
            if self.operations_gate_decision != "approved_for_production":
                raise ValueError(
                    "production deployment requires an explicit approved production gate"
                )
            if not re.fullmatch(
                r"[0-9a-f]{40}", self.deployment_commit
            ) or self.deployment_commit == "0" * 40:
                raise ValueError(
                    "production deployment requires an immutable 40-character commit"
                )
        if self.environment == "production":
            if self.database_url_file is None:
                raise ValueError("GUARDIAN_DATABASE_URL_FILE is required in production")
            if "database_url" in self.model_fields_set:
                raise ValueError(
                    "GUARDIAN_DATABASE_URL must not be set when production uses the controlled file"
                )
        if self.database_url_file is not None:
            from guardian.backup import read_controlled_secret_file

            database_url = read_controlled_secret_file(
                self.database_url_file,
                label="database URL",
            )
            if "database_url" in self.model_fields_set and self.database_url != database_url:
                raise ValueError(
                    "GUARDIAN_DATABASE_URL must match the controlled database URL file"
                )
            object.__setattr__(self, "database_url", database_url)
        if self.environment != "production":
            return self
        if len(self.jwt_secret.get_secret_value()) < 32:
            raise ValueError("GUARDIAN_JWT_SECRET must contain at least 32 characters")
        if not self.field_encryption_key.get_secret_value():
            raise ValueError("GUARDIAN_FIELD_ENCRYPTION_KEY is required in production")
        try:
            Fernet(self.field_encryption_key.get_secret_value().encode())
        except (TypeError, ValueError) as exc:
            raise ValueError("GUARDIAN_FIELD_ENCRYPTION_KEY must be a valid Fernet key") from exc
        if len(self.agent_enrollment_token.get_secret_value()) < 32:
            raise ValueError("GUARDIAN_AGENT_ENROLLMENT_TOKEN must contain at least 32 characters")
        if len(self.trusted_proxy_cert_header_secret.get_secret_value()) < 32:
            raise ValueError(
                "GUARDIAN_TRUSTED_PROXY_CERT_HEADER_SECRET must contain at least 32 characters"
            )
        if not self.secure_cookies:
            raise ValueError("GUARDIAN_SECURE_COOKIES must be true in production")
        if self.auto_create_schema:
            raise ValueError(
                "Run Alembic explicitly; auto schema creation is forbidden in production"
            )
        if not self.database_url.startswith(("postgresql://", "postgresql+psycopg://")):
            raise ValueError("production Controller database must use PostgreSQL")
        if not self.controller_signing_key_file.is_file():
            raise ValueError("GUARDIAN_CONTROLLER_SIGNING_KEY_FILE is missing")
        if not self.agent_ca_certificate_file.is_file():
            raise ValueError("GUARDIAN_AGENT_CA_CERTIFICATE_FILE is missing")
        if not self.agent_ca_private_key_file.is_file():
            raise ValueError("GUARDIAN_AGENT_CA_PRIVATE_KEY_FILE is missing")
        _validate_agent_gateway_url(self.agent_gateway_url)
        if not self.runbook_directory.is_dir():
            raise ValueError("GUARDIAN_RUNBOOK_DIRECTORY is missing")
        if any(not origin.startswith("https://") for origin in self.allowed_origins):
            raise ValueError("GUARDIAN_ALLOWED_ORIGINS must use HTTPS in production")
        if "*" in self.trusted_hosts:
            raise ValueError("wildcard trusted hosts are forbidden in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
