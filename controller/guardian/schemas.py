from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from guardian.agent_security import normalize_certificate_fingerprint


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=12, max_length=256)
    totp_code: str | None = Field(default=None, pattern=r"^\d{6}$")


class LoginResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth token type, not a secret.
    csrf_token: str
    expires_in: int


class UserView(ORMModel):
    id: str
    email: str
    role: str
    totp_enabled: bool


class HostCreate(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,119}$")
    address: str = Field(min_length=1, max_length=255)
    os_name: str | None = Field(default=None, max_length=120)
    location: str | None = Field(default=None, max_length=120)
    enabled: bool = True
    group_name: str | None = Field(default=None, max_length=120)
    tags: list[str] = Field(default_factory=list, max_length=32)
    labels: dict[str, str] = Field(default_factory=dict)

    @field_validator("labels")
    @classmethod
    def validate_labels(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 32 or any(len(k) > 64 or len(v) > 128 for k, v in value.items()):
            raise ValueError("labels exceed limits")
        return value

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: list[str]) -> list[str]:
        normalized = sorted({item.strip() for item in value if item.strip()})
        if len(normalized) != len(value) or any(len(item) > 64 for item in normalized):
            raise ValueError("tags must be unique non-empty values of at most 64 characters")
        return normalized


class HostUpdate(BaseModel):
    name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,119}$")
    address: str | None = Field(default=None, min_length=1, max_length=255)
    location: str | None = Field(default=None, max_length=120)
    enabled: bool | None = None
    group_name: str | None = Field(default=None, max_length=120)
    tags: list[str] | None = Field(default=None, max_length=32)
    labels: dict[str, str] | None = None

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: list[str] | None) -> list[str] | None:
        return HostCreate.validate_tags(value) if value is not None else None

    @field_validator("labels")
    @classmethod
    def validate_labels(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        return HostCreate.validate_labels(value) if value is not None else None


class HostView(ORMModel):
    id: str
    name: str
    address: str
    os_name: str | None
    location: str | None
    status: str
    data_state: str
    enabled: bool
    group_name: str | None
    tags: list[str]
    labels: dict[str, str]
    last_seen_at: datetime | None
    enrolled_at: datetime | None
    disabled_at: datetime | None


class EnrollmentTokenIssue(BaseModel):
    expires_in_minutes: int = Field(default=15, ge=1, le=1440)


class EnrollmentTokenView(BaseModel):
    token: str
    expires_at: datetime
    install_command: str


class ServiceCheckCreate(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,119}$")
    kind: Literal["http", "https", "tcp", "icmp", "docker", "systemd"]
    enabled: bool = True
    host_id: str | None = Field(default=None, max_length=36)
    runner_agent_id: str | None = Field(default=None, max_length=36)
    configuration: dict[str, Any]
    group_name: str | None = Field(default=None, max_length=120)
    interval_seconds: int = Field(default=60, ge=15, le=86400)
    timeout_seconds: int = Field(default=5, ge=1, le=30)
    failure_threshold: int = Field(default=3, ge=1, le=100)
    recovery_threshold: int = Field(default=2, ge=1, le=100)
    severity: Literal["info", "warning", "critical"] = "warning"

    @field_validator("configuration")
    @classmethod
    def reject_embedded_secrets(cls, value: dict[str, Any]) -> dict[str, Any]:
        forbidden = ("password", "token", "secret", "authorization", "cookie", "api_key")
        for key, item in value.items():
            lowered = key.lower()
            if any(marker in lowered for marker in forbidden):
                raise ValueError(
                    "service check credentials must use a protected external reference"
                )
            if isinstance(item, str) and key in {"target", "url"}:
                parsed = urlsplit(item)
                if parsed.username or parsed.password or parsed.query or parsed.fragment:
                    raise ValueError(
                        "service check URLs cannot contain credentials or query secrets"
                    )
        return value


class ServiceCheckView(ORMModel):
    id: str
    name: str
    kind: str
    enabled: bool
    host_id: str | None
    runner_agent_id: str | None
    configuration: dict[str, Any]
    group_name: str | None
    interval_seconds: int
    timeout_seconds: int
    failure_threshold: int
    recovery_threshold: int
    severity: str
    last_checked_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AlertRuleCreate(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,119}$")
    source_type: Literal["service_check", "host_liveness", "agent_error"]
    source_id: str = Field(min_length=1, max_length=36)
    severity: Literal["info", "warning", "critical"] = "warning"
    group_key: str = Field(default="default", min_length=1, max_length=120)
    failure_threshold: int = Field(default=3, ge=1, le=100)
    recovery_threshold: int = Field(default=2, ge=1, le=100)
    repeat_interval_seconds: int = Field(default=3600, ge=60, le=604800)
    escalation_after_seconds: int | None = Field(default=None, ge=60, le=604800)
    recovery_notifications: bool = True


class AlertRuleView(ORMModel):
    id: str
    name: str
    enabled: bool
    source_type: str
    source_id: str
    severity: str
    group_key: str
    failure_threshold: int
    recovery_threshold: int
    repeat_interval_seconds: int
    escalation_after_seconds: int | None
    recovery_notifications: bool
    created_at: datetime


class AlertView(ORMModel):
    id: str
    rule_id: str
    fingerprint: str
    state: str
    consecutive_failures: int
    consecutive_successes: int
    first_observed_at: datetime
    last_observed_at: datetime
    fired_at: datetime | None
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    silenced_until: datetime | None
    resolved_at: datetime | None
    last_notified_at: datetime | None
    notification_count: int
    summary: str
    details: dict[str, Any]


class AlertSilenceRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=255)
    until: datetime

    @field_validator("until")
    @classmethod
    def require_aware_until(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("silence expiry must include a UTC offset")
        return value.astimezone(UTC)


class NotificationChannelCreate(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,119}$")
    kind: Literal["telegram", "smtp", "webhook"]
    enabled: bool = True
    configuration: dict[str, str]
    rate_limit_per_minute: int = Field(default=30, ge=1, le=600)

    @field_validator("configuration")
    @classmethod
    def require_external_secret_references(cls, value: dict[str, str]) -> dict[str, str]:
        if not value or any(not key.endswith(("_env", "_file")) for key in value):
            raise ValueError(
                "notification configuration accepts only environment or file references"
            )
        if any(not item or "\x00" in item or len(item) > 255 for item in value.values()):
            raise ValueError("notification secret reference is invalid")
        return value


class NotificationChannelView(ORMModel):
    id: str
    name: str
    kind: str
    enabled: bool
    configuration: dict[str, Any]
    rate_limit_per_minute: int
    created_at: datetime


class IncidentView(ORMModel):
    id: str
    title: str
    fault_type: str
    severity: int
    status: str
    confidence: float
    affected_hosts: list[str]
    affected_services: list[str]
    evidence: list[dict[str, Any]]
    excluded_causes: list[str]
    recommendations: list[str]
    auto_repair_allowed: bool
    risk: str
    verification_plan: list[str]
    first_seen_at: datetime
    resolved_at: datetime | None
    timeline: list[dict[str, Any]]


class ApprovalView(ORMModel):
    id: str
    incident_id: str
    action_name: str
    risk_level: int
    status: str
    parameters: dict[str, Any]
    impact: dict[str, Any]
    recovery_point_id: str | None
    rollback_plan: list[str]
    requested_at: datetime
    expires_at: datetime
    decided_at: datetime | None
    decided_by: str | None
    requested_by: str | None
    target_host_id: str | None


class ApprovalDecision(BaseModel):
    decision: Literal["approved", "rejected", "dry_run_only"]
    confirmation: str = Field(min_length=3, max_length=255)


class AuditView(ORMModel):
    id: int
    actor_id: str | None
    action: str
    resource_type: str
    resource_id: str | None
    outcome: str
    details: dict[str, Any]
    source_ip: str | None
    created_at: datetime


class RecoveryPointView(ORMModel):
    id: str
    host_id: str
    service_name: str
    snapshot_id: str
    manifest: dict[str, Any]
    checksum: str
    verified: bool
    verified_at: datetime | None
    verification_version: int
    attestation_digest: str | None
    created_at: datetime


class RecoveryVerificationAttestationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    verifier: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$")
    verification_method: Literal["isolated_restore"]
    target_environment: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$")
    completed_at: datetime
    evidence_digest: str = Field(pattern=r"^[A-Fa-f0-9]{64}$")

    @field_validator("completed_at")
    @classmethod
    def require_aware_completed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("completed_at must include a UTC offset")
        return value.astimezone(UTC)

    @field_validator("evidence_digest")
    @classmethod
    def normalize_evidence_digest(cls, value: str) -> str:
        return value.lower()


class RecoveryPointVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=0)
    expected_snapshot_id: str = Field(pattern=r"^[A-Fa-f0-9]{64}$")
    expected_checksum: str = Field(pattern=r"^[A-Fa-f0-9]{64}$")
    attestation: RecoveryVerificationAttestationRequest

    @field_validator("expected_snapshot_id", "expected_checksum")
    @classmethod
    def normalize_digest(cls, value: str) -> str:
        return value.lower()


class RecoveryPointPromotionView(BaseModel):
    recovery_point: RecoveryPointView
    promoted: bool
    attestation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class AgentEnrollRequest(BaseModel):
    host: HostCreate
    signing_public_key: str = Field(min_length=40, max_length=512)
    certificate_fingerprint: str = Field(pattern=r"^[A-Fa-f0-9:]{32,128}$")
    version: str = Field(max_length=64)

    @field_validator("certificate_fingerprint")
    @classmethod
    def validate_certificate_fingerprint(cls, value: str) -> str:
        return normalize_certificate_fingerprint(value)

    @field_validator("signing_public_key")
    @classmethod
    def validate_signing_public_key(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("signing public key must be valid base64") from exc
        if len(decoded) != 32:
            raise ValueError("signing public key must contain 32 bytes")
        return value


class AgentEnrollResponse(BaseModel):
    agent_id: str
    host_id: str
    heartbeat_interval_seconds: int = 30


class AgentView(ORMModel):
    id: str
    host_id: str
    identity_version: int
    certificate_fingerprint: str
    certificate_serial: str | None
    revoked_at: datetime | None
    last_heartbeat_at: datetime | None
    version: str | None


class AgentRotateRequest(BaseModel):
    rotation_id: str = Field(
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    )
    expected_version: int = Field(ge=1)
    signing_public_key: str = Field(min_length=40, max_length=512)
    certificate_fingerprint: str = Field(pattern=r"^[A-Fa-f0-9:]{32,128}$")
    certificate_serial: str = Field(pattern=r"^[A-Fa-f0-9]{1,128}$")

    @field_validator("certificate_fingerprint")
    @classmethod
    def validate_certificate_fingerprint(cls, value: str) -> str:
        return AgentEnrollRequest.validate_certificate_fingerprint(value)

    @field_validator("signing_public_key")
    @classmethod
    def validate_signing_public_key(cls, value: str) -> str:
        return AgentEnrollRequest.validate_signing_public_key(value)


class AgentIdentityView(ORMModel):
    id: str
    agent_id: str
    generation: int
    rotation_id: str | None
    state: Literal["pending", "active", "retiring", "revoked", "retired"]
    certificate_fingerprint: str
    certificate_serial: str | None
    expires_at: datetime | None
    verified_at: datetime | None
    successful_heartbeats: int
    last_pending_heartbeat_at: datetime | None
    activated_at: datetime | None
    retiring_at: datetime | None
    revoked_at: datetime | None
    retired_at: datetime | None
    created_at: datetime


class AgentIdentityActivateRequest(BaseModel):
    expected_version: int = Field(ge=1)


class AgentIdentityRetireRequest(BaseModel):
    expected_version: int = Field(ge=1)
    reason_code: str = Field(pattern=r"^[a-z0-9_.-]{3,64}$")


class AgentIdentityRevokeRequest(BaseModel):
    expected_version: int = Field(ge=1)
    crl_number: int = Field(ge=1)
    crl_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class AgentIdentityValidateRequest(BaseModel):
    expected_version: int = Field(ge=1)


class AgentHeartbeat(BaseModel):
    collected_at: datetime
    version: str = Field(max_length=64)
    metrics: dict[str, Any]
    services: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    events: list[dict[str, Any]] = Field(default_factory=list, max_length=500)


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    version: str
