from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from typing import Any, Literal

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
    labels: dict[str, str] = Field(default_factory=dict)

    @field_validator("labels")
    @classmethod
    def validate_labels(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 32 or any(len(k) > 64 or len(v) > 128 for k, v in value.items()):
            raise ValueError("labels exceed limits")
        return value


class HostView(ORMModel):
    id: str
    name: str
    address: str
    os_name: str | None
    location: str | None
    status: str
    labels: dict[str, str]
    last_seen_at: datetime | None


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
