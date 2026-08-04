from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from guardian.agent_security import normalize_certificate_fingerprint


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


def validate_password_strength(value: str) -> str:
    if len(set(value)) < 8 or value.casefold() in {
        "passwordpassword",
        "correcthorsebatterystaple",
    }:
        raise ValueError("password does not meet the passphrase strength policy")
    if any(ord(character) < 32 for character in value):
        raise ValueError("password contains control characters")
    return value


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=12, max_length=256)
    totp_code: str | None = Field(default=None, pattern=r"^\d{6}$")
    recovery_code: str | None = Field(
        default=None, min_length=16, max_length=32, pattern=r"^[A-Za-z0-9-]+$"
    )


class LoginResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth token type, not a secret.
    csrf_token: str
    expires_in: int
    identity_setup_required: bool
    recovery_codes_remaining: int | None = None


class BrowserLoginRequest(LoginRequest):
    remember_me: bool = False
    device_name: str | None = Field(default=None, max_length=120)


class BrowserLoginResponse(BaseModel):
    identity_setup_required: bool
    recovery_codes_remaining: int | None = None
    remember_me: bool
    idle_expires_at: datetime
    absolute_expires_at: datetime


class StepUpRequest(BaseModel):
    current_password: str = Field(min_length=12, max_length=256)
    totp_code: str | None = Field(default=None, pattern=r"^\d{6}$")


class StepUpView(BaseModel):
    step_up_until: datetime


class SessionDeviceRename(BaseModel):
    device_name: str = Field(min_length=1, max_length=120)


class UserView(ORMModel):
    id: str
    email: str
    role: str
    totp_enabled: bool
    is_active: bool
    scopes: list[str]
    last_login_at: datetime | None
    password_changed_at: datetime | None
    totp_enabled_at: datetime | None
    disabled_at: datetime | None
    must_change_password: bool
    identity_setup_required: bool
    created_by: str | None
    disabled_by: str | None
    created_at: datetime


class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=14, max_length=256)
    role: Literal["viewer", "auditor", "operator", "admin", "owner"] = "viewer"
    scopes: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if "@" not in normalized:
            raise ValueError("email address is invalid")
        return normalized

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return validate_password_strength(value)

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, value: list[str]) -> list[str]:
        normalized = sorted({scope.strip() for scope in value if scope.strip()})
        if len(normalized) != len(value) or any(len(scope) > 80 for scope in normalized):
            raise ValueError("scopes must be unique non-empty values")
        return normalized


class UserUpdate(BaseModel):
    role: Literal["viewer", "auditor", "operator", "admin", "owner"] | None = None
    is_active: bool | None = None
    scopes: list[str] | None = Field(default=None, max_length=32)
    current_password: str = Field(min_length=12, max_length=256)

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, value: list[str] | None) -> list[str] | None:
        return UserCreate.validate_scopes(value) if value is not None else None


class UserPasswordReset(BaseModel):
    current_password: str = Field(min_length=12, max_length=256)
    new_password: str = Field(min_length=14, max_length=256)
    confirmation: Literal["ROTATE USER CREDENTIAL"]

    _validate_password = field_validator("new_password")(validate_password_strength)


class UserDeleteRequest(BaseModel):
    current_password: str = Field(min_length=12, max_length=256)
    confirmation: Literal["DELETE USER"]


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=12, max_length=256)
    new_password: str = Field(min_length=14, max_length=256)
    retain_current_session: Literal[True] = True

    _validate_password = field_validator("new_password")(validate_password_strength)


class ReauthenticationRequest(BaseModel):
    current_password: str = Field(min_length=12, max_length=256)


class TotpConfirmRequest(ReauthenticationRequest):
    totp_code: str = Field(pattern=r"^\d{6}$")


class RecoveryCodesConfirmRequest(BaseModel):
    confirmation: Literal["I SAVED MY RECOVERY CODES"]


class RecoveryCodeBatchView(BaseModel):
    codes: list[str]
    remaining: int
    displayed_once: Literal[True] = True


class TotpSetupView(BaseModel):
    secret: str
    provisioning_uri: str
    displayed_once: Literal[True] = True


class RecoveryCodeStatusView(BaseModel):
    remaining: int
    low: bool


class UserSessionView(ORMModel):
    id: str
    user_id: str
    issued_at: datetime
    expires_at: datetime
    last_seen_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    remember_me: bool
    step_up_until: datetime | None
    revoked_at: datetime | None
    revoke_reason: str | None
    user_agent_summary: str
    ip_summary: str
    created_via: str
    last_activity_type: str | None
    device_name: str | None
    current: bool = False


class HostCreate(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,119}$")
    address: str = Field(default="pending-enrollment", min_length=1, max_length=255)
    os_name: str | None = Field(default=None, max_length=120)
    location: str | None = Field(default=None, max_length=120)
    enabled: bool = True
    group_name: str | None = Field(default=None, max_length=120)
    tags: list[str] = Field(default_factory=list, max_length=32)
    labels: dict[str, str] = Field(default_factory=dict)
    notes: str | None = Field(default=None, max_length=500)
    desired_os_family: Literal[
        "auto", "debian", "rhel", "fedora", "alpine", "generic"
    ] = "auto"

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
    notes: str | None = Field(default=None, max_length=500)
    desired_os_family: Literal[
        "auto", "debian", "rhel", "fedora", "alpine", "generic"
    ] | None = None

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: list[str] | None) -> list[str] | None:
        return HostCreate.validate_tags(value) if value is not None else None

    @field_validator("labels")
    @classmethod
    def validate_labels(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        return HostCreate.validate_labels(value) if value is not None else None


class HostBatchUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host_ids: list[str] = Field(min_length=1, max_length=200)
    enabled: bool | None = None
    group_name: str | None = Field(default=None, max_length=120)
    add_tags: list[str] = Field(default_factory=list, max_length=32)
    remove_tags: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("host_ids")
    @classmethod
    def validate_host_ids(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value) or any(len(item) > 36 for item in value):
            raise ValueError("host_ids must be unique identifiers")
        return value

    @field_validator("add_tags", "remove_tags")
    @classmethod
    def validate_batch_tags(cls, value: list[str]) -> list[str]:
        return HostCreate.validate_tags(value)


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
    notes: str | None
    desired_os_family: str
    last_seen_at: datetime | None
    enrolled_at: datetime | None
    disabled_at: datetime | None


class HostPresentationView(BaseModel):
    """Explicit allowlist for the operator-facing host index."""

    id: str
    name: str
    primary_address: str
    os_name: str | None
    region: str | None
    group: str | None
    provider: str | None
    purpose: str | None
    display_tags: list[str]
    health: Literal["healthy", "degraded", "offline", "unknown"]
    data_state: Literal["normal", "no_data", "stale", "offline", "agent_error"]
    enabled: bool
    management: Literal[
        "guardian_and_komari",
        "guardian",
        "komari_only",
        "pending_enrollment",
    ]
    agent_state: Literal["online", "stale", "never_seen", "revoked", "not_installed"]
    agent_version: str | None
    last_heartbeat_at: datetime | None
    last_seen_at: datetime | None
    enrolled_at: datetime | None
    data_reason: Literal[
        "available",
        "no_guardian_agent",
        "never_connected",
        "pending_enrollment",
        "disabled",
        "stale",
        "agent_error",
    ]
    resource_summary: dict[str, float] | None
    technical_evidence_available: bool


class EnrollmentTokenIssue(BaseModel):
    expires_in_minutes: int = Field(default=10, ge=1, le=1440)
    source_cidr: str | None = Field(default=None, max_length=64)
    os_family: Literal[
        "auto", "debian", "rhel", "fedora", "alpine", "generic"
    ] = "auto"


class EnrollmentTokenView(BaseModel):
    id: str
    host_id: str
    expires_at: datetime
    install_command: str
    status: str


class EnrollmentEventView(BaseModel):
    status: str
    sequence: int
    occurred_at: datetime
    error_code: str | None = None
    error_summary: str | None = None
    rolled_back: bool = False


class EnrollmentSessionView(BaseModel):
    id: str
    host_id: str
    status: str
    sequence: int
    expires_at: datetime
    used_at: datetime | None
    revoked_at: datetime | None
    completed_at: datetime | None
    source_cidr: str | None
    os_family: str
    error_code: str | None
    error_step: str | None
    error_summary: str | None
    rolled_back: bool
    events: list[EnrollmentEventView]


class AgentMaintenanceIssue(BaseModel):
    kind: Literal["repair", "reinstall", "rotate_identity", "decommission"]
    source_cidr: str | None = Field(default=None, max_length=64)
    purge_local_state: bool = False
    approval_id: str | None = Field(default=None, max_length=36)
    confirmation: str | None = Field(default=None, max_length=160)


class AgentMaintenanceTokenView(BaseModel):
    id: str
    host_id: str
    kind: Literal["repair", "reinstall", "rotate_identity", "decommission"]
    expires_at: datetime
    command: str
    status: str


class AgentMaintenanceStart(BaseModel):
    kind: Literal["repair", "reinstall", "rotate_identity", "decommission"]


class AgentMaintenanceStartView(BaseModel):
    session_id: str
    host_id: str
    agent_id: str
    kind: str
    progress_token: str
    expected_identity_version: int
    purge_local_state: bool


class AgentMaintenanceProgress(BaseModel):
    kind: Literal["repair", "reinstall", "rotate_identity", "decommission"]
    status: Literal[
        "artifact_verified",
        "service_stopped",
        "identity_rotated",
        "service_started",
        "heartbeat_verified",
        "confirmation_pending",
        "completed",
        "failed",
        "rolled_back",
    ]
    error_code: str | None = Field(default=None, max_length=64)
    error_summary: str | None = Field(default=None, max_length=240)
    rolled_back: bool = False


class AgentMaintenanceEventView(ORMModel):
    status: str
    status_sequence: int
    occurred_at: datetime
    error_code: str | None
    error_summary: str | None
    rolled_back: bool


class AgentMaintenanceSessionView(ORMModel):
    id: str
    host_id: str
    agent_id: str
    kind: str
    status: str
    status_sequence: int
    source_cidr: str | None
    purge_local_state: bool
    expected_identity_version: int
    old_identity_id: str | None
    new_identity_id: str | None
    approval_id: str | None
    expires_at: datetime
    used_at: datetime | None
    revoked_at: datetime | None
    completed_at: datetime | None
    error_code: str | None
    error_summary: str | None
    rolled_back: bool
    created_at: datetime
    status_updated_at: datetime
    events: list[AgentMaintenanceEventView]


class AgentMaintenanceFinalize(BaseModel):
    confirmation: str = Field(min_length=1, max_length=160)
    expected_identity_version: int = Field(ge=1)
    crl_number: int | None = Field(default=None, ge=1)
    crl_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class EnrollmentProgressReport(BaseModel):
    status: Literal[
        "installer_downloaded",
        "installer_verified",
        "prerequisites_checked",
        "agent_downloaded",
        "agent_verified",
        "local_key_generated",
        "csr_submitted",
        "service_installed",
        "service_started",
        "failed",
    ]
    error_code: str | None = Field(default=None, pattern=r"^[a-z0-9_]{1,64}$")
    error_summary: str | None = Field(default=None, max_length=240)
    rolled_back: bool = False


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


class ServiceCheckUpdate(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = Field(default=None, ge=15, le=86400)


class ServiceCheckResultView(ORMModel):
    id: int
    check_id: str
    status: str
    checked_at: datetime
    latency_ms: float | None
    status_code: int | None
    message: str | None
    details: dict[str, Any]


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
    assigned_to: str | None
    silenced_until: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
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


class AlertUpdateRequest(BaseModel):
    assigned_to: str | None = Field(default=None, max_length=36)
    close: bool = False
    note: str = Field(default="", max_length=500)


class NotificationChannelCreate(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,119}$")
    kind: Literal["telegram", "smtp", "discord", "webhook"]
    enabled: bool = True
    configuration: dict[str, str]
    event_scope: list[str] = Field(default_factory=list, max_length=32)
    severity_filter: list[Literal["info", "warning", "critical"]] = Field(default_factory=list)
    retry_policy: dict[str, int] = Field(default_factory=dict)
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
    event_scope: list[str]
    severity_filter: list[str]
    retry_policy: dict[str, Any]
    rate_limit_per_minute: int
    created_at: datetime


class NotificationDeliveryView(ORMModel):
    id: str
    channel_id: str
    alert_id: str
    event_type: str
    status: str
    attempt_count: int
    next_attempt_at: datetime
    delivered_at: datetime | None
    response_code: int | None
    error_summary: str | None
    created_at: datetime


class IncidentView(ORMModel):
    id: str
    title: str
    fault_type: str
    severity: int
    status: str
    assigned_to: str | None
    acknowledged_at: datetime | None
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
    updated_at: datetime
    resolved_at: datetime | None
    resolution_summary: str | None
    postmortem: str | None
    timeline: list[dict[str, Any]]


class IncidentUpdateRequest(BaseModel):
    status: Literal["open", "acknowledged", "investigating", "mitigating", "resolved"] | None = None
    assigned_to: str | None = Field(default=None, max_length=36)
    note: str = Field(default="", max_length=1000)
    resolution_summary: str | None = Field(default=None, max_length=4000)
    postmortem: str | None = Field(default=None, max_length=20_000)


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


class ApprovalActorView(BaseModel):
    label: str
    role: str | None = None


class ApprovalTargetView(BaseModel):
    host: str | None = None
    service: str | None = None
    scope: str | None = None


class ApprovalFactView(BaseModel):
    key: str
    value: str
    tone: Literal["neutral", "info", "warning", "critical"] = "neutral"


class ApprovalStepView(BaseModel):
    order: int
    action: str
    target: str | None = None
    dry_run: bool = False


class ApprovalTimelineEntryView(BaseModel):
    at: datetime
    event: str
    actor: str | None = None
    outcome: str | None = None


class ApprovalSummaryView(BaseModel):
    id: str
    incident_id: str
    action_name: str
    status: str
    risk_level: int
    target: ApprovalTargetView
    requester: ApprovalActorView | None
    requested_at: datetime
    expires_at: datetime
    progress_label: str
    execution_status: str | None


class ApprovalDetailView(ApprovalSummaryView):
    risk_reason: str
    approver: ApprovalActorView | None
    decided_at: datetime | None
    executed_at: datetime | None
    impact_facts: list[ApprovalFactView]
    steps: list[ApprovalStepView]
    dry_run_available: bool
    dry_run_status: str | None
    recovery_point_label: str | None
    rollback_available: bool
    rollback_steps: list[str]
    timeline: list[ApprovalTimelineEntryView]
    raw_evidence_available: bool


class ApprovalEvidenceView(BaseModel):
    approval_id: str
    parameters: dict[str, Any]
    impact: dict[str, Any]


class ApprovalDecision(BaseModel):
    decision: Literal[
        "approved",
        "approved_with_conditions",
        "changes_requested",
        "rejected",
        "dry_run_only",
    ]
    confirmation: str = Field(min_length=3, max_length=255)
    current_password: str | None = Field(default=None, min_length=12, max_length=256)
    rollback_confirmed: bool = False


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


class AuditPresentationView(BaseModel):
    """Explicit allowlist for the human-readable audit index."""

    event_id: int
    display_action: str
    action_code: str
    category: str
    severity: Literal["neutral", "info", "warning", "critical"]
    result: str
    actor_display: str
    actor_type: Literal["user", "system", "agent", "unknown"]
    resource_display: str
    resource_type: str
    source_display: str
    source_type: Literal["internal_service", "private_network", "external_client", "unknown"]
    created_at: datetime
    summary: str
    correlation_id: str | None
    request_id: str | None
    evidence_available: bool


class AuditEvidenceView(BaseModel):
    """Redacted technical evidence, fetched only after an explicit detail request."""

    audit_id: int
    action_code: str
    resource_type: str
    resource_id: str | None
    actor_id: str | None
    source_ip: str | None
    changes: dict[str, Any]
    correlation_id: str | None


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


class AgentBootstrapRequest(BaseModel):
    host_id: str = Field(min_length=36, max_length=36)
    csr_pem: str = Field(min_length=200, max_length=32768)
    signing_public_key: str = Field(min_length=40, max_length=512)
    signing_key_proof: str = Field(min_length=80, max_length=128)
    version: str = Field(min_length=1, max_length=64)

    @field_validator("signing_public_key")
    @classmethod
    def validate_signing_public_key(cls, value: str) -> str:
        return AgentEnrollRequest.validate_signing_public_key(value)


class AgentBootstrapResponse(BaseModel):
    agent_id: str
    host_id: str
    certificate_pem: str
    agent_mtls_ca_bundle_pem: str
    certificate_serial: str
    certificate_expires_at: datetime
    agent_gateway_endpoint: str
    enrollment_progress_token: str = Field(min_length=32, max_length=512)
    heartbeat_interval_seconds: int = 30


class AgentRenewRequest(BaseModel):
    rotation_id: str = Field(
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    )
    expected_version: int = Field(ge=1)
    csr_pem: str = Field(min_length=200, max_length=32768)
    signing_public_key: str = Field(min_length=40, max_length=512)
    signing_key_proof: str = Field(min_length=80, max_length=128)

    @field_validator("signing_public_key")
    @classmethod
    def validate_signing_public_key(cls, value: str) -> str:
        return AgentEnrollRequest.validate_signing_public_key(value)


class AgentRenewResponse(BaseModel):
    identity: AgentIdentityView
    certificate_pem: str
    agent_mtls_ca_bundle_pem: str
    certificate_expires_at: datetime


class AgentView(ORMModel):
    id: str
    host_id: str
    identity_version: int
    certificate_fingerprint: str
    certificate_serial: str | None
    revoked_at: datetime | None
    last_heartbeat_at: datetime | None
    version: str | None
    build_git_sha: str | None
    build_id: str | None
    build_time: str | None
    go_version: str | None
    platform_os: str | None
    platform_arch: str | None
    build_dirty: bool | None
    binary_sha256: str | None


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


class AgentBuildMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = Field(min_length=1, max_length=64)
    git_sha: str = Field(pattern=r"^(?:unknown|[A-Fa-f0-9]{40})$")
    build_id: str = Field(min_length=1, max_length=128)
    build_time: str = Field(min_length=1, max_length=64)
    go_version: str = Field(pattern=r"^go[0-9A-Za-z.+_-]{1,61}$")
    os: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,31}$")
    arch: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,31}$")
    dirty: bool
    binary_sha256: str = Field(pattern=r"^[A-Fa-f0-9]{64}$")

    @field_validator("git_sha", "binary_sha256")
    @classmethod
    def normalize_digest(cls, value: str) -> str:
        return value.lower()


class PortTrafficObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=36, max_length=36)
    rx_bytes_total: int = Field(ge=0, le=9_223_372_036_854_775_807)
    tx_bytes_total: int = Field(ge=0, le=9_223_372_036_854_775_807)
    combined_bytes_total: int | None = Field(
        default=None, ge=0, le=9_223_372_036_854_775_807
    )
    current_period_rx: int = Field(ge=0, le=9_223_372_036_854_775_807)
    current_period_tx: int = Field(ge=0, le=9_223_372_036_854_775_807)
    current_period_total: int | None = Field(
        default=None, ge=0, le=9_223_372_036_854_775_807
    )
    quota_bytes: int | None = Field(default=None, gt=0)
    quota_percent: float | None = Field(default=None, ge=0)
    quota_state: Literal[
        "unlimited", "normal", "warning", "critical", "exhausted"
    ] | None = None
    reset_policy: dict[str, Any] | None = None
    current_period_start: datetime | None = None
    next_reset_at: datetime | None = None
    last_reset_at: datetime | None = None
    counter_generation: int = Field(ge=1, le=2_147_483_647)
    runtime_rule_state: Literal["active", "missing", "inconsistent", "error"]
    shaping_state: Literal["disabled", "active", "inconsistent", "error"]
    current_egress_rate_bps: int | None = Field(default=None, ge=8_000)
    collected_at: datetime | None = None
    discontinuity_reason: Literal[
        "agent_restart",
        "system_restart",
        "counter_reset",
        "counter_wrap",
        "rule_restore",
        "rule_missing",
    ] | None = None

    @model_validator(mode="after")
    def require_exact_derived_totals(self) -> PortTrafficObservation:
        if (
            self.combined_bytes_total is not None
            and self.combined_bytes_total != self.rx_bytes_total + self.tx_bytes_total
        ):
            raise ValueError("combined_bytes_total must equal RX plus TX")
        if (
            self.current_period_total is not None
            and self.current_period_total
            != self.current_period_rx + self.current_period_tx
        ):
            raise ValueError("current_period_total must equal current-period RX plus TX")
        return self


class AgentHeartbeat(BaseModel):
    collected_at: datetime
    version: str = Field(min_length=1, max_length=64)
    build: AgentBuildMetadata | None = None
    metrics: dict[str, Any]
    services: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    events: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    port_traffic: list[PortTrafficObservation] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def require_consistent_build_version(self) -> AgentHeartbeat:
        if self.build is not None and self.build.version != self.version:
            raise ValueError("Agent build version must match heartbeat version")
        return self


class PortTrafficPolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    protocol: Literal["tcp", "udp", "both"]
    direction: Literal["rx", "tx", "both"]
    port_start: int = Field(ge=1, le=65535)
    port_end: int = Field(ge=1, le=65535)
    interface_name: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,30}$"
    )
    mode: Literal["monitor_only", "enforcing"] = "monitor_only"
    quota_bytes: int | None = Field(
        default=None, gt=0, le=9_223_372_036_854_775_807
    )
    reset_policy: dict[str, Any] = Field(default_factory=dict)
    egress_rate_bps: int | None = Field(default=None, ge=8_000, le=100_000_000_000)
    approval_id: str | None = Field(default=None, max_length=36)

    @model_validator(mode="after")
    def validate_range_and_enforcement(self) -> PortTrafficPolicyCreate:
        if self.port_end < self.port_start:
            raise ValueError("port_end must be greater than or equal to port_start")
        if self.port_end - self.port_start + 1 > 4096:
            raise ValueError("one policy may cover at most 4096 consecutive ports")
        if self.egress_rate_bps is not None and self.direction == "rx":
            raise ValueError("first-version shaping supports egress only")
        if self.mode != "monitor_only" or self.egress_rate_bps is not None:
            raise ValueError(
                "new policies start in monitor_only; use a change request for enforcement"
            )
        if self.approval_id is not None:
            raise ValueError("approval_id is not accepted for a monitor-only policy")
        return self


class PortTrafficPolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=120)
    enabled: bool | None = None
    protocol: Literal["tcp", "udp", "both"] | None = None
    direction: Literal["rx", "tx", "both"] | None = None
    port_start: int | None = Field(default=None, ge=1, le=65535)
    port_end: int | None = Field(default=None, ge=1, le=65535)
    interface_name: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,30}$"
    )
    quota_bytes: int | None = Field(
        default=None, gt=0, le=9_223_372_036_854_775_807
    )
    reset_policy: dict[str, Any] | None = None
    egress_rate_bps: int | None = Field(default=None, ge=8_000, le=100_000_000_000)
    approval_id: str | None = Field(default=None, max_length=36)


class PortTrafficChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["monitor_only", "enforcing"]
    egress_rate_bps: int | None = Field(default=None, ge=8_000, le=100_000_000_000)
    reset_policy: dict[str, Any] | None = None
    reason: str = Field(min_length=3, max_length=500)


class PortTrafficResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3, max_length=500)
    confirmation: str = Field(min_length=3, max_length=120)


class PortTrafficPolicyView(ORMModel):
    id: str
    host_id: str
    name: str
    enabled: bool
    protocol: str
    direction: str
    port_start: int
    port_end: int
    interface_name: str | None
    mode: str
    quota_bytes: int | None
    reset_policy: dict[str, Any]
    egress_rate_bps: int | None
    status: str
    generation: int
    created_at: datetime
    updated_at: datetime


class PortTrafficRuntimeView(ORMModel):
    policy_id: str
    runtime_rule_state: str
    shaping_state: str
    counter_generation: int
    last_sample_at: datetime | None
    last_reset_at: datetime | None
    next_reset_at: datetime | None
    restore_error: str | None
    updated_at: datetime


class PortTrafficHistoryPoint(BaseModel):
    at: datetime
    rx_bytes: int | None
    tx_bytes: int | None
    combined_bytes: int | None
    missing_intervals: int = 0
    discontinuity_count: int = 0
    discontinuity_reason: str | None = None


class PortTrafficHistoryResponse(BaseModel):
    policy_id: str
    resolution: Literal["raw", "hour", "day"]
    starts_at: datetime
    ends_at: datetime
    points: list[PortTrafficHistoryPoint]


class PortTrafficEventView(BaseModel):
    id: str
    kind: Literal["reset", "quota", "runtime", "shaping", "enforcement", "gap", "spike"]
    state: str
    summary: str
    occurred_at: datetime


class PortTrafficSummary(BaseModel):
    policy: PortTrafficPolicyView
    runtime: PortTrafficRuntimeView | None
    current_period_rx: int | None
    current_period_tx: int | None
    current_period_total: int | None
    quota_percent: float | None
    quota_state: Literal["unlimited", "normal", "warning", "critical", "exhausted"]
    estimated_exhaustion_at: datetime | None
    last_sample_at: datetime | None
    data_gap: bool
    recent_events: list[PortTrafficEventView]


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    version: str
