from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network

from sqlalchemy import desc, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from guardian.models import (
    EnrollmentEvent,
    EnrollmentStatus,
    EnrollmentToken,
    Host,
    User,
)


class EnrollmentTokenError(ValueError):
    pass


class EnrollmentRateLimitError(EnrollmentTokenError):
    pass


class EnrollmentRateLimiter:
    def __init__(self) -> None:
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_seconds: int = 600) -> None:
        now = time.monotonic()
        with self._lock:
            attempts = self._attempts[key]
            while attempts and attempts[0] <= now - window_seconds:
                attempts.popleft()
            if len(attempts) >= limit:
                raise EnrollmentRateLimitError("enrollment rate limit exceeded")
            attempts.append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._attempts.clear()


enrollment_limiter = EnrollmentRateLimiter()

ENROLLMENT_STEPS = (
    EnrollmentStatus.waiting.value,
    EnrollmentStatus.installer_downloaded.value,
    EnrollmentStatus.installer_verified.value,
    EnrollmentStatus.prerequisites_checked.value,
    EnrollmentStatus.agent_downloaded.value,
    EnrollmentStatus.agent_verified.value,
    EnrollmentStatus.local_key_generated.value,
    EnrollmentStatus.csr_submitted.value,
    EnrollmentStatus.certificate_issued.value,
    EnrollmentStatus.service_installed.value,
    EnrollmentStatus.service_started.value,
    EnrollmentStatus.heartbeat_received.value,
    EnrollmentStatus.completed.value,
)
ENROLLMENT_SEQUENCE = {status: sequence for sequence, status in enumerate(ENROLLMENT_STEPS)}
INSTALLER_PROGRESS_STEPS = frozenset(ENROLLMENT_STEPS[1:8])
POST_BOOTSTRAP_PROGRESS_STEPS = frozenset(
    {
        EnrollmentStatus.service_installed.value,
        EnrollmentStatus.service_started.value,
    }
)
TERMINAL_STATUSES = frozenset(
    {
        EnrollmentStatus.completed.value,
        EnrollmentStatus.failed.value,
        EnrollmentStatus.expired.value,
        EnrollmentStatus.revoked.value,
    }
)


@dataclass(frozen=True, slots=True)
class IssuedEnrollmentToken:
    id: str
    value: str
    expires_at: datetime


def token_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_source_cidr(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    try:
        network = ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise EnrollmentTokenError("enrollment source CIDR is invalid") from exc
    return str(network)


def source_allowed(token: EnrollmentToken, source_ip: str) -> bool:
    if token.source_cidr is None:
        return True
    try:
        return ip_address(source_ip) in ip_network(token.source_cidr, strict=True)
    except ValueError:
        return False


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _record_event(
    db: Session,
    *,
    token: EnrollmentToken,
    status: str,
    sequence: int,
    occurred_at: datetime,
    error_code: str | None = None,
    error_summary: str | None = None,
    rolled_back: bool = False,
) -> None:
    db.add(
        EnrollmentEvent(
            enrollment_id=token.id,
            status=status,
            status_sequence=sequence,
            occurred_at=occurred_at,
            error_code=error_code,
            error_summary=error_summary,
            rolled_back=rolled_back,
        )
    )


def advance_enrollment(
    db: Session,
    *,
    token: EnrollmentToken,
    status: str,
    now: datetime | None = None,
    allow_completion: bool = False,
) -> bool:
    if status not in ENROLLMENT_SEQUENCE:
        raise EnrollmentTokenError("invalid enrollment progress state")
    if status == EnrollmentStatus.completed.value and not allow_completion:
        raise EnrollmentTokenError("completed requires an authenticated heartbeat")
    if token.status in TERMINAL_STATUSES:
        raise EnrollmentTokenError("enrollment session is no longer active")
    target = ENROLLMENT_SEQUENCE[status]
    if target < token.status_sequence:
        raise EnrollmentTokenError("enrollment progress cannot move backwards")
    if target == token.status_sequence:
        return False
    occurred_at = now or datetime.now(UTC)
    token.status = status
    token.status_sequence = target
    token.status_updated_at = occurred_at
    if status == EnrollmentStatus.completed.value:
        token.completed_at = occurred_at
    _record_event(
        db,
        token=token,
        status=status,
        sequence=target,
        occurred_at=occurred_at,
    )
    return True


def fail_enrollment(
    db: Session,
    *,
    token: EnrollmentToken,
    error_code: str,
    error_step: str,
    error_summary: str,
    rolled_back: bool,
    now: datetime | None = None,
) -> None:
    if token.status in {
        EnrollmentStatus.completed.value,
        EnrollmentStatus.revoked.value,
        EnrollmentStatus.expired.value,
    }:
        raise EnrollmentTokenError("enrollment session is no longer active")
    occurred_at = now or datetime.now(UTC)
    token.status = EnrollmentStatus.failed.value
    token.status_updated_at = occurred_at
    token.error_code = error_code[:64]
    token.error_step = error_step[:32]
    token.error_summary = error_summary[:240]
    token.rolled_back = rolled_back
    token.progress_token_hash = None
    _record_event(
        db,
        token=token,
        status=EnrollmentStatus.failed.value,
        sequence=token.status_sequence,
        occurred_at=occurred_at,
        error_code=token.error_code,
        error_summary=token.error_summary,
        rolled_back=rolled_back,
    )


def issue_enrollment_token(
    db: Session,
    *,
    host: Host,
    actor: User,
    ttl: timedelta = timedelta(minutes=10),
    source_cidr: str | None = None,
    os_family: str = "auto",
    installer_version: str | None = None,
    agent_version: str | None = None,
    revoke_existing: bool = True,
    now: datetime | None = None,
) -> IssuedEnrollmentToken:
    now = now or datetime.now(UTC)
    if ttl < timedelta(minutes=1) or ttl > timedelta(hours=24):
        raise EnrollmentTokenError("enrollment token lifetime is outside the allowed range")
    if host.agent and host.agent.revoked_at is None:
        raise EnrollmentTokenError("host already has an active agent")
    if os_family not in {
        "auto",
        "debian",
        "rhel",
        "fedora",
        "alpine",
        "generic",
    }:
        raise EnrollmentTokenError("unsupported enrollment operating system family")
    normalized_cidr = normalize_source_cidr(source_cidr)
    if revoke_existing:
        existing = list(
            db.scalars(
                select(EnrollmentToken)
                .where(
                    EnrollmentToken.host_id == host.id,
                    EnrollmentToken.used_at.is_(None),
                    EnrollmentToken.revoked_at.is_(None),
                    EnrollmentToken.expires_at > now,
                )
                .with_for_update()
            ).all()
        )
        for previous in existing:
            previous.revoked_at = now
            previous.status = EnrollmentStatus.revoked.value
            previous.status_updated_at = now
            _record_event(
                db,
                token=previous,
                status=EnrollmentStatus.revoked.value,
                sequence=previous.status_sequence,
                occurred_at=now,
            )
    value = secrets.token_urlsafe(32)
    expires_at = now + ttl
    token = EnrollmentToken(
        host_id=host.id,
        token_hash=token_digest(value),
        expires_at=expires_at,
        created_by=actor.id,
        created_at=now,
        status=EnrollmentStatus.waiting.value,
        status_sequence=0,
        status_updated_at=now,
        source_cidr=normalized_cidr,
        os_family=os_family,
        installer_version=installer_version,
        agent_version=agent_version,
    )
    db.add(token)
    db.flush()
    _record_event(
        db,
        token=token,
        status=EnrollmentStatus.waiting.value,
        sequence=0,
        occurred_at=now,
    )
    return IssuedEnrollmentToken(id=token.id, value=value, expires_at=expires_at)


def authenticate_enrollment_token(
    db: Session,
    *,
    value: str,
    expected_host_id: str | None = None,
    source_ip: str | None = None,
    now: datetime | None = None,
    lock: bool = False,
) -> tuple[EnrollmentToken, Host]:
    now = now or datetime.now(UTC)
    digest = token_digest(value)
    query = select(EnrollmentToken).where(EnrollmentToken.token_hash == digest)
    if lock:
        query = query.with_for_update()
    token = db.scalar(query)
    if token is None or not secrets.compare_digest(token.token_hash, digest):
        raise EnrollmentTokenError("invalid enrollment token")
    if token.used_at is not None:
        raise EnrollmentTokenError("enrollment token was already used")
    if token.revoked_at is not None:
        raise EnrollmentTokenError("enrollment token was revoked")
    if token.status == EnrollmentStatus.failed.value:
        raise EnrollmentTokenError("enrollment session failed and must be regenerated")
    if _as_utc(token.expires_at) <= now:
        raise EnrollmentTokenError("enrollment token expired")
    host = db.get(Host, token.host_id)
    if host is None or not host.enabled:
        raise EnrollmentTokenError("enrollment target is unavailable")
    if expected_host_id is not None and not secrets.compare_digest(host.id, expected_host_id):
        raise EnrollmentTokenError("enrollment token host mismatch")
    if source_ip is not None and not source_allowed(token, source_ip):
        raise EnrollmentTokenError("enrollment source is not allowed")
    return token, host


def issue_progress_token(token: EnrollmentToken) -> str:
    if token.used_at is None or token.status != EnrollmentStatus.certificate_issued.value:
        raise EnrollmentTokenError("progress credential requires a completed bootstrap")
    value = secrets.token_urlsafe(32)
    token.progress_token_hash = token_digest(value)
    return value


def authenticate_progress_token(
    db: Session,
    *,
    value: str,
    source_ip: str | None = None,
    now: datetime | None = None,
) -> tuple[EnrollmentToken, Host]:
    now = now or datetime.now(UTC)
    digest = token_digest(value)
    token = db.scalar(
        select(EnrollmentToken)
        .where(EnrollmentToken.progress_token_hash == digest)
        .with_for_update()
    )
    if (
        token is None
        or token.progress_token_hash is None
        or not secrets.compare_digest(token.progress_token_hash, digest)
    ):
        raise EnrollmentTokenError("invalid enrollment progress credential")
    if token.revoked_at is not None or token.status in TERMINAL_STATUSES:
        raise EnrollmentTokenError("enrollment session is no longer active")
    if _as_utc(token.expires_at) <= now:
        raise EnrollmentTokenError("enrollment progress credential expired")
    host = db.get(Host, token.host_id)
    if host is None or not host.enabled:
        raise EnrollmentTokenError("enrollment target is unavailable")
    if source_ip is not None and not source_allowed(token, source_ip):
        raise EnrollmentTokenError("enrollment source is not allowed")
    return token, host


def consume_enrollment_token(
    db: Session,
    *,
    value: str,
    expected_host_id: str | None = None,
    source_ip: str | None = None,
    now: datetime | None = None,
) -> tuple[EnrollmentToken, Host]:
    now = now or datetime.now(UTC)
    token, host = authenticate_enrollment_token(
        db,
        value=value,
        expected_host_id=expected_host_id,
        source_ip=source_ip,
        now=now,
        lock=True,
    )
    result = db.execute(
        update(EnrollmentToken)
        .where(
            EnrollmentToken.id == token.id,
            EnrollmentToken.used_at.is_(None),
            EnrollmentToken.revoked_at.is_(None),
            EnrollmentToken.expires_at > now,
        )
        .values(used_at=now)
        .execution_options(synchronize_session=False)
    )
    if not isinstance(result, CursorResult) or result.rowcount != 1:
        raise EnrollmentTokenError("enrollment token was already used")
    token.used_at = now
    if token.status_sequence < ENROLLMENT_SEQUENCE[EnrollmentStatus.csr_submitted.value]:
        for status in ENROLLMENT_STEPS[
            token.status_sequence + 1 : ENROLLMENT_SEQUENCE[EnrollmentStatus.csr_submitted.value]
            + 1
        ]:
            advance_enrollment(db, token=token, status=status, now=now)
    return token, host


def revoke_enrollment_token(
    db: Session,
    *,
    token_id: str,
    host_id: str,
    now: datetime | None = None,
) -> EnrollmentToken:
    token = db.scalar(
        select(EnrollmentToken)
        .where(EnrollmentToken.id == token_id, EnrollmentToken.host_id == host_id)
        .with_for_update()
    )
    if token is None:
        raise EnrollmentTokenError("enrollment token not found")
    if token.used_at is not None:
        raise EnrollmentTokenError("used enrollment token cannot be revoked")
    if token.revoked_at is None:
        revoked_at = now or datetime.now(UTC)
        token.revoked_at = revoked_at
        token.status = EnrollmentStatus.revoked.value
        token.status_updated_at = revoked_at
        _record_event(
            db,
            token=token,
            status=EnrollmentStatus.revoked.value,
            sequence=token.status_sequence,
            occurred_at=revoked_at,
        )
    return token


def latest_host_enrollment(db: Session, host_id: str) -> EnrollmentToken | None:
    return db.scalar(
        select(EnrollmentToken)
        .where(EnrollmentToken.host_id == host_id)
        .order_by(desc(EnrollmentToken.created_at))
        .limit(1)
    )


def complete_host_enrollment(
    db: Session,
    *,
    host_id: str,
    now: datetime | None = None,
) -> EnrollmentToken | None:
    token = db.scalar(
        select(EnrollmentToken)
        .where(
            EnrollmentToken.host_id == host_id,
            EnrollmentToken.used_at.is_not(None),
            EnrollmentToken.revoked_at.is_(None),
            EnrollmentToken.completed_at.is_(None),
        )
        .order_by(desc(EnrollmentToken.created_at))
        .with_for_update()
        .limit(1)
    )
    if token is None or token.status == EnrollmentStatus.failed.value:
        return None
    occurred_at = now or datetime.now(UTC)
    for status in (
        EnrollmentStatus.certificate_issued.value,
        EnrollmentStatus.service_installed.value,
        EnrollmentStatus.service_started.value,
        EnrollmentStatus.heartbeat_received.value,
        EnrollmentStatus.completed.value,
    ):
        if ENROLLMENT_SEQUENCE[status] > token.status_sequence:
            advance_enrollment(
                db,
                token=token,
                status=status,
                now=occurred_at,
                allow_completion=status == EnrollmentStatus.completed.value,
            )
    token.progress_token_hash = None
    return token
