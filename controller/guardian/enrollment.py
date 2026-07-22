from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from guardian.models import EnrollmentToken, Host, User


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


@dataclass(frozen=True, slots=True)
class IssuedEnrollmentToken:
    id: str
    value: str
    expires_at: datetime


def token_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def issue_enrollment_token(
    db: Session,
    *,
    host: Host,
    actor: User,
    ttl: timedelta = timedelta(minutes=15),
    now: datetime | None = None,
) -> IssuedEnrollmentToken:
    now = now or datetime.now(UTC)
    if ttl < timedelta(minutes=1) or ttl > timedelta(hours=24):
        raise EnrollmentTokenError("enrollment token lifetime is outside the allowed range")
    if host.agent and host.agent.revoked_at is None:
        raise EnrollmentTokenError("host already has an active agent")
    value = secrets.token_urlsafe(32)
    expires_at = now + ttl
    token = EnrollmentToken(
        host_id=host.id,
        token_hash=token_digest(value),
        expires_at=expires_at,
        created_by=actor.id,
        created_at=now,
    )
    db.add(token)
    db.flush()
    return IssuedEnrollmentToken(id=token.id, value=value, expires_at=expires_at)


def consume_enrollment_token(
    db: Session,
    *,
    value: str,
    expected_host_id: str | None = None,
    now: datetime | None = None,
) -> tuple[EnrollmentToken, Host]:
    now = now or datetime.now(UTC)
    digest = token_digest(value)
    token = db.scalar(
        select(EnrollmentToken)
        .where(EnrollmentToken.token_hash == digest)
        .with_for_update()
    )
    if token is None or not secrets.compare_digest(token.token_hash, digest):
        raise EnrollmentTokenError("invalid enrollment token")
    if token.used_at is not None:
        raise EnrollmentTokenError("enrollment token was already used")
    if token.revoked_at is not None:
        raise EnrollmentTokenError("enrollment token was revoked")
    expires_at = token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at <= now:
        raise EnrollmentTokenError("enrollment token expired")
    host = db.get(Host, token.host_id)
    if host is None or not host.enabled:
        raise EnrollmentTokenError("enrollment target is unavailable")
    if expected_host_id is not None and not secrets.compare_digest(host.id, expected_host_id):
        raise EnrollmentTokenError("enrollment token host mismatch")
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
        token.revoked_at = now or datetime.now(UTC)
    return token
