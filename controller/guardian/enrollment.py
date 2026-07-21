from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian.models import EnrollmentToken, Host, User


class EnrollmentTokenError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class IssuedEnrollmentToken:
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
    db.add(
        EnrollmentToken(
            host_id=host.id,
            token_hash=token_digest(value),
            expires_at=expires_at,
            created_by=actor.id,
            created_at=now,
        )
    )
    return IssuedEnrollmentToken(value=value, expires_at=expires_at)


def consume_enrollment_token(
    db: Session, *, value: str, now: datetime | None = None
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
    token.used_at = now
    return token, host

