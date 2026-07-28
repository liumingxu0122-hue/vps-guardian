from __future__ import annotations

import hashlib
import ipaddress
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Request
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from guardian.config import Settings
from guardian.identity import as_utc, request_fingerprints
from guardian.models import User, UserSession

BROWSER_SESSION_COOKIE = "guardian_browser_session"
CSRF_COOKIE = "guardian_csrf"
SESSION_INVALID_CODES = frozenset(
    {
        "SESSION_MISSING",
        "SESSION_REVOKED",
        "SESSION_IDLE_EXPIRED",
        "SESSION_ABSOLUTE_EXPIRED",
        "SESSION_VERSION_MISMATCH",
        "SESSION_INVALID",
    }
)


def secret_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _device_summary(user_agent: str) -> str:
    lowered = user_agent.casefold()
    device = (
        "mobile"
        if "mobile" in lowered
        else "tablet"
        if "tablet" in lowered or "ipad" in lowered
        else "desktop"
    )
    browser = (
        "edge"
        if "edg/" in lowered
        else "firefox"
        if "firefox/" in lowered
        else "chrome"
        if "chrome/" in lowered
        else "safari"
        if "safari/" in lowered
        else "unknown"
    )
    return f"{device}:{browser}"


def _ip_summary(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "protected"
    if address.is_private or address.is_loopback:
        return "private"
    if isinstance(address, ipaddress.IPv4Address):
        return "public_ipv4"
    return "public_ipv6"


@dataclass(frozen=True)
class BrowserSessionCredentials:
    row: UserSession
    session_secret: str
    csrf_secret: str


def create_browser_session(
    db: Session,
    *,
    user: User,
    request: Request,
    settings: Settings,
    remember_me: bool,
    created_via: str,
    device_name: str | None = None,
    rotated_from_session_id: str | None = None,
) -> BrowserSessionCredentials:
    now = datetime.now(UTC)
    if remember_me:
        idle_delta = timedelta(days=settings.session_remember_idle_days)
        absolute_delta = timedelta(days=settings.session_remember_absolute_days)
    else:
        idle_delta = timedelta(hours=settings.session_default_idle_hours)
        absolute_delta = timedelta(days=settings.session_default_absolute_days)
    absolute_expires_at = now + absolute_delta
    idle_expires_at = min(now + idle_delta, absolute_expires_at)
    session_secret = secrets.token_urlsafe(48)
    csrf_secret = secrets.token_urlsafe(32)
    user_agent = request.headers.get("user-agent", "")[:1024]
    source_ip = request.client.host if request.client else "unknown"
    user_agent_digest, ip_digest = request_fingerprints(request, settings)
    row = UserSession(
        id=str(uuid.uuid4()),
        user_id=user.id,
        token_hash=secret_hash(session_secret),
        csrf_secret_hash=secret_hash(csrf_secret),
        issued_at=now,
        last_seen_at=now,
        idle_expires_at=idle_expires_at,
        absolute_expires_at=absolute_expires_at,
        expires_at=absolute_expires_at,
        remember_me=remember_me,
        user_agent_digest=user_agent_digest,
        ip_digest=ip_digest,
        user_agent_summary=_device_summary(user_agent),
        ip_summary=_ip_summary(source_ip),
        created_via=created_via,
        last_activity_type="sign_in",
        device_name=device_name,
        rotated_from_session_id=rotated_from_session_id,
        session_version=user.session_version,
    )
    db.add(row)
    db.flush()
    return BrowserSessionCredentials(
        row=row,
        session_secret=session_secret,
        csrf_secret=csrf_secret,
    )


def find_browser_session(db: Session, session_secret: str) -> UserSession | None:
    return db.scalar(
        select(UserSession).where(
            UserSession.token_hash == secret_hash(session_secret),
            UserSession.created_via != "api_token",
        )
    )


def browser_session_error(row: UserSession, user: User, now: datetime) -> str | None:
    if row.revoked_at is not None:
        return "SESSION_REVOKED"
    if row.session_version != user.session_version:
        return "SESSION_VERSION_MISMATCH"
    if as_utc(row.absolute_expires_at) <= now:
        return "SESSION_ABSOLUTE_EXPIRED"
    if as_utc(row.idle_expires_at) <= now:
        return "SESSION_IDLE_EXPIRED"
    return None


def touch_browser_session(
    db: Session,
    *,
    row: UserSession,
    settings: Settings,
    activity_type: str,
    now: datetime | None = None,
) -> bool:
    current = now or datetime.now(UTC)
    last_seen_at = as_utc(row.last_seen_at)
    if current - last_seen_at < timedelta(
        seconds=settings.session_activity_touch_interval_seconds
    ):
        return False
    idle_delta = (
        timedelta(days=settings.session_remember_idle_days)
        if row.remember_me
        else timedelta(hours=settings.session_default_idle_hours)
    )
    absolute = as_utc(row.absolute_expires_at)
    idle_expires_at = min(current + idle_delta, absolute)
    result = db.execute(
        update(UserSession)
        .where(
            UserSession.id == row.id,
            UserSession.revoked_at.is_(None),
            UserSession.last_seen_at <= current
            - timedelta(seconds=settings.session_activity_touch_interval_seconds),
            UserSession.idle_expires_at > current,
            UserSession.absolute_expires_at > current,
        )
        .values(
            last_seen_at=current,
            idle_expires_at=idle_expires_at,
            last_activity_type=activity_type[:64],
        )
        .execution_options(synchronize_session=False)
    )
    return bool(getattr(result, "rowcount", 0))


def rotate_browser_session(
    db: Session,
    *,
    row: UserSession,
    user: User,
    request: Request,
    settings: Settings,
    reason: str,
) -> BrowserSessionCredentials:
    now = datetime.now(UTC)
    row.revoked_at = now
    row.revoked_by = user.id
    row.revoke_reason = reason[:160]
    return create_browser_session(
        db,
        user=user,
        request=request,
        settings=settings,
        remember_me=row.remember_me,
        created_via=row.created_via,
        device_name=row.device_name,
        rotated_from_session_id=row.id,
    )


def session_cookie_ttl(row: UserSession, *, now: datetime | None = None) -> int:
    current = now or datetime.now(UTC)
    return max(1, int((as_utc(row.absolute_expires_at) - current).total_seconds()))
