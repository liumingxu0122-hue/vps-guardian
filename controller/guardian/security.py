from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian.config import Settings, get_settings
from guardian.database import get_db
from guardian.identity import as_utc, forced_setup_required
from guardian.models import Role, User, UserSession
from guardian.sessions import (
    BROWSER_SESSION_COOKIE,
    browser_session_error,
    find_browser_session,
    secret_hash,
)

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
dummy_password_hash = password_hasher.hash("vps-guardian-dummy-login-equalizer")
bearer = HTTPBearer(auto_error=False)


class LoginRateLimiter:
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
                raise HTTPException(status_code=429, detail="login rate limit exceeded")
            attempts.append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)


login_limiter = LoginRateLimiter()


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def verify_user_password(password: str, user: User | None) -> bool:
    """Run the same Argon2 verification path even when the identifier is unknown."""
    return verify_password(password, user.password_hash if user else dummy_password_hash)


def create_access_token(
    user: User, settings: Settings, *, session_id: str
) -> tuple[str, int]:
    now = datetime.now(UTC)
    ttl = settings.jwt_ttl_minutes * 60
    payload = {
        "sub": user.id,
        "role": user.role,
        "sv": user.session_version,
        "sid": session_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        "jti": secrets.token_urlsafe(16),
        "iss": "vps-guardian",
        "aud": "vps-guardian-web",
    }
    token = jwt.encode(payload, settings.jwt_secret.get_secret_value(), algorithm="HS256")
    return token, ttl


def decode_access_token(token: str, settings: Settings) -> dict[str, object]:
    try:
        return jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=["HS256"],
            audience="vps-guardian-web",
            issuer="vps-guardian",
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token"
        ) from exc


def _fernet(settings: Settings) -> Fernet:
    key = settings.field_encryption_key.get_secret_value()
    if not key:
        digest = hashlib.sha256(settings.jwt_secret.get_secret_value().encode()).digest()
        key = base64.urlsafe_b64encode(digest).decode()
    return Fernet(key.encode())


def encrypt_sensitive(value: str, settings: Settings) -> str:
    return _fernet(settings).encrypt(value.encode()).decode()


def decrypt_sensitive(value: str, settings: Settings) -> str:
    try:
        return _fernet(settings).decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("encrypted value cannot be decrypted") from exc


def totp_counter_for_code(
    secret: str, code: str | None, *, now: datetime | None = None
) -> int | None:
    if not code:
        return None
    checked_at = now or datetime.now(UTC)
    totp = pyotp.TOTP(secret)
    current_counter = int(checked_at.timestamp()) // totp.interval
    for counter in range(current_counter - 1, current_counter + 2):
        if secrets.compare_digest(totp.generate_otp(counter), code):
            return counter
    return None


def verify_totp(user: User, code: str | None, settings: Settings) -> bool:
    if not user.totp_enabled:
        return True
    if not code or not user.totp_secret_encrypted:
        return False
    secret = decrypt_sensitive(user.totp_secret_encrypted, settings)
    counter = totp_counter_for_code(secret, code)
    return counter is not None and (
        user.last_totp_counter is None or counter > user.last_totp_counter
    )


def canonical_json(data: object) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode()


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def _coded_error(status_code: int, code: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "params": {}})


def _same_origin(request: Request, settings: Settings) -> bool:
    origin = request.headers.get("origin")
    if not origin or any(character in origin for character in ", \t\r\n"):
        return False
    normalized_origin = origin.rstrip("/")
    configured_origins = (value.rstrip("/") for value in settings.allowed_origins)
    if any(
        secrets.compare_digest(normalized_origin, configured)
        for configured in configured_origins
    ):
        return True
    own_origin = f"{request.url.scheme}://{request.url.netloc}".rstrip("/")
    return secrets.compare_digest(normalized_origin, own_origin)


def enforce_csrf(request: Request, session: UserSession, settings: Settings) -> None:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    if request.headers.get("authorization", "").startswith("Bearer "):
        return
    if not _same_origin(request, settings):
        raise _coded_error(403, "CSRF_INVALID")
    cookie = request.cookies.get("guardian_csrf")
    header = request.headers.get("x-csrf-token")
    if (
        not cookie
        or not header
        or not session.csrf_secret_hash
        or not secrets.compare_digest(cookie, header)
        or not secrets.compare_digest(secret_hash(cookie), session.csrf_secret_hash)
    ):
        raise _coded_error(403, "CSRF_INVALID")


SCOPE_PREFIXES = {
    "/api/v1/overview": "operations",
    "/api/v1/attention": "operations",
    "/api/v1/stability": "operations",
    "/api/v1/hosts": "hosts",
    "/api/v1/services": "services",
    "/api/v1/service-checks": "services",
    "/api/v1/service-check-results": "services",
    "/api/v1/alerts": "alerts",
    "/api/v1/alert-rules": "alerts",
    "/api/v1/incidents": "incidents",
    "/api/v1/repairs": "repairs",
    "/api/v1/approvals": "approvals",
    "/api/v1/recovery-points": "recovery",
    "/api/v1/audit": "audit",
    "/api/v1/users": "users",
    "/api/v1/agents": "agents",
    "/api/v1/notification": "notifications",
    "/api/v1/settings": "settings",
}


def enforce_explicit_scopes(request: Request, user: User) -> None:
    """Treat non-empty scopes as an additional least-privilege restriction."""
    if not user.scopes or request.url.path.startswith("/api/v1/auth/"):
        return
    resource = next(
        (
            scope_resource
            for prefix, scope_resource in SCOPE_PREFIXES.items()
            if request.url.path.startswith(prefix)
        ),
        "system",
    )
    action = "read" if request.method in {"GET", "HEAD", "OPTIONS"} else "write"
    allowed = {
        "*:*",
        f"{resource}:*",
        f"{resource}:{action}",
    }
    if not allowed.intersection(user.scopes):
        raise HTTPException(status_code=403, detail="explicit scope denied")


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> User:
    now = datetime.now(UTC)
    if credentials is not None:
        try:
            payload = decode_access_token(credentials.credentials, settings)
        except HTTPException as exc:
            raise _coded_error(401, "SESSION_INVALID") from exc
        user = db.scalar(select(User).where(User.id == str(payload["sub"])))
        if not user or not user.is_active:
            raise _coded_error(401, "SESSION_REVOKED")
        if payload.get("sv") != user.session_version:
            raise _coded_error(401, "SESSION_VERSION_MISMATCH")
        session_id = payload.get("sid")
        if not isinstance(session_id, str):
            raise _coded_error(401, "SESSION_INVALID")
        auth_session = db.scalar(
            select(UserSession).where(
                UserSession.id == session_id,
                UserSession.user_id == user.id,
                UserSession.created_via == "api_token",
            )
        )
        if auth_session is None:
            raise _coded_error(401, "SESSION_INVALID")
        if auth_session.revoked_at is not None:
            raise _coded_error(401, "SESSION_REVOKED")
        if auth_session.session_version != user.session_version:
            raise _coded_error(401, "SESSION_VERSION_MISMATCH")
        if as_utc(auth_session.expires_at) <= now:
            raise _coded_error(401, "SESSION_ABSOLUTE_EXPIRED")
        request.state.auth_method = "bearer"
    else:
        session_secret = request.cookies.get(BROWSER_SESSION_COOKIE)
        if not session_secret:
            raise _coded_error(401, "SESSION_MISSING")
        auth_session = find_browser_session(db, session_secret)
        if auth_session is None:
            raise _coded_error(401, "SESSION_INVALID")
        user = db.scalar(select(User).where(User.id == auth_session.user_id))
        if not user or not user.is_active:
            raise _coded_error(401, "SESSION_REVOKED")
        error_code = browser_session_error(auth_session, user, now)
        if error_code:
            raise _coded_error(401, error_code)
        request.state.auth_method = "browser"
    request.state.auth_session = auth_session
    enforce_csrf(request, auth_session, settings)
    forced_paths = {
        "/api/v1/auth/me",
        "/api/v1/auth/logout",
        "/api/v1/auth/change-password",
        "/api/v1/auth/totp/setup",
        "/api/v1/auth/totp/enable",
        "/api/v1/auth/recovery-codes/confirm",
        "/api/v1/auth/recovery-codes/regenerate",
        "/api/v1/auth/step-up",
        "/api/v1/auth/activity",
        "/api/v1/auth/sessions",
    }
    if forced_setup_required(user) and request.url.path not in forced_paths:
        raise HTTPException(
            status_code=403,
            detail={"code": "identity_setup_required"},
        )
    enforce_explicit_scopes(request, user)
    return user


ROLE_ORDER = {
    Role.viewer.value: 0,
    Role.operator.value: 1,
    Role.admin.value: 2,
    Role.owner.value: 3,
}


def require_role(minimum: Role):  # type: ignore[no-untyped-def]
    def dependency(user: Annotated[User, Depends(get_current_user)]) -> User:
        if ROLE_ORDER.get(user.role, -1) < ROLE_ORDER[minimum.value]:
            raise _coded_error(403, "PERMISSION_DENIED")
        return user

    return dependency
