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
from guardian.models import Role, User

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
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


def create_access_token(user: User, settings: Settings) -> tuple[str, int]:
    now = datetime.now(UTC)
    ttl = settings.jwt_ttl_minutes * 60
    payload = {
        "sub": user.id,
        "role": user.role,
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


def verify_totp(user: User, code: str | None, settings: Settings) -> bool:
    if not user.totp_enabled:
        return True
    if not code or not user.totp_secret_encrypted:
        return False
    secret = decrypt_sensitive(user.totp_secret_encrypted, settings)
    return bool(pyotp.TOTP(secret).verify(code, valid_window=1))


def canonical_json(data: object) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode()


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def enforce_csrf(request: Request) -> None:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    if request.headers.get("authorization", "").startswith("Bearer "):
        return
    cookie = request.cookies.get("guardian_csrf")
    header = request.headers.get("x-csrf-token")
    if not cookie or not header or not secrets.compare_digest(cookie, header):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> User:
    token = credentials.credentials if credentials else request.cookies.get("guardian_session")
    if not token:
        raise HTTPException(status_code=401, detail="authentication required")
    payload = decode_access_token(token, settings)
    user = db.scalar(select(User).where(User.id == str(payload["sub"])))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="account disabled")
    enforce_csrf(request)
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
            raise HTTPException(status_code=403, detail="insufficient role")
        return user

    return dependency
