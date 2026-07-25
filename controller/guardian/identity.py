from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import Request
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from guardian.config import Settings
from guardian.models import RecoveryCode, User, UserSession

RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"


def as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _keyed_digest(value: str, settings: Settings, *, purpose: str) -> str:
    key = settings.jwt_secret.get_secret_value().encode()
    return hmac.new(key, f"{purpose}:{value}".encode(), hashlib.sha256).hexdigest()


def request_fingerprints(request: Request, settings: Settings) -> tuple[str, str]:
    user_agent = request.headers.get("user-agent", "")[:1024]
    source_ip = request.client.host if request.client else "unknown"
    return (
        _keyed_digest(user_agent, settings, purpose="user-agent"),
        _keyed_digest(source_ip, settings, purpose="source-ip"),
    )


def create_user_session(
    db: Session,
    *,
    user: User,
    request: Request,
    settings: Settings,
) -> UserSession:
    now = datetime.now(UTC)
    user_agent_digest, ip_digest = request_fingerprints(request, settings)
    row = UserSession(
        id=str(uuid.uuid4()),
        user_id=user.id,
        issued_at=now,
        expires_at=now + timedelta(minutes=settings.jwt_ttl_minutes),
        user_agent_digest=user_agent_digest,
        ip_digest=ip_digest,
        session_version=user.session_version,
    )
    db.add(row)
    db.flush()
    return row


def revoke_sessions(
    db: Session,
    *,
    user_id: str,
    actor_id: str | None,
    reason: str,
    except_session_id: str | None = None,
) -> int:
    now = datetime.now(UTC)
    statement = (
        update(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now, revoked_by=actor_id, revoke_reason=reason[:160])
    )
    if except_session_id:
        statement = statement.where(UserSession.id != except_session_id)
    result = db.execute(statement)
    return int(getattr(result, "rowcount", 0) or 0)


def normalize_recovery_code(value: str) -> str:
    return "".join(character for character in value.upper() if character.isalnum())


def recovery_code_hash(value: str, settings: Settings) -> str:
    return _keyed_digest(
        normalize_recovery_code(value),
        settings,
        purpose="recovery-code",
    )


def generate_recovery_code_batch(
    db: Session,
    *,
    user: User,
    settings: Settings,
) -> list[str]:
    now = datetime.now(UTC)
    db.execute(
        update(RecoveryCode)
        .where(
            RecoveryCode.user_id == user.id,
            RecoveryCode.used_at.is_(None),
            RecoveryCode.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    batch_id = str(uuid.uuid4())
    plaintext: list[str] = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(RECOVERY_CODE_ALPHABET) for _ in range(16))
        displayed = "-".join(raw[index : index + 4] for index in range(0, 16, 4))
        plaintext.append(displayed)
        db.add(
            RecoveryCode(
                user_id=user.id,
                code_hash=recovery_code_hash(displayed, settings),
                batch_id=batch_id,
                created_at=now,
            )
        )
    db.flush()
    return plaintext


def consume_recovery_code(
    db: Session,
    *,
    user: User,
    value: str,
    settings: Settings,
) -> tuple[bool, int]:
    digest = recovery_code_hash(value, settings)
    row = db.scalar(
        select(RecoveryCode)
        .where(
            RecoveryCode.user_id == user.id,
            RecoveryCode.code_hash == digest,
            RecoveryCode.used_at.is_(None),
            RecoveryCode.revoked_at.is_(None),
        )
        .with_for_update()
    )
    if row is None:
        return False, active_recovery_code_count(db, user.id)
    row.used_at = datetime.now(UTC)
    db.flush()
    return True, active_recovery_code_count(db, user.id)


def active_recovery_code_count(db: Session, user_id: str) -> int:
    return len(
        list(
            db.scalars(
                select(RecoveryCode.id).where(
                    RecoveryCode.user_id == user_id,
                    RecoveryCode.used_at.is_(None),
                    RecoveryCode.revoked_at.is_(None),
                )
            ).all()
        )
    )


def forced_setup_required(user: User) -> bool:
    return bool(
        user.must_change_password
        or (
            user.identity_setup_enforced
            and (not user.totp_enabled or user.recovery_codes_confirmed_at is None)
        )
    )
