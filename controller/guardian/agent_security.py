from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import HTTPException, Request
from sqlalchemy import and_, delete, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from guardian.config import Settings
from guardian.models import Agent, AgentIdentity, AgentIdentityState, Nonce
from guardian.security import canonical_json

MAX_FORWARDED_CERTIFICATE_BYTES = 16_384


def lock_active_agent(db: Session, agent_id: str) -> Agent:
    """Serialize identity authentication and lifecycle changes for one Agent."""
    agent = db.scalar(
        select(Agent)
        .where(Agent.id == agent_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if agent is None or agent.revoked_at is not None:
        raise HTTPException(status_code=404, detail="active agent not found")
    return agent


def normalize_certificate_fingerprint(value: str) -> str:
    normalized = value.replace(":", "").replace(" ", "").upper()
    if len(normalized) != 64 or any(
        character not in "0123456789ABCDEF" for character in normalized
    ):
        raise ValueError("invalid certificate fingerprint")
    return normalized


def normalize_certificate_serial(value: str) -> str:
    normalized = value.strip().upper().removeprefix("0X").lstrip("0") or "0"
    if len(normalized) > 128 or any(
        character not in "0123456789ABCDEF" for character in normalized
    ):
        raise ValueError("invalid certificate serial")
    return normalized


def trusted_client_certificate_identity(
    request: Request,
    settings: Settings,
) -> tuple[str, str]:
    """Return the SHA-256 fingerprint and serial asserted by the trusted mTLS gateway."""
    expected_proxy_auth = settings.trusted_proxy_cert_header_secret.get_secret_value()
    proxy_auth = request.headers.get("x-guardian-proxy-auth", "")
    if not expected_proxy_auth or not secrets.compare_digest(proxy_auth, expected_proxy_auth):
        raise HTTPException(status_code=401, detail="untrusted mTLS proxy")

    encoded_certificate = request.headers.get("x-guardian-client-certificate-der", "")
    if not encoded_certificate or len(encoded_certificate) > MAX_FORWARDED_CERTIFICATE_BYTES:
        raise HTTPException(status_code=401, detail="invalid forwarded client certificate")
    try:
        certificate_der = base64.b64decode(encoded_certificate, validate=True)
        certificate = x509.load_der_x509_certificate(certificate_der)
    except (TypeError, ValueError, binascii.Error) as exc:
        raise HTTPException(
            status_code=401,
            detail="invalid forwarded client certificate",
        ) from exc
    return (
        certificate.fingerprint(hashes.SHA256()).hex().upper(),
        normalize_certificate_serial(format(certificate.serial_number, "X")),
    )


def build_agent_signing_message(
    agent_id: str,
    timestamp: str,
    nonce: str,
    payload: object | bytes,
) -> bytes:
    payload_bytes = payload if isinstance(payload, bytes) else canonical_json(payload)
    digest = hashlib.sha256(payload_bytes).hexdigest()
    return f"{agent_id}\n{timestamp}\n{nonce}\n{digest}".encode()


def verify_agent_request(
    *,
    request: Request,
    agent: Agent,
    payload: bytes,
    db: Session,
    settings: Settings,
) -> AgentIdentity:
    """Verify a request while the caller holds the Agent row lock through commit."""
    timestamp = request.headers.get("x-agent-timestamp", "")
    nonce = request.headers.get("x-agent-nonce", "")
    signature = request.headers.get("x-agent-signature", "")
    if settings.environment == "production":
        fingerprint, certificate_serial = trusted_client_certificate_identity(request, settings)
    else:
        try:
            fingerprint = normalize_certificate_fingerprint(
                request.headers.get("x-client-cert-fingerprint", "")
            )
        except ValueError as exc:
            raise HTTPException(status_code=401, detail="invalid mTLS fingerprint") from exc
        certificate_serial = None
    if not timestamp or len(nonce) < 16 or len(nonce) > 128 or not signature:
        raise HTTPException(status_code=401, detail="missing agent signature headers")
    now = datetime.now(UTC)
    identity = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.agent_id == agent.id,
            AgentIdentity.certificate_fingerprint == fingerprint,
            or_(
                AgentIdentity.state == AgentIdentityState.active.value,
                AgentIdentity.state == AgentIdentityState.retiring.value,
                and_(
                    AgentIdentity.state == AgentIdentityState.pending.value,
                    AgentIdentity.expires_at.is_not(None),
                    AgentIdentity.expires_at > now,
                ),
            ),
            *(
                [AgentIdentity.certificate_serial == certificate_serial]
                if certificate_serial is not None
                else []
            ),
        )
    )
    if identity is None:
        raise HTTPException(status_code=401, detail="agent identity not accepted")
    try:
        signed_at = datetime.fromtimestamp(int(timestamp), UTC)
    except (TypeError, ValueError, OSError) as exc:
        raise HTTPException(status_code=401, detail="invalid agent timestamp") from exc
    if abs((now - signed_at).total_seconds()) > settings.nonce_ttl_seconds:
        raise HTTPException(status_code=401, detail="expired agent request")

    db.execute(
        delete(Nonce)
        .where(Nonce.expires_at < now)
        .execution_options(synchronize_session=False)
    )
    if db.scalar(select(Nonce).where(Nonce.value == nonce)):
        raise HTTPException(status_code=409, detail="replayed agent request")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(identity.signing_public_key, validate=True)
        )
        public_key.verify(
            base64.b64decode(signature, validate=True),
            build_agent_signing_message(agent.id, timestamp, nonce, payload),
        )
    except (ValueError, binascii.Error, InvalidSignature) as exc:
        raise HTTPException(status_code=401, detail="invalid agent signature") from exc

    db.add(
        Nonce(
            value=nonce,
            agent_id=agent.id,
            expires_at=max(now, signed_at)
            + timedelta(seconds=settings.nonce_ttl_seconds),
        )
    )
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="replayed agent request") from exc
    return identity
