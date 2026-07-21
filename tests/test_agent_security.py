from __future__ import annotations

import base64
import json
import secrets
import time
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient
from guardian.agent_security import (
    build_agent_signing_message,
    lock_active_agent,
    normalize_certificate_serial,
    trusted_client_certificate_identity,
    verify_agent_request,
)
from guardian.config import Settings
from guardian.database import SessionLocal
from guardian.models import Agent, AgentIdentity, AgentIdentityState, Host, MetricSnapshot, Nonce
from pydantic import SecretStr
from sqlalchemy.dialects import postgresql


def forwarded_certificate(serial: int = 0x1003) -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "staging-agent")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(private_key, algorithm=None)
    )
    certificate_der = certificate.public_bytes(serialization.Encoding.DER)
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex().upper()
    return base64.b64encode(certificate_der).decode(), fingerprint


def production_gateway_settings() -> Settings:
    return Settings.model_construct(
        environment="production",
        trusted_proxy_cert_header_secret=SecretStr("p" * 48),
        nonce_ttl_seconds=300,
    )


def request_with_headers(headers: dict[str, str]) -> Request:
    return Request(
        {
            "type": "http",
            "headers": [
                (key.lower().encode("ascii"), value.encode("ascii"))
                for key, value in headers.items()
            ],
        }
    )


def test_agent_identity_lock_uses_postgresql_for_update_and_refreshes_cached_state() -> None:
    captured: list[object] = []
    agent = Agent(
        id="locked-agent",
        host_id="locked-host",
        signing_public_key="A" * 44,
        certificate_fingerprint="AA" * 32,
    )

    class RecordingSession:
        def scalar(self, statement: object) -> Agent:
            captured.append(statement)
            return agent

    assert lock_active_agent(RecordingSession(), agent.id) is agent  # type: ignore[arg-type]
    assert len(captured) == 1
    statement = captured[0]
    compiled = str(statement.compile(dialect=postgresql.dialect()))  # type: ignore[attr-defined]
    assert compiled.rstrip().endswith("FOR UPDATE")
    assert statement.get_execution_options()["populate_existing"] is True  # type: ignore[attr-defined]


def test_future_dated_signature_nonce_is_retained_for_its_full_validity_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_time = datetime(2026, 7, 18, 0, 0, tzinfo=UTC)

    class FrozenDateTime(datetime):
        current = base_time

        @classmethod
        def now(cls, tz: object = None) -> datetime:
            if tz is None:
                return cls.current.replace(tzinfo=None)
            return cls.current

    monkeypatch.setattr("guardian.agent_security.datetime", FrozenDateTime)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    payload = b'{"status":"ok"}'
    timestamp = str(int((base_time + timedelta(seconds=240)).timestamp()))
    nonce = "future-dated-nonce-0001"
    agent = Agent(
        id="future-nonce-agent",
        host_id="future-nonce-host",
        signing_public_key=base64.b64encode(public_key).decode(),
        certificate_fingerprint="AA" * 32,
    )
    signature = base64.b64encode(
        private_key.sign(build_agent_signing_message(agent.id, timestamp, nonce, payload))
    ).decode()
    request = request_with_headers(
        {
            "X-Client-Cert-Fingerprint": "AA" * 32,
            "X-Agent-Timestamp": timestamp,
            "X-Agent-Nonce": nonce,
            "X-Agent-Signature": signature,
        }
    )
    settings = Settings.model_construct(environment="test", nonce_ttl_seconds=300)
    with SessionLocal() as database:
        database.add(Host(id=agent.host_id, name="future-nonce-host", address="192.0.2.32"))
        database.add(agent)
        database.flush()
        database.add(
            AgentIdentity(
                agent_id=agent.id,
                generation=1,
                state=AgentIdentityState.active.value,
                signing_public_key=agent.signing_public_key,
                certificate_fingerprint=agent.certificate_fingerprint,
            )
        )
        database.flush()
        verify_agent_request(
            request=request,
            agent=agent,
            payload=payload,
            db=database,
            settings=settings,
        )
        stored = database.get(Nonce, nonce)
        assert stored
        expires_at = stored.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        assert expires_at == base_time + timedelta(seconds=540)

        FrozenDateTime.current = base_time + timedelta(seconds=301)
        with pytest.raises(HTTPException) as replay:
            verify_agent_request(
                request=request,
                agent=agent,
                payload=payload,
                db=database,
                settings=settings,
            )
        assert replay.value.status_code == 409
        assert replay.value.detail == "replayed agent request"


def test_production_identity_is_derived_from_forwarded_certificate() -> None:
    escaped_certificate, expected_fingerprint = forwarded_certificate()
    request = request_with_headers(
        {
            "X-Guardian-Proxy-Auth": "p" * 48,
            "X-Guardian-Client-Certificate-Der": escaped_certificate,
            "X-Client-Cert-Fingerprint": "AA" * 32,
        }
    )

    fingerprint, serial = trusted_client_certificate_identity(
        request,
        production_gateway_settings(),
    )

    assert fingerprint == expected_fingerprint
    assert fingerprint != "AA" * 32
    assert serial == "1003"


@pytest.mark.parametrize(
    ("proxy_auth", "certificate"),
    [
        ("wrong", "valid"),
        ("p" * 48, "malformed"),
        ("p" * 48, "missing"),
        ("p" * 48, "oversized"),
    ],
)
def test_production_identity_fails_closed(
    proxy_auth: str,
    certificate: str,
) -> None:
    escaped_certificate, _ = forwarded_certificate()
    forwarded = {
        "valid": escaped_certificate,
        "malformed": "%2D%2Dnot-a-certificate",
        "missing": "",
        "oversized": "A" * 16_385,
    }[certificate]
    request = request_with_headers(
        {
            "X-Guardian-Proxy-Auth": proxy_auth,
            "X-Guardian-Client-Certificate-Der": forwarded,
        }
    )

    with pytest.raises(HTTPException) as error:
        trusted_client_certificate_identity(request, production_gateway_settings())
    assert error.value.status_code == 401


def test_certificate_serial_normalization_fails_closed() -> None:
    assert normalize_certificate_serial("0x001003") == "1003"
    assert normalize_certificate_serial("0000") == "0"
    with pytest.raises(ValueError, match="invalid certificate serial"):
        normalize_certificate_serial("not-hex")


def test_production_signed_request_binds_certificate_serial() -> None:
    escaped_certificate, fingerprint = forwarded_certificate()
    signing_key = Ed25519PrivateKey.generate()
    public_key = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    agent = Agent(
        id="production-agent",
        host_id="production-host",
        signing_public_key=base64.b64encode(public_key).decode(),
        certificate_fingerprint=fingerprint,
        certificate_serial="1003",
    )
    payload = b'{"status":"ok"}'

    def signed_request(nonce: str) -> Request:
        timestamp = str(int(time.time()))
        signature = base64.b64encode(
            signing_key.sign(
                build_agent_signing_message(agent.id, timestamp, nonce, payload)
            )
        ).decode()
        return request_with_headers(
            {
                "X-Guardian-Proxy-Auth": "p" * 48,
                "X-Guardian-Client-Certificate-Der": escaped_certificate,
                "X-Agent-Timestamp": timestamp,
                "X-Agent-Nonce": nonce,
                "X-Agent-Signature": signature,
            }
        )

    with SessionLocal() as database:
        database.add(Host(id=agent.host_id, name="production-agent-host", address="192.0.2.30"))
        database.add(agent)
        identity = AgentIdentity(
            agent_id=agent.id,
            generation=1,
            state=AgentIdentityState.active.value,
            signing_public_key=agent.signing_public_key,
            certificate_fingerprint=agent.certificate_fingerprint,
            certificate_serial=agent.certificate_serial,
            verified_at=datetime.now(UTC),
            activated_at=datetime.now(UTC),
        )
        database.add(identity)
        database.flush()
        verify_agent_request(
            request=signed_request("production-nonce-0001"),
            agent=agent,
            payload=payload,
            db=database,
            settings=production_gateway_settings(),
        )

        identity.certificate_serial = "1004"
        database.flush()
        with pytest.raises(HTTPException, match="identity not accepted"):
            verify_agent_request(
                request=signed_request("production-nonce-0002"),
                agent=agent,
                payload=payload,
                db=database,
                settings=production_gateway_settings(),
            )


@pytest.mark.parametrize(
    ("headers", "detail"),
    [
        ({"X-Client-Cert-Fingerprint": "invalid"}, "invalid mTLS fingerprint"),
        (
            {"X-Client-Cert-Fingerprint": "AA" * 32},
            "missing agent signature headers",
        ),
        (
            {
                "X-Client-Cert-Fingerprint": "BB" * 32,
                "X-Agent-Timestamp": "1",
                "X-Agent-Nonce": "n" * 16,
                "X-Agent-Signature": "invalid",
            },
            "agent identity not accepted",
        ),
        (
            {
                "X-Client-Cert-Fingerprint": "AA" * 32,
                "X-Agent-Timestamp": "not-a-timestamp",
                "X-Agent-Nonce": "n" * 16,
                "X-Agent-Signature": "invalid",
            },
            "invalid agent timestamp",
        ),
        (
            {
                "X-Client-Cert-Fingerprint": "AA" * 32,
                "X-Agent-Timestamp": "0",
                "X-Agent-Nonce": "n" * 16,
                "X-Agent-Signature": "invalid",
            },
            "expired agent request",
        ),
    ],
)
def test_agent_request_rejection_paths(headers: dict[str, str], detail: str) -> None:
    agent = Agent(
        id="rejection-agent",
        host_id="rejection-host",
        signing_public_key=base64.b64encode(b"A" * 32).decode(),
        certificate_fingerprint="AA" * 32,
    )
    settings = Settings.model_construct(environment="test", nonce_ttl_seconds=300)
    with SessionLocal() as database, pytest.raises(HTTPException) as error:
        database.add(Host(id=agent.host_id, name="rejection-agent-host", address="192.0.2.31"))
        database.add(agent)
        database.add(
            AgentIdentity(
                agent_id=agent.id,
                generation=1,
                state=AgentIdentityState.active.value,
                signing_public_key=agent.signing_public_key,
                certificate_fingerprint=agent.certificate_fingerprint,
                certificate_serial=agent.certificate_serial,
                verified_at=datetime.now(UTC),
                activated_at=datetime.now(UTC),
            )
        )
        database.flush()
        verify_agent_request(
            request=request_with_headers(headers),
            agent=agent,
            payload=b"{}",
            db=database,
            settings=settings,
        )
    assert error.value.detail == detail


def test_signed_heartbeat_and_replay_rejection(client: TestClient) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    enrollment = client.post(
        "/api/v1/agents/enroll",
        headers={"X-Enrollment-Token": "test-enrollment-token"},
        json={
            "host": {"name": "agent-node", "address": "192.0.2.20"},
            "signing_public_key": base64.b64encode(public_key).decode(),
            "certificate_fingerprint": "AA:" * 31 + "AA",
            "version": "0.1.0",
        },
    )
    assert enrollment.status_code == 200
    agent_id = enrollment.json()["agent_id"]
    payload = {
        "collected_at": "2026-07-15T23:03:04.123456789Z",
        "version": "0.1.0",
        "metrics": {"cpu_percent": 12.5, "memory_percent": 33.0},
        "services": [
            {
                "kind": "journal_errors",
                "summary": "Authorization: Bearer super-secret-agent-token",
            }
        ],
        "events": [
            {
                "type": "heartbeat_failed",
                "at": "2026-07-15T23:03:00Z",
                "summary_sha256": "a" * 64,
                "password": "super-secret-event-password",
            }
        ],
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    signature = base64.b64encode(
        private_key.sign(build_agent_signing_message(agent_id, timestamp, nonce, payload_bytes))
    ).decode()
    headers = {
        "Content-Type": "application/json",
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": signature,
        "X-Client-Cert-Fingerprint": "AA:" * 31 + "AA",
    }
    tampered = client.post(
        f"/api/v1/agents/{agent_id}/heartbeat",
        headers=headers,
        content=payload_bytes.replace(b"12.5", b"12.6"),
    )
    assert tampered.status_code == 401
    assert tampered.json()["detail"] == "invalid agent signature"
    response = client.post(
        f"/api/v1/agents/{agent_id}/heartbeat",
        headers=headers,
        content=payload_bytes,
    )
    assert response.status_code == 202
    with SessionLocal() as database:
        snapshot = database.query(MetricSnapshot).one()
        assert "super-secret-agent-token" not in str(snapshot.payload)
        assert "super-secret-event-password" not in str(snapshot.payload)
        assert "[REDACTED]" in str(snapshot.payload)
        events = snapshot.payload["_events"]
        assert isinstance(events, list)
        assert isinstance(events[0], dict)
        assert events[0]["at"] == "2026-07-15T23:03:00Z"
    replay = client.post(
        f"/api/v1/agents/{agent_id}/heartbeat",
        headers=headers,
        content=payload_bytes,
    )
    assert replay.status_code == 409


def test_unsigned_heartbeat_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/v1/agents/not-enrolled/heartbeat",
        json={
            "collected_at": datetime.now(UTC).isoformat(),
            "version": "0.1.0",
            "metrics": {},
        },
    )
    assert response.status_code == 404
