from __future__ import annotations

import base64
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient
from guardian.agent_crl import generate_agent_crl
from guardian.agent_pki import AgentCertificateError, issue_agent_certificate
from guardian.agent_security import build_agent_signing_message
from guardian.config import get_settings
from guardian.database import SessionLocal
from guardian.models import Agent, AgentIdentity, AuditLog, EnrollmentToken
from pydantic import SecretStr
from sqlalchemy import select


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_ca(directory: Path) -> tuple[Path, Path]:
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Phase 4C Test Agent CA")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, None)
    )
    key_path = directory / "agent-ca.key"
    certificate_path = directory / "agent-ca.crt"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return certificate_path, key_path


def create_crl_ca(
    directory: Path,
) -> tuple[Path, Path, x509.Certificate, ed25519.Ed25519PrivateKey]:
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Phase 4C CRL CA")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, None)
    )
    key_path = directory / "crl-ca.key"
    certificate_path = directory / "crl-ca.crt"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return certificate_path, key_path, certificate, key


def create_empty_crl(certificate: x509.Certificate, key: ed25519.Ed25519PrivateKey) -> bytes:
    now = datetime.now(UTC).replace(microsecond=0)
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(certificate.subject)
        .last_update(now - timedelta(minutes=1))
        .next_update(now + timedelta(days=7))
        .add_extension(x509.CRLNumber(10), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(certificate.public_key()),
            critical=False,
        )
        .sign(key, None)
        .public_bytes(serialization.Encoding.PEM)
    )


def create_csr(
    key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey,
) -> str:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-local")]))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )


@pytest.fixture
def configured_ca(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    certificate_path, key_path = create_ca(tmp_path)
    settings = get_settings()
    monkeypatch.setattr(settings, "agent_ca_certificate_file", certificate_path)
    monkeypatch.setattr(settings, "agent_ca_private_key_file", key_path)
    monkeypatch.setattr(settings, "agent_gateway_url", "https://agents.example.test:8444")


def signing_identity() -> tuple[ed25519.Ed25519PrivateKey, str]:
    key = ed25519.Ed25519PrivateKey.generate()
    encoded = base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")
    return key, encoded


def create_host_and_token(
    client: TestClient,
    owner_token: str,
    *,
    name: str = "phase4c-node",
) -> tuple[str, dict[str, object]]:
    host = client.post(
        "/api/v1/hosts",
        headers=auth(owner_token),
        json={"name": name, "address": "192.0.2.120", "tags": ["phase4c", "staging"]},
    )
    assert host.status_code == 201
    host_id = str(host.json()["id"])
    issued = client.post(
        f"/api/v1/hosts/{host_id}/enrollment-token",
        headers=auth(owner_token),
        json={"expires_in_minutes": 15},
    )
    assert issued.status_code == 201
    return host_id, dict(issued.json())


def bootstrap_payload(
    host_id: str,
    *,
    tls_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | None = None,
    signing_public_key: str | None = None,
) -> tuple[dict[str, str], ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey]:
    actual_tls_key = tls_key or ec.generate_private_key(ec.SECP256R1())
    signing_key, actual_signing_public_key = signing_identity()
    return (
        {
            "host_id": host_id,
            "csr_pem": create_csr(actual_tls_key),
            "signing_public_key": signing_public_key or actual_signing_public_key,
            "version": "0.1.0-phase4c-test",
        },
        actual_tls_key,
        signing_key,
    )


def test_pki_issues_client_only_certificate_with_bound_identity(
    configured_ca: None,
) -> None:
    del configured_ca
    settings = get_settings()
    tls_key = ec.generate_private_key(ec.SECP256R1())
    issued = issue_agent_certificate(
        csr_pem=create_csr(tls_key),
        agent_id=str(uuid.uuid4()),
        host_id=str(uuid.uuid4()),
        settings=settings,
    )
    certificate = x509.load_pem_x509_certificate(issued.certificate_pem.encode("ascii"))
    assert certificate.public_key().public_numbers() == tls_key.public_key().public_numbers()
    assert certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    assert "PRIVATE KEY" not in issued.certificate_pem
    assert "PRIVATE KEY" not in issued.ca_bundle_pem


def test_crl_generation_is_signed_monotonic_and_preserves_revocations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate_path, key_path, certificate, key = create_crl_ca(tmp_path)
    settings = get_settings()
    monkeypatch.setattr(settings, "agent_ca_certificate_file", certificate_path)
    monkeypatch.setattr(settings, "agent_ca_private_key_file", key_path)
    first = generate_agent_crl(
        current_crl_pem=create_empty_crl(certificate, key),
        revoked_serial="A001",
        settings=settings,
    )
    second = generate_agent_crl(
        current_crl_pem=first.pem,
        revoked_serial="A002",
        settings=settings,
    )
    parsed = x509.load_pem_x509_crl(second.pem)
    assert parsed.is_signature_valid(certificate.public_key())
    assert parsed.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 12
    assert {entry.serial_number for entry in parsed} == {0xA001, 0xA002}
    assert len(second.sha256) == 64
    with pytest.raises(AgentCertificateError, match="already present"):
        generate_agent_crl(
            current_crl_pem=second.pem,
            revoked_serial="A001",
            settings=settings,
        )


@pytest.mark.parametrize(
    "key",
    [rsa.generate_private_key(public_exponent=65537, key_size=2048)],
)
def test_pki_rejects_weak_csr(
    configured_ca: None,
    key: rsa.RSAPrivateKey,
) -> None:
    del configured_ca
    with pytest.raises(AgentCertificateError, match="too weak"):
        issue_agent_certificate(
            csr_pem=create_csr(key),
            agent_id=str(uuid.uuid4()),
            host_id=str(uuid.uuid4()),
            settings=get_settings(),
        )


def test_bootstrap_is_host_bound_single_use_and_audited_without_secrets(
    client: TestClient,
    owner_token: str,
    configured_ca: None,
) -> None:
    del configured_ca
    host_id, issued_token = create_host_and_token(client, owner_token)
    payload, tls_key, _ = bootstrap_payload(host_id)
    token = str(issued_token["token"])
    enrolled = client.post(
        "/api/v1/agents/bootstrap",
        headers={"X-Enrollment-Token": token},
        json=payload,
    )
    replay = client.post(
        "/api/v1/agents/bootstrap",
        headers={"X-Enrollment-Token": token},
        json=payload,
    )
    assert enrolled.status_code == 200
    assert replay.status_code == 401
    response = enrolled.json()
    certificate = x509.load_pem_x509_certificate(response["certificate_pem"].encode())
    assert certificate.public_key().public_numbers() == tls_key.public_key().public_numbers()
    assert response["agent_gateway_endpoint"] == "https://agents.example.test:8444"
    assert "--host-id" in str(issued_token["install_command"])
    for forbidden in ("--private-key", "--certificate", token):
        assert forbidden not in str(issued_token["install_command"])
    with SessionLocal() as db:
        stored = db.scalar(select(EnrollmentToken))
        assert stored and stored.used_at is not None and token not in stored.token_hash
        audit_text = " ".join(str(entry.details) for entry in db.scalars(select(AuditLog)))
        assert token not in audit_text
        assert "PRIVATE KEY" not in audit_text


def test_production_bootstrap_requires_the_private_agent_gateway(
    client: TestClient,
    owner_token: str,
    configured_ca: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del configured_ca
    settings = get_settings()
    proxy_secret = "phase4c-test-proxy-secret-value-123456"
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "trusted_proxy_cert_header_secret", SecretStr(proxy_secret))
    host_id, issued = create_host_and_token(client, owner_token, name="gateway-bound-node")
    payload, _, _ = bootstrap_payload(host_id)
    direct = client.post(
        "/api/v1/agents/bootstrap",
        headers={"X-Enrollment-Token": str(issued["token"])},
        json=payload,
    )
    gateway = client.post(
        "/api/v1/agents/bootstrap",
        headers={
            "X-Enrollment-Token": str(issued["token"]),
            "X-Guardian-Proxy-Auth": proxy_secret,
        },
        json=payload,
    )
    assert direct.status_code == 401
    assert gateway.status_code == 200


def test_revoked_expired_wrong_host_and_invalid_csr_are_rejected(
    client: TestClient,
    owner_token: str,
    configured_ca: None,
) -> None:
    del configured_ca
    host_id, revoked = create_host_and_token(client, owner_token, name="revoked-node")
    revoke = client.post(
        f"/api/v1/hosts/{host_id}/enrollment-tokens/{revoked['id']}/revoke",
        headers=auth(owner_token),
    )
    payload, _, _ = bootstrap_payload(host_id)
    assert revoke.status_code == 204
    assert client.post(
        "/api/v1/agents/bootstrap",
        headers={"X-Enrollment-Token": str(revoked["token"])},
        json=payload,
    ).status_code == 401

    expired_host, expired = create_host_and_token(client, owner_token, name="expired-node")
    with SessionLocal() as db:
        token = db.get(EnrollmentToken, str(expired["id"]))
        assert token
        token.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    expired_payload, _, _ = bootstrap_payload(expired_host)
    assert client.post(
        "/api/v1/agents/bootstrap",
        headers={"X-Enrollment-Token": str(expired["token"])},
        json=expired_payload,
    ).status_code == 401

    first_host, bound = create_host_and_token(client, owner_token, name="bound-node")
    second_host, _ = create_host_and_token(client, owner_token, name="other-node")
    wrong_payload, _, _ = bootstrap_payload(second_host)
    assert client.post(
        "/api/v1/agents/bootstrap",
        headers={"X-Enrollment-Token": str(bound["token"])},
        json=wrong_payload,
    ).status_code == 401
    invalid_payload, _, _ = bootstrap_payload(first_host)
    invalid_payload["csr_pem"] = "-----BEGIN CERTIFICATE REQUEST-----\ninvalid\n"
    assert client.post(
        "/api/v1/agents/bootstrap",
        headers={"X-Enrollment-Token": str(bound["token"])},
        json=invalid_payload,
    ).status_code == 422
    valid_payload, _, _ = bootstrap_payload(first_host)
    assert client.post(
        "/api/v1/agents/bootstrap",
        headers={"X-Enrollment-Token": str(bound["token"])},
        json=valid_payload,
    ).status_code == 200


def test_rate_limit_and_sequential_reuse_allow_exactly_one_enrollment(
    client: TestClient,
    owner_token: str,
    configured_ca: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del configured_ca
    settings = get_settings()
    monkeypatch.setattr(settings, "enrollment_attempts_per_10m", 2)
    host_id, issued = create_host_and_token(client, owner_token, name="limited-node")
    payload, _, _ = bootstrap_payload(host_id)
    invalid = {**payload, "csr_pem": "not-a-csr".ljust(256, "x")}
    for _ in range(2):
        assert client.post(
            "/api/v1/agents/bootstrap",
            headers={"X-Enrollment-Token": str(issued["token"])},
            json=invalid,
        ).status_code == 422
    assert client.post(
        "/api/v1/agents/bootstrap",
        headers={"X-Enrollment-Token": str(issued["token"])},
        json=payload,
    ).status_code == 429

    from guardian.enrollment import enrollment_limiter

    enrollment_limiter.clear()
    other_host, other = create_host_and_token(client, owner_token, name="concurrent-node")
    other_payload, _, _ = bootstrap_payload(other_host)

    first = client.post(
        "/api/v1/agents/bootstrap",
        headers={"X-Enrollment-Token": str(other["token"])},
        json=other_payload,
    )
    replay = client.post(
        "/api/v1/agents/bootstrap",
        headers={"X-Enrollment-Token": str(other["token"])},
        json=other_payload,
    )
    assert first.status_code == 200
    assert replay.status_code == 401


def signed_headers(
    *,
    agent_id: str,
    private_key: ed25519.Ed25519PrivateKey,
    fingerprint: str,
    payload: bytes,
) -> dict[str, str]:
    timestamp = str(int(datetime.now(UTC).timestamp()))
    nonce = secrets.token_urlsafe(24)
    signature = private_key.sign(build_agent_signing_message(agent_id, timestamp, nonce, payload))
    return {
        "Content-Type": "application/json",
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": base64.b64encode(signature).decode("ascii"),
        "X-Client-Cert-Fingerprint": fingerprint,
    }


def test_active_mtls_identity_can_renew_with_dual_key_possession_proof(
    client: TestClient,
    owner_token: str,
    configured_ca: None,
) -> None:
    del configured_ca
    host_id, issued = create_host_and_token(client, owner_token, name="renew-node")
    bootstrap, _, old_signing_key = bootstrap_payload(host_id)
    enrolled = client.post(
        "/api/v1/agents/bootstrap",
        headers={"X-Enrollment-Token": str(issued["token"])},
        json=bootstrap,
    )
    assert enrolled.status_code == 200
    agent_id = str(enrolled.json()["agent_id"])
    old_certificate = x509.load_pem_x509_certificate(
        enrolled.json()["certificate_pem"].encode("ascii")
    )
    old_fingerprint = old_certificate.fingerprint(hashes.SHA256()).hex().upper()

    new_tls_key = ec.generate_private_key(ec.SECP256R1())
    csr_pem = create_csr(new_tls_key)
    new_signing_key, new_public_key = signing_identity()
    renewal_payload = {
        "rotation_id": str(uuid.uuid4()),
        "expected_version": 1,
        "csr_pem": csr_pem,
        "signing_public_key": new_public_key,
        "signing_key_proof": base64.b64encode(
            new_signing_key.sign(csr_pem.encode("ascii"))
        ).decode("ascii"),
    }
    body = json.dumps(renewal_payload, separators=(",", ":")).encode()
    renewed = client.post(
        f"/api/v1/agents/{agent_id}/certificate/renew",
        headers=signed_headers(
            agent_id=agent_id,
            private_key=old_signing_key,
            fingerprint=old_fingerprint,
            payload=body,
        ),
        content=body,
    )
    assert renewed.status_code == 200
    assert renewed.json()["identity"]["generation"] == 2
    with SessionLocal() as db:
        agent = db.get(Agent, agent_id)
        identities = list(
            db.scalars(
                select(AgentIdentity)
                .where(AgentIdentity.agent_id == agent_id)
                .order_by(AgentIdentity.generation)
            )
        )
        assert agent and agent.identity_version == 2
        assert [identity.state for identity in identities] == ["retiring", "active"]
        assert db.scalar(
            select(AuditLog).where(AuditLog.action == "agent.certificate_renewed")
        )
