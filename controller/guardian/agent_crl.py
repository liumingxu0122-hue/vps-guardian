from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from guardian.agent_pki import AgentCertificateError, _read_pem
from guardian.agent_security import normalize_certificate_serial
from guardian.config import Settings

AgentCAPrivateKey = (
    ed25519.Ed25519PrivateKey | ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey
)


@dataclass(frozen=True, slots=True)
class GeneratedAgentCRL:
    pem: bytes
    number: int
    sha256: str
    revoked_serial: str


def _load_ca(settings: Settings) -> tuple[x509.Certificate, AgentCAPrivateKey]:
    production = settings.environment == "production"
    certificate_bytes = _read_pem(
        settings.agent_ca_certificate_file,
        label="Agent CA certificate",
        private=False,
        production=production,
    )
    private_key_bytes = _read_pem(
        settings.agent_ca_private_key_file,
        label="Agent CA private key",
        private=True,
        production=production,
    )
    try:
        certificate = x509.load_pem_x509_certificate(certificate_bytes)
        private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
    except (TypeError, ValueError) as exc:
        raise AgentCertificateError("Agent CA material is invalid") from exc
    if not isinstance(
        private_key,
        (ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey),
    ):
        raise AgentCertificateError("Agent CA private key algorithm is not allowed")
    certificate_public = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if certificate_public != key_public:
        raise AgentCertificateError("Agent CA certificate and private key do not match")
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise AgentCertificateError("Agent CA key usage is missing") from exc
    if not usage.crl_sign:
        raise AgentCertificateError("Agent CA is not allowed to sign CRLs")
    return certificate, private_key


def generate_agent_crl(
    *,
    current_crl_pem: bytes,
    revoked_serial: str,
    settings: Settings,
    now: datetime | None = None,
) -> GeneratedAgentCRL:
    ca_certificate, ca_private_key = _load_ca(settings)
    try:
        current = x509.load_pem_x509_crl(current_crl_pem)
    except ValueError as exc:
        raise AgentCertificateError("current Agent CRL is invalid") from exc
    issuer_public_key = ca_private_key.public_key()
    if current.issuer != ca_certificate.subject or not current.is_signature_valid(
        issuer_public_key
    ):
        raise AgentCertificateError("current Agent CRL signature or issuer is invalid")
    try:
        current_number = current.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound as exc:
        raise AgentCertificateError("current Agent CRL has no CRL number") from exc
    normalized_serial = normalize_certificate_serial(revoked_serial)
    serial_number = int(normalized_serial, 16)
    if any(entry.serial_number == serial_number for entry in current):
        raise AgentCertificateError("certificate serial is already present in the Agent CRL")

    issued_at = (now or datetime.now(UTC)).replace(microsecond=0)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_certificate.subject)
        .last_update(issued_at)
        .next_update(min(issued_at + timedelta(days=7), ca_certificate.not_valid_after_utc))
        .add_extension(x509.CRLNumber(current_number + 1), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public_key),
            critical=False,
        )
    )
    for entry in current:
        builder = builder.add_revoked_certificate(entry)
    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(serial_number)
        .revocation_date(issued_at)
        .add_extension(x509.CRLReason(x509.ReasonFlags.cessation_of_operation), critical=False)
        .build()
    )
    builder = builder.add_revoked_certificate(revoked)
    if isinstance(ca_private_key, ed25519.Ed25519PrivateKey):
        generated = builder.sign(private_key=ca_private_key, algorithm=None)
    else:
        generated = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    pem = generated.public_bytes(serialization.Encoding.PEM)
    return GeneratedAgentCRL(
        pem=pem,
        number=current_number + 1,
        sha256=hashlib.sha256(pem).hexdigest(),
        revoked_serial=normalized_serial,
    )


def read_serial_file(path: Path) -> str:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise AgentCertificateError("certificate serial file must be an absolute regular file")
    if path.stat().st_size < 1 or path.stat().st_size > 256:
        raise AgentCertificateError("certificate serial file has an invalid size")
    return normalize_certificate_serial(path.read_text(encoding="ascii").strip())
