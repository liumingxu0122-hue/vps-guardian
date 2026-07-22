from __future__ import annotations

import base64
import binascii
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from guardian.agent_security import normalize_certificate_serial
from guardian.config import Settings

MAX_PEM_BYTES = 32_768


class AgentCertificateError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class IssuedAgentCertificate:
    certificate_pem: str
    ca_bundle_pem: str
    fingerprint: str
    serial: str
    expires_at: datetime


def _read_pem(path: Path, *, label: str, private: bool, production: bool) -> bytes:
    if production and not path.is_absolute():
        raise AgentCertificateError(f"{label} path must be absolute")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        raise AgentCertificateError(f"{label} file is missing or unsafe") from exc
    if resolved != path.resolve() or path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise AgentCertificateError(f"{label} file is missing or unsafe")
    if production and os.name == "posix":
        mode = stat.S_IMODE(metadata.st_mode)
        if metadata.st_uid != 0 or (private and mode & 0o033) or (not private and mode & 0o022):
            raise AgentCertificateError(f"{label} file permissions are unsafe")
    if metadata.st_size < 1 or metadata.st_size > MAX_PEM_BYTES:
        raise AgentCertificateError(f"{label} file has an invalid size")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise AgentCertificateError(f"{label} file is unreadable") from exc


def validate_agent_csr(csr_pem: str) -> x509.CertificateSigningRequest:
    if len(csr_pem.encode("utf-8")) > MAX_PEM_BYTES:
        raise AgentCertificateError("CSR is too large")
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise AgentCertificateError("CSR is invalid") from exc
    if not csr.is_signature_valid:
        raise AgentCertificateError("CSR signature is invalid")
    public_key = csr.public_key()
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if not isinstance(public_key.curve, (ec.SECP256R1, ec.SECP384R1)):
            raise AgentCertificateError("CSR algorithm is not allowed")
    elif isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 3072:
            raise AgentCertificateError("CSR RSA key is too weak")
    else:
        raise AgentCertificateError("CSR algorithm is not allowed")
    signature_hash = csr.signature_hash_algorithm
    if signature_hash is None or signature_hash.name not in {"sha256", "sha384", "sha512"}:
        raise AgentCertificateError("CSR signature hash is not allowed")
    return csr


def verify_signing_key_proof(
    *, csr_pem: str, signing_public_key: str, signing_key_proof: str
) -> None:
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            base64.b64decode(signing_public_key, validate=True)
        )
        proof = base64.b64decode(signing_key_proof, validate=True)
        public_key.verify(proof, csr_pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError, binascii.Error, InvalidSignature) as exc:
        raise AgentCertificateError("signing key proof is invalid") from exc


def issue_agent_certificate(
    *,
    csr_pem: str,
    agent_id: str,
    host_id: str,
    settings: Settings,
    now: datetime | None = None,
) -> IssuedAgentCertificate:
    csr = validate_agent_csr(csr_pem)
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
        ca_certificate = x509.load_pem_x509_certificate(certificate_bytes)
        ca_private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
    except (TypeError, ValueError) as exc:
        raise AgentCertificateError("Agent CA material is invalid") from exc
    if not isinstance(
        ca_private_key,
        (ed25519.Ed25519PrivateKey, ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey),
    ):
        raise AgentCertificateError("Agent CA private key algorithm is not allowed")
    ca_public = ca_certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_public = ca_private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if ca_public != key_public:
        raise AgentCertificateError("Agent CA certificate and private key do not match")
    try:
        constraints = ca_certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        usage = ca_certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise AgentCertificateError("Agent CA constraints or key usage is missing") from exc
    if not constraints.ca or not usage.key_cert_sign or not usage.crl_sign:
        raise AgentCertificateError("Agent CA is not authorized for certificate and CRL signing")

    issued_at = now or datetime.now(UTC)
    expires_at = min(
        issued_at + timedelta(hours=settings.agent_certificate_ttl_hours),
        ca_certificate.not_valid_after_utc,
    )
    if expires_at <= issued_at:
        raise AgentCertificateError("Agent CA is expired")
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"guardian-agent-{agent_id}")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(issued_at - timedelta(minutes=5))
        .not_valid_after(expires_at)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(f"spiffe://vps-guardian/agents/{agent_id}")]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1"), host_id.encode("ascii")
            ),
            critical=False,
        )
    )
    if isinstance(ca_private_key, ed25519.Ed25519PrivateKey):
        certificate = builder.sign(private_key=ca_private_key, algorithm=None)
    else:
        certificate = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    ca_bundle_pem = ca_certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return IssuedAgentCertificate(
        certificate_pem=certificate_pem,
        ca_bundle_pem=ca_bundle_pem,
        fingerprint=certificate.fingerprint(hashes.SHA256()).hex().upper(),
        serial=normalize_certificate_serial(format(certificate.serial_number, "X")),
        expires_at=certificate.not_valid_after_utc,
    )


def validate_agent_gateway_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise AgentCertificateError("Agent gateway URL must be an HTTPS origin")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise AgentCertificateError("Agent gateway URL must not include a path, query, or fragment")
    return value.rstrip("/")
