from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPublicKeyTypes

TRUST_MATERIAL_SCHEMA = "vps-guardian-trust-material/v2"
MAX_CERTIFICATE_BYTES = 1_048_576
MAX_PRIVATE_KEY_BYTES = 65_536
MAX_PUBLIC_KEY_BYTES = 4_096
MAX_MANIFEST_BYTES = 1_048_576


class TrustMaterialError(RuntimeError):
    pass


@dataclass(frozen=True)
class TrustMaterialPaths:
    agent_ca: Path
    agent_crl: Path
    controller_signing_key: Path
    controller_public_key: Path
    gateway_certificate: Path
    gateway_issuer_ca: Path


@dataclass(frozen=True)
class _LoadedCRL:
    data: bytes
    value: x509.CertificateRevocationList
    number: int
    revoked_serials: frozenset[int]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular_file(path: Path, *, label: str, maximum_bytes: int) -> bytes:
    if not path.is_absolute():
        raise TrustMaterialError(f"{label} path must be absolute")
    try:
        supplied = path
        resolved = supplied.resolve(strict=True)
        metadata = supplied.lstat()
    except OSError as exc:
        raise TrustMaterialError(f"{label} is missing or unreadable") from exc
    if resolved != supplied or stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise TrustMaterialError(f"{label} path is not a canonical regular file")
    if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
        raise TrustMaterialError(f"{label} has an invalid size")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(supplied, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise TrustMaterialError(f"{label} changed while it was being read")
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise TrustMaterialError(f"{label} changed while it was being read")
            data = handle.read(maximum_bytes + 1)
    except TrustMaterialError:
        raise
    except OSError as exc:
        raise TrustMaterialError(f"{label} is missing or unreadable") from exc
    if len(data) != metadata.st_size or len(data) > maximum_bytes:
        raise TrustMaterialError(f"{label} changed while it was being read")
    return data


def _require_single_pem_block(data: bytes, *, label: str, block_name: bytes) -> None:
    begin = b"-----BEGIN " + block_name + b"-----"
    end = b"-----END " + block_name + b"-----"
    if data.count(begin) != 1 or data.count(end) != 1:
        raise TrustMaterialError(f"{label} must contain exactly one PEM object")
    begin_at = data.find(begin)
    end_at = data.find(end, begin_at) + len(end)
    if data[:begin_at].strip() or data[end_at:].strip():
        raise TrustMaterialError(f"{label} contains data outside its PEM object")


def _load_certificate(path: Path, *, label: str) -> tuple[bytes, x509.Certificate]:
    data = _read_regular_file(path, label=label, maximum_bytes=MAX_CERTIFICATE_BYTES)
    _require_single_pem_block(data, label=label, block_name=b"CERTIFICATE")
    try:
        certificate = x509.load_pem_x509_certificate(data)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise TrustMaterialError(f"{label} is not a supported X.509 certificate") from exc
    return data, certificate


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    data = _read_regular_file(
        path,
        label="Controller signing key",
        maximum_bytes=MAX_PRIVATE_KEY_BYTES,
    )
    begin_markers = data.count(b"-----BEGIN ")
    end_markers = data.count(b"-----END ")
    if begin_markers != 1 or end_markers != 1:
        raise TrustMaterialError("Controller signing key must contain exactly one PEM object")
    begin_at = data.find(b"-----BEGIN ")
    end_at = data.find(b"-----END ", begin_at)
    end_marker_end = data.find(b"-----", end_at + len(b"-----END "))
    if (
        begin_at < 0
        or end_at < 0
        or end_marker_end < 0
        or data[:begin_at].strip()
        or data[end_marker_end + len(b"-----") :].strip()
    ):
        raise TrustMaterialError("Controller signing key contains data outside its PEM object")
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise TrustMaterialError(
            "Controller signing key is not a supported unencrypted key"
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise TrustMaterialError("Controller signing key must be Ed25519")
    return key


def _subject_key_identifier(certificate: x509.Certificate, *, label: str) -> bytes:
    try:
        identifier = certificate.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value.digest
    except x509.ExtensionNotFound as exc:
        raise TrustMaterialError(f"{label} has no subject key identifier") from exc
    if not identifier:
        raise TrustMaterialError(f"{label} has an empty subject key identifier")
    return identifier


def _authority_key_identifier(
    extensions: x509.Extensions,
    *,
    label: str,
) -> bytes:
    try:
        identifier = extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value.key_identifier
    except x509.ExtensionNotFound as exc:
        raise TrustMaterialError(f"{label} has no authority key identifier") from exc
    if not identifier:
        raise TrustMaterialError(f"{label} has no authority key identifier key ID")
    return identifier


def _require_ca(certificate: x509.Certificate, *, label: str) -> None:
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise TrustMaterialError(f"{label} has no basic constraints") from exc
    if not constraints.ca:
        raise TrustMaterialError(f"{label} is not a CA certificate")
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise TrustMaterialError(f"{label} has no key usage") from exc
    if not usage.key_cert_sign or not usage.crl_sign:
        raise TrustMaterialError(f"{label} key usage cannot issue certificates and CRLs")


def _require_leaf_server_certificate(certificate: x509.Certificate) -> None:
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise TrustMaterialError("gateway certificate has no basic constraints") from exc
    if constraints.ca:
        raise TrustMaterialError("gateway certificate cannot be a CA certificate")
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise TrustMaterialError("gateway certificate has no key usage") from exc
    if not usage.digital_signature:
        raise TrustMaterialError("gateway certificate cannot authenticate a TLS server")
    try:
        purposes = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise TrustMaterialError("gateway certificate has no extended key usage") from exc
    if x509.oid.ExtendedKeyUsageOID.SERVER_AUTH not in purposes:
        raise TrustMaterialError("gateway certificate is not valid for TLS server authentication")


def _require_current_interval(
    not_before: datetime,
    not_after: datetime,
    *,
    now: datetime,
    label: str,
) -> None:
    if not_before >= not_after:
        raise TrustMaterialError(f"{label} validity interval is invalid")
    if now < not_before:
        raise TrustMaterialError(f"{label} is not yet valid")
    if now >= not_after:
        raise TrustMaterialError(f"{label} is expired")


def _verify_direct_issuer(
    certificate: x509.Certificate,
    issuer: x509.Certificate,
    *,
    label: str,
) -> None:
    if certificate.issuer != issuer.subject:
        raise TrustMaterialError(f"{label} issuer does not match its issuer certificate")
    try:
        certificate.verify_directly_issued_by(issuer)
    except (InvalidSignature, TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise TrustMaterialError(
            f"{label} signature is not valid for its issuer certificate"
        ) from exc


def _format_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _certificate_metadata(
    data: bytes,
    certificate: x509.Certificate,
    *,
    artifact: str,
) -> dict[str, Any]:
    return {
        "artifact": artifact,
        "artifact_sha256": _sha256(data),
        "authority_key_identifier": _authority_key_identifier(
            certificate.extensions,
            label=artifact,
        ).hex(),
        "der_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "issuer": certificate.issuer.rfc4514_string(),
        "not_after": _format_datetime(certificate.not_valid_after_utc),
        "not_before": _format_datetime(certificate.not_valid_before_utc),
        "serial_number": format(certificate.serial_number, "X"),
        "signature_algorithm_oid": certificate.signature_algorithm_oid.dotted_string,
        "subject": certificate.subject.rfc4514_string(),
        "subject_key_identifier": _subject_key_identifier(
            certificate,
            label=artifact,
        ).hex(),
    }


def _load_crl(
    path: Path,
    *,
    agent_ca: x509.Certificate,
    agent_ca_ski: bytes,
    label: str,
    now: datetime,
    require_current: bool,
) -> _LoadedCRL:
    data = _read_regular_file(path, label=label, maximum_bytes=MAX_CERTIFICATE_BYTES)
    _require_single_pem_block(data, label=label, block_name=b"X509 CRL")
    try:
        crl = x509.load_pem_x509_crl(data)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise TrustMaterialError(f"{label} is not a supported X.509 CRL") from exc
    if crl.issuer != agent_ca.subject:
        raise TrustMaterialError(f"{label} issuer does not match the Agent CA")
    if _authority_key_identifier(crl.extensions, label=label) != agent_ca_ski:
        raise TrustMaterialError(f"{label} authority key identifier does not match the Agent CA")
    try:
        issuer_public_key = cast(CertificateIssuerPublicKeyTypes, agent_ca.public_key())
        signature_valid = crl.is_signature_valid(issuer_public_key)
    except (InvalidSignature, TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise TrustMaterialError(f"{label} signature could not be verified") from exc
    if not signature_valid:
        raise TrustMaterialError(f"{label} signature is not valid for the Agent CA")
    try:
        number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound as exc:
        raise TrustMaterialError(f"{label} has no CRL number") from exc
    if number < 0:
        raise TrustMaterialError(f"{label} has an invalid CRL number")
    if len(str(number)) > 40:
        raise TrustMaterialError(f"{label} CRL number is too large")
    if crl.next_update_utc is None:
        raise TrustMaterialError(f"{label} has no nextUpdate")
    if crl.last_update_utc >= crl.next_update_utc:
        raise TrustMaterialError(f"{label} update interval is invalid")
    if (
        crl.last_update_utc < agent_ca.not_valid_before_utc
        or crl.next_update_utc > agent_ca.not_valid_after_utc
    ):
        raise TrustMaterialError(f"{label} validity exceeds the Agent CA validity")
    if require_current:
        _require_current_interval(
            crl.last_update_utc,
            crl.next_update_utc,
            now=now,
            label=label,
        )
        if crl.next_update_utc <= now + timedelta(minutes=5):
            raise TrustMaterialError(f"{label} expires within the five-minute safety margin")
    serials = tuple(entry.serial_number for entry in crl)
    revoked_serials = frozenset(serials)
    if len(serials) != len(revoked_serials):
        raise TrustMaterialError(f"{label} contains a duplicate revoked certificate serial")
    return _LoadedCRL(
        data=data,
        value=crl,
        number=number,
        revoked_serials=revoked_serials,
    )


def _verify_crl_advance(current: _LoadedCRL, previous: _LoadedCRL) -> None:
    if current.number < previous.number:
        raise TrustMaterialError("Agent CRL number rolls back the previous CRL")
    if current.number == previous.number and current.data != previous.data:
        raise TrustMaterialError("Agent CRL content changed without advancing the CRL number")
    if current.number > previous.number:
        if current.value.last_update_utc < previous.value.last_update_utc:
            raise TrustMaterialError("Agent CRL thisUpdate rolls back the previous CRL")
        if not previous.revoked_serials.issubset(current.revoked_serials):
            raise TrustMaterialError("Agent CRL omits a previously revoked certificate")


def _canonical_controller_public_key(private_key: Ed25519PrivateKey) -> tuple[bytes, bytes]:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw, base64.b64encode(raw) + b"\n"


def _controller_public_key_metadata(
    private_key: Ed25519PrivateKey,
    public_key_path: Path,
) -> dict[str, Any]:
    raw, canonical = _canonical_controller_public_key(private_key)
    artifact = _read_regular_file(
        public_key_path,
        label="Controller public key",
        maximum_bytes=MAX_PUBLIC_KEY_BYTES,
    )
    if artifact != canonical:
        raise TrustMaterialError(
            "Controller public key artifact does not match the Controller signing key"
        )
    try:
        parsed = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(artifact.removesuffix(b"\n"), validate=True)
        )
    except (ValueError, TypeError) as exc:
        raise TrustMaterialError("Controller public key artifact is invalid") from exc
    parsed_raw = parsed.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if parsed_raw != raw:
        raise TrustMaterialError(
            "Controller public key artifact does not match the Controller signing key"
        )
    return {
        "artifact": "controller-public-key",
        "artifact_sha256": _sha256(artifact),
        "encoding": "base64-raw-ed25519",
        "raw_sha256": _sha256(raw),
        "raw_size": len(raw),
    }


def build_trust_material_manifest(
    paths: TrustMaterialPaths,
    *,
    previous_crl: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if now is not None and now.tzinfo is None:
        raise TrustMaterialError("trust material validation time must include a timezone")
    checked_at = (now or datetime.now(UTC)).astimezone(UTC)
    agent_ca_data, agent_ca = _load_certificate(paths.agent_ca, label="Agent CA certificate")
    gateway_ca_data, gateway_ca = _load_certificate(
        paths.gateway_issuer_ca,
        label="gateway issuer CA certificate",
    )
    gateway_data, gateway = _load_certificate(
        paths.gateway_certificate,
        label="gateway certificate",
    )

    _require_ca(agent_ca, label="Agent CA certificate")
    _require_ca(gateway_ca, label="gateway issuer CA certificate")
    if agent_ca.subject != agent_ca.issuer:
        raise TrustMaterialError("Agent CA certificate is not self-issued")
    if gateway_ca.subject != gateway_ca.issuer:
        raise TrustMaterialError("gateway issuer CA certificate is not self-issued")
    _verify_direct_issuer(agent_ca, agent_ca, label="Agent CA certificate")
    _verify_direct_issuer(gateway_ca, gateway_ca, label="gateway issuer CA certificate")
    _require_current_interval(
        agent_ca.not_valid_before_utc,
        agent_ca.not_valid_after_utc,
        now=checked_at,
        label="Agent CA certificate",
    )
    _require_current_interval(
        gateway_ca.not_valid_before_utc,
        gateway_ca.not_valid_after_utc,
        now=checked_at,
        label="gateway issuer CA certificate",
    )

    agent_ca_ski = _subject_key_identifier(agent_ca, label="Agent CA certificate")
    if _authority_key_identifier(
        agent_ca.extensions,
        label="Agent CA certificate",
    ) != agent_ca_ski:
        raise TrustMaterialError("Agent CA authority and subject key identifiers differ")
    gateway_ca_ski = _subject_key_identifier(
        gateway_ca,
        label="gateway issuer CA certificate",
    )
    if _authority_key_identifier(
        gateway_ca.extensions,
        label="gateway issuer CA certificate",
    ) != gateway_ca_ski:
        raise TrustMaterialError("gateway issuer CA authority and subject key identifiers differ")

    _require_leaf_server_certificate(gateway)
    _verify_direct_issuer(gateway, gateway_ca, label="gateway certificate")
    if _authority_key_identifier(
        gateway.extensions,
        label="gateway certificate",
    ) != gateway_ca_ski:
        raise TrustMaterialError(
            "gateway certificate authority key identifier does not match its issuer CA"
        )
    _require_current_interval(
        gateway.not_valid_before_utc,
        gateway.not_valid_after_utc,
        now=checked_at,
        label="gateway certificate",
    )
    if (
        gateway.not_valid_before_utc < gateway_ca.not_valid_before_utc
        or gateway.not_valid_after_utc > gateway_ca.not_valid_after_utc
    ):
        raise TrustMaterialError("gateway certificate validity exceeds its issuer CA validity")

    active_crl = _load_crl(
        paths.agent_crl,
        agent_ca=agent_ca,
        agent_ca_ski=agent_ca_ski,
        label="Agent CRL",
        now=checked_at,
        require_current=True,
    )
    if previous_crl is not None:
        prior = _load_crl(
            previous_crl,
            agent_ca=agent_ca,
            agent_ca_ski=agent_ca_ski,
            label="previous Agent CRL",
            now=checked_at,
            require_current=False,
        )
        _verify_crl_advance(active_crl, prior)

    controller_private_key = _load_private_key(paths.controller_signing_key)
    revoked_serials = [format(serial, "X") for serial in sorted(active_crl.revoked_serials)]
    revoked_set_payload = ("\n".join(revoked_serials) + ("\n" if revoked_serials else "")).encode()
    active_crl_next_update = active_crl.value.next_update_utc
    if active_crl_next_update is None:
        raise TrustMaterialError("Agent CRL has no nextUpdate")
    return {
        "artifacts": {
            "agent_ca": _certificate_metadata(
                agent_ca_data,
                agent_ca,
                artifact="agent-ca.crt",
            ),
            "agent_crl": {
                "artifact": "agent-ca.crl",
                "artifact_sha256": _sha256(active_crl.data),
                "authority_key_identifier": _authority_key_identifier(
                    active_crl.value.extensions,
                    label="Agent CRL",
                ).hex(),
                "crl_number": str(active_crl.number),
                "issuer": active_crl.value.issuer.rfc4514_string(),
                "next_update": _format_datetime(active_crl_next_update),
                "revoked_certificate_count": len(active_crl.revoked_serials),
                "revoked_serials_sha256": _sha256(revoked_set_payload),
                "signature_algorithm_oid": active_crl.value.signature_algorithm_oid.dotted_string,
                "this_update": _format_datetime(active_crl.value.last_update_utc),
            },
            "controller_public_key": _controller_public_key_metadata(
                controller_private_key,
                paths.controller_public_key,
            ),
            "gateway_certificate": _certificate_metadata(
                gateway_data,
                gateway,
                artifact="agent-gateway.crt",
            ),
            "gateway_issuer_ca": _certificate_metadata(
                gateway_ca_data,
                gateway_ca,
                artifact="agent-gateway-issuer-ca.crt",
            ),
        },
        "contains_private_material": False,
        "schema": TRUST_MATERIAL_SCHEMA,
    }


def _destination(path: Path, *, replace: bool) -> Path:
    if not path.is_absolute():
        raise TrustMaterialError("output path must be absolute")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise TrustMaterialError("output parent is missing or unsafe") from exc
    if parent != path.parent or not parent.is_dir():
        raise TrustMaterialError("output parent is not a canonical directory")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return path
    except OSError as exc:
        raise TrustMaterialError("output path is unsafe") from exc
    if not replace:
        raise TrustMaterialError("output already exists")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise TrustMaterialError("output path is not a regular file")
    if path.resolve(strict=True) != path:
        raise TrustMaterialError("output path is not canonical")
    return path


def _canonical_path_for_comparison(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except OSError as exc:
        raise TrustMaterialError("trust material path cannot be resolved") from exc


def _reject_output_input_collision(destination: Path, inputs: tuple[Path, ...]) -> None:
    output = _canonical_path_for_comparison(destination)
    if any(output == _canonical_path_for_comparison(source) for source in inputs):
        raise TrustMaterialError("trust material output must not replace an input artifact")


def _write_atomic(path: Path, payload: bytes, *, replace: bool, mode: int) -> None:
    destination = _destination(path, replace=replace)
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            dir=destination.parent,
        )
        os.chmod(temporary_name, mode)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        if not replace and destination.exists():
            raise TrustMaterialError("output already exists")
        os.replace(temporary_name, destination)
        temporary_name = None
        if os.name == "posix":
            directory = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except TrustMaterialError:
        raise
    except OSError as exc:
        raise TrustMaterialError("could not write trust material output atomically") from exc
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def export_controller_public_key(
    controller_signing_key: Path,
    destination: Path,
    *,
    replace: bool = False,
) -> None:
    _reject_output_input_collision(destination, (controller_signing_key,))
    private_key = _load_private_key(controller_signing_key)
    _, canonical = _canonical_controller_public_key(private_key)
    _write_atomic(destination, canonical, replace=replace, mode=0o644)


def write_trust_material_manifest(
    paths: TrustMaterialPaths,
    destination: Path,
    *,
    previous_crl: Path | None = None,
    replace: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    _reject_output_input_collision(
        destination,
        tuple(
            path
            for path in (
                paths.agent_ca,
                paths.agent_crl,
                paths.controller_signing_key,
                paths.controller_public_key,
                paths.gateway_certificate,
                paths.gateway_issuer_ca,
                previous_crl,
            )
            if path is not None
        ),
    )
    manifest = build_trust_material_manifest(paths, previous_crl=previous_crl, now=now)
    payload = json.dumps(manifest, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    _write_atomic(destination, (payload + "\n").encode(), replace=replace, mode=0o644)
    return manifest


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TrustMaterialError("trust material manifest contains duplicate JSON keys")
        result[key] = value
    return result


def load_trust_material_manifest(path: Path) -> dict[str, Any]:
    data = _read_regular_file(
        path,
        label="trust material manifest",
        maximum_bytes=MAX_MANIFEST_BYTES,
    )
    try:
        value = json.loads(data, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustMaterialError("trust material manifest is not valid JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != TRUST_MATERIAL_SCHEMA:
        raise TrustMaterialError("trust material manifest schema is invalid")
    canonical = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    if data != (canonical + "\n").encode():
        raise TrustMaterialError("trust material manifest is not canonical JSON")
    return value


def verify_trust_material_manifest(
    paths: TrustMaterialPaths,
    manifest_path: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    expected = load_trust_material_manifest(manifest_path)
    actual = build_trust_material_manifest(paths, now=now)
    if expected != actual:
        raise TrustMaterialError("trust material artifacts do not exactly match the manifest")
    return actual
