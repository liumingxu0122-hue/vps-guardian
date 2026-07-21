from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from guardian.trust_material import (
    TRUST_MATERIAL_SCHEMA,
    TrustMaterialError,
    TrustMaterialPaths,
    build_trust_material_manifest,
    export_controller_public_key,
    verify_trust_material_manifest,
    write_trust_material_manifest,
)
from guardian.trust_material_cli import main as trust_material_main
from jsonschema import Draft202012Validator

NOW = datetime.now(UTC).replace(microsecond=0)


@dataclass(frozen=True)
class MaterialFixture:
    paths: TrustMaterialPaths
    agent_ca_key: Ed25519PrivateKey
    agent_ca: x509.Certificate
    gateway_ca_key: Ed25519PrivateKey
    gateway_ca: x509.Certificate


def _key_usage(*, ca: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=not ca,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=ca,
        crl_sign=ca,
        encipher_only=False,
        decipher_only=False,
    )


def _ca(common_name: str, key: Ed25519PrivateKey) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_key_usage(ca=True), critical=True)
        .add_extension(subject_key_identifier, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                subject_key_identifier
            ),
            critical=False,
        )
        .sign(key, algorithm=None)
    )


def _gateway_certificate(
    ca_key: Ed25519PrivateKey,
    ca_certificate: x509.Certificate,
    *,
    authority_key_identifier: x509.SubjectKeyIdentifier | None = None,
    not_before: datetime = NOW - timedelta(hours=1),
    not_after: datetime = NOW + timedelta(days=30),
) -> x509.Certificate:
    key = Ed25519PrivateKey.generate()
    issuer_ski = authority_key_identifier or ca_certificate.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value
    return (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent.example.test")])
        )
        .issuer_name(ca_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(ca=False), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("agent.example.test")]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski),
            critical=False,
        )
        .sign(ca_key, algorithm=None)
    )


def _crl(
    ca_key: Ed25519PrivateKey,
    ca_certificate: x509.Certificate,
    *,
    number: int | None,
    revoked_serials: tuple[int, ...] = (),
    signing_key: Ed25519PrivateKey | None = None,
    authority_key_identifier: x509.SubjectKeyIdentifier | None = None,
    last_update: datetime = NOW - timedelta(minutes=5),
    next_update: datetime = NOW + timedelta(days=7),
) -> x509.CertificateRevocationList:
    issuer_ski = authority_key_identifier or ca_certificate.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_certificate.subject)
        .last_update(last_update)
        .next_update(next_update)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski),
            critical=False,
        )
    )
    if number is not None:
        builder = builder.add_extension(x509.CRLNumber(number), critical=False)
    for serial in revoked_serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(NOW - timedelta(minutes=10))
            .build()
        )
    return builder.sign(signing_key or ca_key, algorithm=None)


def _write_certificate(path: Path, certificate: x509.Certificate) -> None:
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def _write_crl(path: Path, crl: x509.CertificateRevocationList) -> None:
    path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))


def _material(tmp_path: Path, *, crl_number: int = 12) -> MaterialFixture:
    agent_ca_key = Ed25519PrivateKey.generate()
    agent_ca = _ca("VPS Guardian Agent CA", agent_ca_key)
    gateway_ca_key = Ed25519PrivateKey.generate()
    gateway_ca = _ca("VPS Guardian Gateway CA", gateway_ca_key)
    gateway = _gateway_certificate(gateway_ca_key, gateway_ca)
    controller_key = Ed25519PrivateKey.generate()

    agent_ca_path = tmp_path / "agent-ca.crt"
    agent_crl_path = tmp_path / "agent-ca.crl"
    gateway_ca_path = tmp_path / "gateway-ca.crt"
    gateway_path = tmp_path / "gateway.crt"
    controller_key_path = tmp_path / "controller-ed25519.pem"
    controller_public_path = tmp_path / "controller-public-key"
    _write_certificate(agent_ca_path, agent_ca)
    _write_crl(
        agent_crl_path,
        _crl(agent_ca_key, agent_ca, number=crl_number, revoked_serials=(1001, 1002)),
    )
    _write_certificate(gateway_ca_path, gateway_ca)
    _write_certificate(gateway_path, gateway)
    controller_key_path.write_bytes(
        controller_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    export_controller_public_key(controller_key_path, controller_public_path)
    return MaterialFixture(
        paths=TrustMaterialPaths(
            agent_ca=agent_ca_path,
            agent_crl=agent_crl_path,
            controller_signing_key=controller_key_path,
            controller_public_key=controller_public_path,
            gateway_certificate=gateway_path,
            gateway_issuer_ca=gateway_ca_path,
        ),
        agent_ca_key=agent_ca_key,
        agent_ca=agent_ca,
        gateway_ca_key=gateway_ca_key,
        gateway_ca=gateway_ca,
    )


def test_v2_manifest_is_derived_from_exact_artifacts_without_bodies(tmp_path: Path) -> None:
    fixture = _material(tmp_path)
    manifest_path = tmp_path / "trust-material-v2.json"
    manifest = write_trust_material_manifest(
        fixture.paths,
        manifest_path,
        now=NOW,
    )

    assert manifest["schema"] == TRUST_MATERIAL_SCHEMA
    assert manifest["contains_private_material"] is False
    artifacts = manifest["artifacts"]
    assert artifacts["agent_ca"]["artifact_sha256"] == hashlib.sha256(
        fixture.paths.agent_ca.read_bytes()
    ).hexdigest()
    assert artifacts["agent_crl"]["crl_number"] == "12"
    assert artifacts["agent_crl"]["issuer"] == artifacts["agent_ca"]["subject"]
    assert (
        artifacts["agent_crl"]["authority_key_identifier"]
        == artifacts["agent_ca"]["subject_key_identifier"]
    )
    assert (
        artifacts["gateway_certificate"]["issuer"]
        == artifacts["gateway_issuer_ca"]["subject"]
    )
    assert (
        artifacts["gateway_certificate"]["authority_key_identifier"]
        == artifacts["gateway_issuer_ca"]["subject_key_identifier"]
    )
    assert artifacts["controller_public_key"]["raw_size"] == 32
    assert artifacts["controller_public_key"]["artifact_sha256"] == hashlib.sha256(
        fixture.paths.controller_public_key.read_bytes()
    ).hexdigest()

    serialized = manifest_path.read_text(encoding="utf-8")
    public_key_body = base64.b64encode(
        serialization.load_pem_private_key(
            fixture.paths.controller_signing_key.read_bytes(),
            password=None,
        )
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    assert "BEGIN CERTIFICATE" not in serialized
    assert "PRIVATE KEY" not in serialized
    assert public_key_body not in serialized
    assert verify_trust_material_manifest(fixture.paths, manifest_path, now=NOW) == manifest

    schema = json.loads(
        (Path(__file__).resolve().parents[1] / "docs/trust-material-v2.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(manifest)


def test_manifest_verification_detects_exact_artifact_digest_change(tmp_path: Path) -> None:
    fixture = _material(tmp_path)
    manifest_path = tmp_path / "trust-material-v2.json"
    write_trust_material_manifest(fixture.paths, manifest_path, now=NOW)

    original = fixture.paths.gateway_certificate.read_bytes()
    fixture.paths.gateway_certificate.write_bytes(original.replace(b"\n", b"\r\n"))
    with pytest.raises(TrustMaterialError, match="exactly match"):
        verify_trust_material_manifest(fixture.paths, manifest_path, now=NOW)


def test_controller_public_key_must_match_the_private_signing_key(tmp_path: Path) -> None:
    fixture = _material(tmp_path)
    other_private = Ed25519PrivateKey.generate()
    other_path = tmp_path / "other-controller.pem"
    other_public = tmp_path / "other-controller-public-key"
    other_path.write_bytes(
        other_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    export_controller_public_key(other_path, other_public)

    mismatched = replace(fixture.paths, controller_public_key=other_public)
    with pytest.raises(TrustMaterialError, match="does not match the Controller signing key"):
        build_trust_material_manifest(mismatched, now=NOW)


def test_gateway_and_crl_aki_and_signatures_are_verified(tmp_path: Path) -> None:
    fixture = _material(tmp_path)
    unrelated_key = Ed25519PrivateKey.generate()
    unrelated_ca = _ca("Unrelated CA", unrelated_key)
    unrelated_ski = unrelated_ca.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value

    wrong_gateway_path = tmp_path / "wrong-aki-gateway.crt"
    _write_certificate(
        wrong_gateway_path,
        _gateway_certificate(
            fixture.gateway_ca_key,
            fixture.gateway_ca,
            authority_key_identifier=unrelated_ski,
        ),
    )
    with pytest.raises(TrustMaterialError, match="authority key identifier"):
        build_trust_material_manifest(
            replace(fixture.paths, gateway_certificate=wrong_gateway_path),
            now=NOW,
        )

    invalid_crl_path = tmp_path / "invalid-signature.crl"
    _write_crl(
        invalid_crl_path,
        _crl(
            fixture.agent_ca_key,
            fixture.agent_ca,
            number=13,
            signing_key=unrelated_key,
        ),
    )
    with pytest.raises(TrustMaterialError, match="signature is not valid"):
        build_trust_material_manifest(
            replace(fixture.paths, agent_crl=invalid_crl_path),
            now=NOW,
        )


def test_crl_number_is_required_and_previous_real_crl_blocks_rollback(tmp_path: Path) -> None:
    fixture = _material(tmp_path)
    previous_path = tmp_path / "previous.crl"
    _write_crl(
        previous_path,
        _crl(
            fixture.agent_ca_key,
            fixture.agent_ca,
            number=20,
            revoked_serials=(1001, 1002),
            last_update=NOW - timedelta(minutes=20),
        ),
    )

    missing_number_path = tmp_path / "missing-number.crl"
    _write_crl(
        missing_number_path,
        _crl(fixture.agent_ca_key, fixture.agent_ca, number=None),
    )
    with pytest.raises(TrustMaterialError, match="has no CRL number"):
        build_trust_material_manifest(
            replace(fixture.paths, agent_crl=missing_number_path),
            now=NOW,
        )

    rollback_path = tmp_path / "rollback.crl"
    _write_crl(
        rollback_path,
        _crl(fixture.agent_ca_key, fixture.agent_ca, number=19, revoked_serials=(1001, 1002)),
    )
    with pytest.raises(TrustMaterialError, match="number rolls back"):
        build_trust_material_manifest(
            replace(fixture.paths, agent_crl=rollback_path),
            previous_crl=previous_path,
            now=NOW,
        )

    replay_path = tmp_path / "same-number-different-content.crl"
    _write_crl(
        replay_path,
        _crl(fixture.agent_ca_key, fixture.agent_ca, number=20, revoked_serials=(1001,)),
    )
    with pytest.raises(TrustMaterialError, match="without advancing"):
        build_trust_material_manifest(
            replace(fixture.paths, agent_crl=replay_path),
            previous_crl=previous_path,
            now=NOW,
        )

    omission_path = tmp_path / "omission.crl"
    _write_crl(
        omission_path,
        _crl(fixture.agent_ca_key, fixture.agent_ca, number=21, revoked_serials=(1001,)),
    )
    with pytest.raises(TrustMaterialError, match="omits a previously revoked"):
        build_trust_material_manifest(
            replace(fixture.paths, agent_crl=omission_path),
            previous_crl=previous_path,
            now=NOW,
        )

    advanced_path = tmp_path / "advanced.crl"
    _write_crl(
        advanced_path,
        _crl(
            fixture.agent_ca_key,
            fixture.agent_ca,
            number=21,
            revoked_serials=(1001, 1002, 1003),
        ),
    )
    advanced = build_trust_material_manifest(
        replace(fixture.paths, agent_crl=advanced_path),
        previous_crl=previous_path,
        now=NOW,
    )
    assert advanced["artifacts"]["agent_crl"]["crl_number"] == "21"
    assert advanced["artifacts"]["agent_crl"]["revoked_certificate_count"] == 3


def test_pki_generators_explicitly_emit_key_identifiers() -> None:
    root = Path(__file__).resolve().parents[1]
    agent_pki = (root / "scripts/pki-init.sh").read_text(encoding="utf-8")

    assert "crl_extensions = guardian_crl" in agent_pki
    assert "[ guardian_crl ]" in agent_pki
    assert "authorityKeyIdentifier = keyid:always" in agent_pki
    assert "-addext 'subjectKeyIdentifier=hash'" in agent_pki
    assert "-addext 'authorityKeyIdentifier=keyid:always,issuer'" in agent_pki
    assert "[ server_cert ]" in agent_pki
    assert "extendedKeyUsage = serverAuth" in agent_pki


def test_manifest_json_duplicate_keys_fail_closed(tmp_path: Path) -> None:
    fixture = _material(tmp_path)
    manifest_path = tmp_path / "duplicate.json"
    manifest_path.write_text(
        json.dumps({"schema": TRUST_MATERIAL_SCHEMA})[:-1]
        + f',"schema":"{TRUST_MATERIAL_SCHEMA}"}}',
        encoding="utf-8",
    )

    with pytest.raises(TrustMaterialError, match="duplicate JSON keys"):
        verify_trust_material_manifest(fixture.paths, manifest_path, now=NOW)

    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_text(
        '{ "schema": "vps-guardian-trust-material/v2" }\n',
        encoding="utf-8",
    )
    with pytest.raises(TrustMaterialError, match="not canonical JSON"):
        verify_trust_material_manifest(fixture.paths, noncanonical, now=NOW)


def _cli_material_arguments(paths: TrustMaterialPaths) -> list[str]:
    return [
        "--agent-ca",
        str(paths.agent_ca),
        "--agent-crl",
        str(paths.agent_crl),
        "--controller-signing-key",
        str(paths.controller_signing_key),
        "--controller-public-key",
        str(paths.controller_public_key),
        "--gateway-certificate",
        str(paths.gateway_certificate),
        "--gateway-issuer-ca",
        str(paths.gateway_issuer_ca),
    ]


def test_cli_exports_writes_verifies_replaces_and_reports_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = _material(tmp_path)
    exported = tmp_path / "exported-controller-public-key"
    assert (
        trust_material_main(
            [
                "export-controller-public-key",
                "--controller-signing-key",
                str(fixture.paths.controller_signing_key),
                "--controller-public-key",
                str(exported),
            ]
        )
        == 0
    )
    assert exported.read_bytes() == fixture.paths.controller_public_key.read_bytes()
    assert (
        trust_material_main(
            [
                "export-controller-public-key",
                "--controller-signing-key",
                str(fixture.paths.controller_signing_key),
                "--controller-public-key",
                str(exported),
            ]
        )
        == 1
    )
    assert "output already exists" in capsys.readouterr().err
    assert (
        trust_material_main(
            [
                "export-controller-public-key",
                "--controller-signing-key",
                str(fixture.paths.controller_signing_key),
                "--controller-public-key",
                str(exported),
                "--replace",
            ]
        )
        == 0
    )

    manifest_path = tmp_path / "cli-manifest.json"
    arguments = _cli_material_arguments(fixture.paths)
    assert trust_material_main(["write", *arguments, "--manifest", str(manifest_path)]) == 0
    assert trust_material_main(["verify", *arguments, "--manifest", str(manifest_path)]) == 0
    fixture.paths.controller_public_key.write_bytes(b"invalid\n")
    assert trust_material_main(["verify", *arguments, "--manifest", str(manifest_path)]) == 1
    assert "does not match the Controller signing key" in capsys.readouterr().err


def test_writers_refuse_to_replace_input_artifacts(tmp_path: Path) -> None:
    fixture = _material(tmp_path)
    with pytest.raises(TrustMaterialError, match="must not replace an input"):
        export_controller_public_key(
            fixture.paths.controller_signing_key,
            fixture.paths.controller_signing_key,
            replace=True,
        )
    with pytest.raises(TrustMaterialError, match="must not replace an input"):
        write_trust_material_manifest(
            fixture.paths,
            fixture.paths.agent_crl,
            replace=True,
            now=NOW,
        )


def test_rejects_non_ca_wrong_issuer_and_expired_gateway(tmp_path: Path) -> None:
    fixture = _material(tmp_path)
    with pytest.raises(TrustMaterialError, match="is not a CA certificate"):
        build_trust_material_manifest(
            replace(fixture.paths, agent_ca=fixture.paths.gateway_certificate),
            now=NOW,
        )

    unrelated_key = Ed25519PrivateKey.generate()
    unrelated_ca = _ca("Wrong Gateway CA", unrelated_key)
    wrong_issuer_path = tmp_path / "wrong-issuer.crt"
    _write_certificate(wrong_issuer_path, _gateway_certificate(unrelated_key, unrelated_ca))
    with pytest.raises(TrustMaterialError, match="issuer does not match"):
        build_trust_material_manifest(
            replace(fixture.paths, gateway_certificate=wrong_issuer_path),
            now=NOW,
        )

    expired_path = tmp_path / "expired-gateway.crt"
    _write_certificate(
        expired_path,
        _gateway_certificate(
            fixture.gateway_ca_key,
            fixture.gateway_ca,
            not_before=NOW - timedelta(days=10),
            not_after=NOW - timedelta(seconds=1),
        ),
    )
    with pytest.raises(TrustMaterialError, match="gateway certificate is expired"):
        build_trust_material_manifest(
            replace(fixture.paths, gateway_certificate=expired_path),
            now=NOW,
        )


def test_rejects_wrong_crl_aki_expiry_duplicate_serial_and_oversized_number(
    tmp_path: Path,
) -> None:
    fixture = _material(tmp_path)
    unrelated_ca = _ca("Wrong CRL CA", Ed25519PrivateKey.generate())
    unrelated_ski = unrelated_ca.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value

    wrong_aki_path = tmp_path / "wrong-aki.crl"
    _write_crl(
        wrong_aki_path,
        _crl(
            fixture.agent_ca_key,
            fixture.agent_ca,
            number=30,
            authority_key_identifier=unrelated_ski,
        ),
    )
    with pytest.raises(TrustMaterialError, match="authority key identifier"):
        build_trust_material_manifest(
            replace(fixture.paths, agent_crl=wrong_aki_path),
            now=NOW,
        )

    expired_path = tmp_path / "expired.crl"
    _write_crl(
        expired_path,
        _crl(
            fixture.agent_ca_key,
            fixture.agent_ca,
            number=30,
            last_update=NOW - timedelta(hours=12),
            next_update=NOW - timedelta(seconds=1),
        ),
    )
    with pytest.raises(TrustMaterialError, match="Agent CRL is expired"):
        build_trust_material_manifest(
            replace(fixture.paths, agent_crl=expired_path),
            now=NOW,
        )

    expiring_path = tmp_path / "expiring.crl"
    _write_crl(
        expiring_path,
        _crl(
            fixture.agent_ca_key,
            fixture.agent_ca,
            number=31,
            next_update=NOW + timedelta(minutes=4),
        ),
    )
    with pytest.raises(TrustMaterialError, match="five-minute safety margin"):
        build_trust_material_manifest(
            replace(fixture.paths, agent_crl=expiring_path),
            now=NOW,
        )

    duplicate_path = tmp_path / "duplicate.crl"
    _write_crl(
        duplicate_path,
        _crl(
            fixture.agent_ca_key,
            fixture.agent_ca,
            number=30,
            revoked_serials=(1001, 1001),
        ),
    )
    with pytest.raises(TrustMaterialError, match="duplicate revoked certificate serial"):
        build_trust_material_manifest(
            replace(fixture.paths, agent_crl=duplicate_path),
            now=NOW,
        )

    oversized_path = tmp_path / "oversized-number.crl"
    _write_crl(
        oversized_path,
        _crl(fixture.agent_ca_key, fixture.agent_ca, number=10**40),
    )
    with pytest.raises(TrustMaterialError, match="CRL number is too large"):
        build_trust_material_manifest(
            replace(fixture.paths, agent_crl=oversized_path),
            now=NOW,
        )


def test_rejects_non_ed25519_controller_key_relative_path_and_invalid_manifest(
    tmp_path: Path,
) -> None:
    fixture = _material(tmp_path)
    ec_key_path = tmp_path / "controller-ec.pem"
    ec_key_path.write_bytes(
        ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(TrustMaterialError, match="must be Ed25519"):
        build_trust_material_manifest(
            replace(fixture.paths, controller_signing_key=ec_key_path),
            now=NOW,
        )

    joined_key_path = tmp_path / "joined-controller.pem"
    joined_key_path.write_bytes(
        fixture.paths.controller_signing_key.read_bytes()
        + fixture.paths.controller_signing_key.read_bytes()
    )
    with pytest.raises(TrustMaterialError, match="exactly one PEM object"):
        build_trust_material_manifest(
            replace(fixture.paths, controller_signing_key=joined_key_path),
            now=NOW,
        )

    with pytest.raises(TrustMaterialError, match="path must be absolute"):
        build_trust_material_manifest(
            replace(fixture.paths, agent_ca=Path("relative-agent-ca.crt")),
            now=NOW,
        )

    invalid_manifest = tmp_path / "invalid-manifest.json"
    invalid_manifest.write_text(
        '{"schema":"vps-guardian-trust-material/v1"}\n',
        encoding="utf-8",
    )
    with pytest.raises(TrustMaterialError, match="schema is invalid"):
        verify_trust_material_manifest(fixture.paths, invalid_manifest, now=NOW)
