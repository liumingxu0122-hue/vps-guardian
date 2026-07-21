from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import guardian.backup_cli as backup_cli
import pytest
from fastapi.testclient import TestClient
from guardian.backup import (
    BackupCoordinator,
    BackupError,
    BackupResult,
    CommandResult,
    MySQLBackup,
    PostgreSQLBackup,
    RecoveryPlanner,
    RecoveryPointPromotionConflict,
    RecoveryVerificationAttestation,
    ResticAdapter,
    ResticConfig,
    RetentionPolicy,
    SQLiteBackup,
    SubprocessExecutor,
    _validate_controlled_secret_metadata,
    build_manifest,
    load_and_verify_manifest,
    load_restic_config,
    promote_recovery_point,
    read_controlled_secret_file,
    record_recovery_point,
    recovery_verification_attestation_digest,
    write_manifest,
)
from guardian.backup_cli import (
    _database_url_from_file,
    _mysql_backup,
    _postgres_backup,
    _source_commit,
)
from guardian.backup_cli import app as backup_app
from guardian.config import Settings
from guardian.database import SessionLocal
from guardian.models import AuditLog, Host, RecoveryPoint
from guardian.recovery_cli import app as recovery_app
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from typer.testing import CliRunner

ROOT = Path(__file__).parents[1]


class FakeExecutor:
    def __init__(self, responses: list[CommandResult] | None = None) -> None:
        self.responses = responses or []
        self.calls: list[dict[str, object]] = []

    def run(self, argv, *, env=None, cwd=None, timeout=900):  # type: ignore[no-untyped-def]
        self.calls.append(
            {"argv": tuple(argv), "env": dict(env or {}), "cwd": cwd, "timeout": timeout}
        )
        return self.responses.pop(0) if self.responses else CommandResult(0)


def test_subprocess_timeout_signals_the_entire_posix_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TimedOutProcess:
        pid = 4242
        returncode = -9
        communicate_calls = 0

        def communicate(self, timeout=None):  # type: ignore[no-untyped-def]
            self.communicate_calls += 1
            if self.communicate_calls == 1:
                raise subprocess.TimeoutExpired(["restic", "check"], timeout)
            return "", ""

        def terminate(self) -> None:
            raise AssertionError("POSIX timeout must not signal only the parent")

        def kill(self) -> None:
            raise AssertionError("POSIX timeout must not kill only the parent")

    process = TimedOutProcess()
    popen_options: dict[str, object] = {}

    def fake_popen(*_args, **kwargs):  # type: ignore[no-untyped-def]
        popen_options.update(kwargs)
        return process

    signals: list[tuple[int, int]] = []
    monkeypatch.setattr("guardian.backup.subprocess.Popen", fake_popen)
    monkeypatch.setattr(
        "guardian.backup.os.killpg",
        lambda pid, signal_number: signals.append((pid, signal_number)),
        raising=False,
    )

    with pytest.raises(BackupError, match="timed out after graceful termination"):
        SubprocessExecutor(platform_name="posix").run(["restic", "check"], timeout=1)

    assert popen_options["start_new_session"] is True
    assert signals == [(4242, 15), (4242, 9)]


def restic_config(tmp_path: Path) -> ResticConfig:
    password_file = tmp_path / "restic-password"
    password_file.write_text("repository-secret\n", encoding="utf-8")
    return ResticConfig(repository=str(tmp_path / "repository"), password_file=password_file)


def test_restic_uses_fixed_argv_and_does_not_expose_password(tmp_path: Path) -> None:
    source = tmp_path / "staging"
    source.mkdir()
    (source / "data.txt").write_text("content", encoding="utf-8")
    executor = FakeExecutor(
        [CommandResult(0, '{"message_type":"summary","snapshot_id":"abcdef123456"}\n')]
    )
    adapter = ResticAdapter(restic_config(tmp_path), executor)

    snapshot_id = adapter.backup(source, host="node-1", service="web", checksum="a" * 64)

    assert snapshot_id == "abcdef123456"
    argv = executor.calls[0]["argv"]
    assert isinstance(argv, tuple)
    assert argv[0] == "restic"
    assert "backup" in argv
    assert "repository-secret" not in " ".join(argv)
    assert executor.calls[0]["cwd"] == source


def test_repository_rejects_embedded_credentials(tmp_path: Path) -> None:
    with pytest.raises(BackupError, match="must not contain credentials"):
        ResticConfig(
            repository="s3:https://user:password@example.test/bucket",
            password_file=tmp_path / "password",
        )
    with pytest.raises(BackupError, match="must not contain credentials"):
        ResticConfig(
            repository="s3:user:password@objects.example.test/bucket",
            password_file=tmp_path / "password",
        )
    with pytest.raises(BackupError, match="must not contain credentials"):
        ResticConfig(
            repository="s3://user:password@objects.example.test/bucket",
            password_file=tmp_path / "password",
        )
    with pytest.raises(BackupError, match="must not contain credentials"):
        ResticConfig(
            repository="s3:https://objects.example.test/bucket?X-Amz-Signature=secret",
            password_file=tmp_path / "password",
        )


def test_repository_rejects_plaintext_s3_and_relative_local_paths(tmp_path: Path) -> None:
    with pytest.raises(BackupError, match="must use TLS"):
        ResticConfig(
            repository="s3:http://objects.example.test/staging",
            password_file=tmp_path / "restic-password",
        )


def test_controlled_local_repository_rejects_lexical_path_escape(tmp_path: Path) -> None:
    root = tmp_path / "backup-root"
    root.mkdir()
    with pytest.raises(BackupError, match="must be canonical"):
        ResticConfig(
            repository=str(root / ".." / "escaped"),
            password_file=tmp_path / "restic-password",
            controlled=True,
            local_repository_root=root,
        )
    with pytest.raises(BackupError, match="invalid Restic repository URL"):
        ResticConfig(
            repository="s3:https://[",
            password_file=tmp_path / "restic-password",
        )
    with pytest.raises(BackupError, match="absolute path"):
        ResticConfig(
            repository="relative-restic-repository",
            password_file=tmp_path / "restic-password",
        )


def test_local_password_file_decode_errors_are_sanitized(tmp_path: Path) -> None:
    password_file = tmp_path / "restic-password"
    password_file.write_bytes(b"\xff\xfe")
    config = ResticConfig(
        repository=str(tmp_path / "repository"),
        password_file=password_file,
    )

    with pytest.raises(BackupError, match="missing or unsafe"):
        config.validate_secret_file()


def test_database_url_file_is_used_for_the_backup_database_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url_file = tmp_path / "database-url"
    expected = "postgresql+psycopg://guardian:secret@database/guardian"
    monkeypatch.setenv("GUARDIAN_DATABASE_URL_FILE", str(database_url_file))
    monkeypatch.delenv("GUARDIAN_DATABASE_URL", raising=False)
    monkeypatch.setattr(
        "guardian.backup.read_controlled_secret_file",
        lambda path, **_: expected if path == database_url_file else "",
    )

    settings = Settings(database_url_file=database_url_file)

    assert settings.database_url == expected


def test_local_restic_ignores_ambient_aws_credentials_and_missing_secret_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password_file = tmp_path / "restic-password"
    password_file.write_text("local-password\n", encoding="utf-8")
    config = load_restic_config(
        environment={
            "RESTIC_REPOSITORY": str(tmp_path / "repository"),
            "RESTIC_PASSWORD_FILE": str(password_file),
            "AWS_ACCESS_KEY_ID": "must-not-be-inherited",
            "AWS_SECRET_ACCESS_KEY": "must-not-be-inherited",
            "AWS_ACCESS_KEY_ID_FILE": str(tmp_path / "missing-access-key"),
            "AWS_SECRET_ACCESS_KEY_FILE": str(tmp_path / "missing-secret-key"),
            "AWS_DEFAULT_REGION_FILE": str(tmp_path / "missing-region"),
        }
    )
    monkeypatch.setenv("TMPDIR", str(tmp_path / "controlled-tmp"))

    assert config.repository == str(tmp_path / "repository")
    assert not ({"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} & config.environment().keys())
    assert config.environment()["TMPDIR"] == str(tmp_path / "controlled-tmp")


def test_restic_rejects_ambiguous_repository_sources(tmp_path: Path) -> None:
    with pytest.raises(BackupError, match="only one Restic repository source"):
        load_restic_config(
            environment={
                "RESTIC_REPOSITORY": str(tmp_path / "repository"),
                "RESTIC_REPOSITORY_FILE": str(tmp_path / "repository-file"),
                "RESTIC_PASSWORD_FILE": str(tmp_path / "restic-password"),
            }
        )


def test_s3_restic_requires_all_credential_file_paths(tmp_path: Path) -> None:
    with pytest.raises(BackupError, match="access-key, secret-key, and region files"):
        ResticConfig(
            repository="s3:https://objects.example.test/staging",
            password_file=tmp_path / "restic-password",
            credential_files={"AWS_ACCESS_KEY_ID": tmp_path / "access-key"},
        )


def test_s3_credentials_only_enter_the_restic_child_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password_file = tmp_path / "restic-password"
    access_file = tmp_path / "access-key"
    secret_file = tmp_path / "secret-key"
    region_file = tmp_path / "region"
    values = {
        password_file: "restic-password-value",
        access_file: "file-access-key",
        secret_file: "file-secret-key",
        region_file: "test-region-1",
    }
    monkeypatch.setattr(
        "guardian.backup.read_controlled_secret_file",
        lambda path, **_: values[path],
    )
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "ambient-access-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret-key")
    executor = FakeExecutor([CommandResult(0, "[]")])
    adapter = ResticAdapter(
        ResticConfig(
            repository="s3:https://objects.example.test/staging",
            password_file=password_file,
            credential_files={
                "AWS_ACCESS_KEY_ID": access_file,
                "AWS_SECRET_ACCESS_KEY": secret_file,
                "AWS_DEFAULT_REGION": region_file,
            },
        ),
        executor,
    )

    assert adapter.snapshots() == []
    child_environment = executor.calls[0]["env"]
    assert child_environment["AWS_ACCESS_KEY_ID"] == "file-access-key"  # type: ignore[index]
    assert child_environment["AWS_SECRET_ACCESS_KEY"] == "file-secret-key"  # type: ignore[index]
    assert child_environment["AWS_DEFAULT_REGION"] == "test-region-1"  # type: ignore[index]
    command = " ".join(executor.calls[0]["argv"])  # type: ignore[arg-type]
    assert "file-access-key" not in command
    assert "file-secret-key" not in command
    assert "ambient-access-key" not in child_environment.values()  # type: ignore[union-attr]


def test_controlled_secret_metadata_requires_root_and_approved_mode() -> None:
    path = Path("/etc/vps-guardian-backup-secrets/aws-secret-access-key")
    _validate_controlled_secret_metadata(
        path=path,
        mode=0o640,
        owner_uid=0,
        platform_name="posix",
    )
    _validate_controlled_secret_metadata(
        path=Path("/run/secrets/aws_secret_access_key"),
        mode=0o444,
        owner_uid=0,
        platform_name="posix",
    )
    with pytest.raises(BackupError, match="root-owned"):
        _validate_controlled_secret_metadata(
            path=path,
            mode=0o640,
            owner_uid=1000,
            platform_name="posix",
        )
    with pytest.raises(BackupError, match="mode must be one of"):
        _validate_controlled_secret_metadata(
            path=path,
            mode=0o644,
            owner_uid=0,
            platform_name="posix",
        )


def test_controlled_secret_file_rejects_non_printing_control_characters(
    tmp_path: Path,
) -> None:
    secret_file = tmp_path / "aws-access-key-id"
    secret_file.write_bytes(b"access-key\x7fvalue\n")
    secret_file.chmod(0o600)

    with pytest.raises(BackupError, match="invalid value"):
        read_controlled_secret_file(secret_file, label="AWS_ACCESS_KEY_ID")


def test_repository_maintenance_commands_use_the_bounded_restic_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operations: list[object] = []

    class FakeAdapter:
        def initialize(self) -> None:
            operations.append("initialize")

        def check(self, *, read_data_subset: str) -> None:
            operations.append(("check", read_data_subset))

    monkeypatch.setattr("guardian.backup_cli._restic", FakeAdapter)
    runner = CliRunner()

    refused = runner.invoke(backup_app, ["repository-init"])
    initialized = runner.invoke(
        backup_app,
        [
            "repository-init",
            "--execute",
            "--confirm",
            "INITIALIZE RESTIC REPOSITORY",
        ],
    )
    checked = runner.invoke(
        backup_app,
        ["repository-check", "--read-data-subset", "25%"],
    )

    assert refused.exit_code == 2
    assert initialized.exit_code == 0
    assert checked.exit_code == 0
    assert operations == ["initialize", ("check", "25%")]


def test_repository_check_rejects_a_zero_data_subset(tmp_path: Path) -> None:
    adapter = ResticAdapter(restic_config(tmp_path), FakeExecutor())

    with pytest.raises(BackupError, match="invalid Restic check subset"):
        adapter.check(read_data_subset="0%")


def test_recovery_cli_sanitizes_expected_filesystem_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_planner(*_: object) -> None:
        raise OSError("cannot read /sensitive/repository/path")

    monkeypatch.setattr("guardian.recovery_cli._planner", fail_planner)
    result = CliRunner().invoke(recovery_app, ["points"])

    assert result.exit_code == 2
    assert "recovery error: recovery operation failed" in result.output
    assert "/sensitive/repository/path" not in result.output
    assert "Traceback" not in result.output


def test_manifest_detects_tampering_and_path_traversal(tmp_path: Path) -> None:
    (tmp_path / "service.conf").write_text("healthy=true\n", encoding="utf-8")
    manifest = build_manifest(tmp_path, host="node-1", service="api")
    checksum = write_manifest(tmp_path, manifest)
    assert load_and_verify_manifest(tmp_path, expected_checksum=checksum)["service"] == "api"

    (tmp_path / "service.conf").write_text("tampered=true\n", encoding="utf-8")
    with pytest.raises(BackupError, match="artifact verification failed"):
        load_and_verify_manifest(tmp_path)


def test_manifest_rejects_extra_files_wrong_sizes_and_symlinks(tmp_path: Path) -> None:
    data = tmp_path / "service.conf"
    data.write_text("healthy=true\n", encoding="utf-8")
    manifest = build_manifest(tmp_path, host="node-1", service="api")
    write_manifest(tmp_path, manifest)

    (tmp_path / "unexpected.txt").write_text("not listed", encoding="utf-8")
    with pytest.raises(BackupError, match="file set"):
        load_and_verify_manifest(tmp_path)
    (tmp_path / "unexpected.txt").unlink()

    manifest["artifacts"][0]["size"] = data.stat().st_size + 1
    write_manifest(tmp_path, manifest)
    with pytest.raises(BackupError, match="artifact verification failed"):
        load_and_verify_manifest(tmp_path)

    manifest["artifacts"][0]["path"] = "../outside"
    write_manifest(tmp_path, manifest)
    with pytest.raises(BackupError, match="path traversal"):
        load_and_verify_manifest(tmp_path)

    data.unlink()
    try:
        data.symlink_to(tmp_path / "manifest.json")
    except OSError:
        return
    with pytest.raises(BackupError, match="unsafe file type"):
        load_and_verify_manifest(tmp_path)


def test_recovery_metadata_is_nonsecret_and_bound_to_the_manifest(tmp_path: Path) -> None:
    (tmp_path / "service.conf").write_text("healthy=true\n", encoding="utf-8")
    metadata = {
        "source_commit": "1" * 40,
        "alembic_revisions": ["0004_agent_dual_identity"],
        "configuration_references": ["controller environment"],
        "public_certificate_references": ["agent CA certificate"],
        "external_secret_references": ["agent CA private key", "Restic password"],
    }
    manifest = build_manifest(
        tmp_path,
        host="node-1",
        service="controller",
        recovery_metadata=metadata,
    )
    checksum = write_manifest(tmp_path, manifest)

    restored = load_and_verify_manifest(tmp_path, expected_checksum=checksum)
    assert restored["recovery_metadata"]["source_commit"] == "1" * 40
    assert restored["recovery_metadata"]["contains_secret_values"] is False
    with pytest.raises(BackupError, match="invalid recovery metadata"):
        build_manifest(
            tmp_path,
            host="node-1",
            service="controller",
            recovery_metadata={**metadata, "source_commit": "0" * 40},
        )


def test_sqlite_online_backup_passes_integrity_check(tmp_path: Path) -> None:
    source = tmp_path / "live.db"
    with closing(sqlite3.connect(source)) as database:
        database.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        database.execute("INSERT INTO events(value) VALUES ('preserved')")
        database.commit()
    destination = tmp_path / "backup"
    destination.mkdir()

    backup = SQLiteBackup(source).create(destination)

    with closing(sqlite3.connect(backup)) as database:
        assert database.execute("SELECT value FROM events").fetchone() == ("preserved",)
        assert database.execute("PRAGMA integrity_check").fetchone() == ("ok",)


class DumpExecutor(FakeExecutor):
    def run(self, argv, *, env=None, cwd=None, timeout=900):  # type: ignore[no-untyped-def]
        result = super().run(argv, env=env, cwd=cwd, timeout=timeout)
        arguments = list(argv)
        if "--file" in arguments:
            Path(arguments[arguments.index("--file") + 1]).write_bytes(b"PGDUMP")
        for argument in arguments:
            if argument.startswith("--result-file="):
                Path(argument.split("=", 1)[1]).write_text("MYSQLDUMP", encoding="utf-8")
        return result


def test_database_dump_credentials_stay_out_of_command_arguments(tmp_path: Path) -> None:
    passfile = tmp_path / "pgpass"
    passfile.write_text("*:5432:*:*:top-secret-password\n", encoding="utf-8")
    defaults_file = tmp_path / "mysql.cnf"
    defaults_file.write_text("[client]\npassword=another-secret\n", encoding="utf-8")
    destination = tmp_path / "dumps"
    destination.mkdir()
    executor = DumpExecutor()

    PostgreSQLBackup(
        host="db.internal",
        port=5432,
        user="guardian",
        database="appdb",
        passfile=passfile,
        executor=executor,
    ).create(destination)
    MySQLBackup(database="appdb", defaults_file=defaults_file, executor=executor).create(
        destination
    )

    all_arguments = " ".join(
        argument
        for call in executor.calls
        for argument in call["argv"]  # type: ignore[union-attr]
    )
    assert "top-secret-password" not in all_arguments
    assert "another-secret" not in all_arguments
    assert executor.calls[0]["env"]["PGPASSFILE"] == str(passfile)  # type: ignore[index]
    assert any(
        str(argument).startswith("--defaults-file=")
        for argument in executor.calls[1]["argv"]  # type: ignore[union-attr]
    )
    assert not any(
        str(argument).startswith("--defaults-extra-file=")
        for argument in executor.calls[1]["argv"]  # type: ignore[union-attr]
    )


def test_database_dump_preserves_tls_parameters_and_rejects_option_injection(
    tmp_path: Path,
) -> None:
    postgres = _postgres_backup(
        make_url(
            "postgresql+psycopg://guardian:secret@db.example/guardian"
            "?sslmode=verify-full&sslrootcert=/etc/ssl/guardian-ca.pem"
        ),
        tmp_path,
    )
    assert postgres.connection_environment == {
        "PGSSLMODE": "verify-full",
        "PGSSLROOTCERT": "/etc/ssl/guardian-ca.pem",
    }

    mysql = _mysql_backup(
        make_url(
            "mysql+pymysql://guardian:secret@db.example/guardian"
            "?ssl_mode=VERIFY_IDENTITY&ssl_ca=/etc/ssl/guardian-ca.pem"
        ),
        tmp_path,
    )
    options = mysql.defaults_file.read_text(encoding="utf-8")
    assert 'ssl-mode="VERIFY_IDENTITY"' in options
    assert 'ssl-ca="/etc/ssl/guardian-ca.pem"' in options

    for database_url in (
        "postgresql+psycopg://guardian:secret@db.example/guardian",
        "postgresql+psycopg://guardian:secret@db.example/guardian?sslmode=require",
        "postgresql+psycopg://guardian:secret@db.example/guardian?sslmode=verify-ca",
        "postgresql+psycopg://guardian:secret@db/guardian",
    ):
        with pytest.raises(BackupError, match="require sslmode=verify-full"):
            _postgres_backup(make_url(database_url), tmp_path)
    for database_url in (
        "mysql+pymysql://guardian:secret@db.example/guardian",
        "mysql+pymysql://guardian:secret@db.example/guardian?ssl_mode=REQUIRED",
        "mysql+pymysql://guardian:secret@db.example/guardian?ssl_mode=VERIFY_CA",
    ):
        with pytest.raises(BackupError, match="require ssl_mode=VERIFY_IDENTITY"):
            _mysql_backup(make_url(database_url), tmp_path)

    assert (
        _postgres_backup(
            make_url("postgresql+psycopg://guardian:secret@database/guardian"), tmp_path
        ).host
        == "database"
    )
    local_mysql = _mysql_backup(
        make_url("mysql+pymysql://guardian:secret@restore-mysql/guardian"), tmp_path
    )
    assert 'host="restore-mysql"' in local_mysql.defaults_file.read_text(encoding="utf-8")

    with pytest.raises(BackupError, match="invalid MySQL password"):
        _mysql_backup(
            make_url("mysql+pymysql://guardian:secret%0Assl-mode=DISABLED@db.example/guardian"),
            tmp_path,
        )
    with pytest.raises(BackupError, match="unsupported connection parameters"):
        _postgres_backup(
            make_url("postgresql+psycopg://guardian:secret@db.example/guardian?options=-cfoo"),
            tmp_path,
        )


def test_source_commit_accepts_a_logical_parent_symlink_but_not_a_file_symlink(
    tmp_path: Path,
) -> None:
    release = tmp_path / "releases" / "release-1"
    release.mkdir(parents=True)
    source_commit = release / "SOURCE_COMMIT"
    source_commit.write_text("a" * 40 + "\n", encoding="ascii")
    current = tmp_path / "current"
    direct_link = tmp_path / "SOURCE_COMMIT.link"
    try:
        current.symlink_to(release, target_is_directory=True)
        direct_link.symlink_to(source_commit)
    except OSError:
        pytest.skip("symbolic links are unavailable")

    assert _source_commit(current / "SOURCE_COMMIT", platform_name="test") == "a" * 40
    with pytest.raises(BackupError, match="missing or unsafe"):
        _source_commit(direct_link, platform_name="test")


def test_controller_cli_reports_uploaded_snapshot_pending_database_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_commit = tmp_path / "SOURCE_COMMIT"
    source_commit.write_text("a" * 40 + "\n", encoding="ascii")

    class UnverifiedCoordinator:
        def __init__(self, _restic) -> None:  # type: ignore[no-untyped-def]
            pass

        def create_backup(self, **_kwargs) -> BackupResult:  # type: ignore[no-untyped-def]
            return BackupResult(
                snapshot_id="a" * 64,
                checksum="b" * 64,
                manifest={"schema_version": 1},
                verified=False,
            )

    monkeypatch.setattr(backup_cli, "BackupCoordinator", UnverifiedCoordinator)
    monkeypatch.setattr(backup_cli, "_restic", lambda: object())
    monkeypatch.setattr(
        backup_cli,
        "get_settings",
        lambda: SimpleNamespace(database_url="postgresql+psycopg://guardian:secret@database/db"),
    )
    monkeypatch.setattr(backup_cli, "_database_backup_from_url", lambda *_args: object())
    monkeypatch.setattr(
        backup_cli,
        "_controller_recovery_metadata",
        lambda **_kwargs: {"source_commit": "a" * 40},
    )
    result = CliRunner().invoke(
        backup_app,
        ["controller", "--source-commit-file", str(source_commit)],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output == {
        "snapshot_id": "a" * 64,
        "checksum": "b" * 64,
        "source_commit": "a" * 40,
        "uploaded": True,
        "repository_checked": True,
        "manifest_restored": True,
        "database_restore_verified": False,
        "verified": False,
        "verification_state": "pending",
        "recorded": False,
        "recording_error": "inventory_host_not_found",
    }


def test_controller_cli_preserves_upload_result_when_recovery_point_recording_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_commit = tmp_path / "SOURCE_COMMIT"
    source_commit.write_text("a" * 40 + "\n", encoding="ascii")

    class UploadedCoordinator:
        def __init__(self, _restic) -> None:  # type: ignore[no-untyped-def]
            pass

        def create_backup(self, **_kwargs) -> BackupResult:  # type: ignore[no-untyped-def]
            return BackupResult("a" * 64, "b" * 64, {"schema_version": 1}, False)

    monkeypatch.setattr(backup_cli, "BackupCoordinator", UploadedCoordinator)
    monkeypatch.setattr(backup_cli, "_restic", lambda: object())
    monkeypatch.setattr(
        backup_cli,
        "get_settings",
        lambda: SimpleNamespace(database_url="postgresql+psycopg://guardian:secret@database/db"),
    )
    monkeypatch.setattr(backup_cli, "_database_backup_from_url", lambda *_args: object())
    monkeypatch.setattr(
        backup_cli,
        "_controller_recovery_metadata",
        lambda **_kwargs: {"source_commit": "a" * 40},
    )
    monkeypatch.setattr(
        "guardian.database.SessionLocal",
        lambda: (_ for _ in ()).throw(SQLAlchemyError("synthetic persistence failure")),
    )

    result = CliRunner().invoke(
        backup_app,
        ["controller", "--source-commit-file", str(source_commit)],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output["uploaded"] is True
    assert output["recorded"] is False
    assert output["recording_error"] == "recovery_point_persistence_failed"
    assert "synthetic persistence failure" not in result.output


def test_service_database_url_is_loaded_only_from_regular_protected_file(
    tmp_path: Path,
) -> None:
    url_file = tmp_path / "database-url"
    url_file.write_text(
        "postgresql+psycopg://guardian:staging-secret@database/guardian\n",
        encoding="utf-8",
    )
    parsed = _database_url_from_file(url_file)
    assert parsed.drivername == "postgresql+psycopg"
    assert parsed.password == "staging-secret"

    relative = Path("database-url")
    with pytest.raises(BackupError, match="absolute regular file"):
        _database_url_from_file(relative)
    symlink = tmp_path / "database-url-link"
    try:
        symlink.symlink_to(url_file)
    except OSError:
        return
    with pytest.raises(BackupError, match="absolute regular file"):
        _database_url_from_file(symlink)


class SimulatedRestic(FakeExecutor):
    def __init__(self, snapshot_root: Path) -> None:
        super().__init__()
        self.snapshot_root = snapshot_root

    def run(self, argv, *, env=None, cwd=None, timeout=900):  # type: ignore[no-untyped-def]
        super().run(argv, env=env, cwd=cwd, timeout=timeout)
        arguments = list(argv)
        if "backup" in arguments:
            assert cwd is not None
            shutil.copytree(cwd, self.snapshot_root)
            return CommandResult(0, '{"message_type":"summary","snapshot_id":"abcdef123456"}\n')
        if "restore" in arguments and "--dry-run" not in arguments:
            target = Path(arguments[arguments.index("--target") + 1])
            shutil.copytree(self.snapshot_root, target)
        return CommandResult(0)


def test_backup_is_verified_only_after_isolated_restore(tmp_path: Path) -> None:
    source = tmp_path / "app.conf"
    source.write_text("version=1\n", encoding="utf-8")
    executor = SimulatedRestic(tmp_path / "snapshot")
    coordinator = BackupCoordinator(ResticAdapter(restic_config(tmp_path), executor))

    result = coordinator.create_backup(
        host="node-1",
        service="api",
        sources=[source],
        validator=lambda _root, _manifest: True,
    )

    assert result.snapshot_id == "abcdef123456"
    assert result.verified is True
    commands = [call["argv"] for call in executor.calls]
    assert any("check" in command for command in commands)  # type: ignore[operator]
    assert any("restore" in command for command in commands)  # type: ignore[operator]


def test_backup_without_service_validator_is_not_marked_verified(tmp_path: Path) -> None:
    source = tmp_path / "app.conf"
    source.write_text("version=1\n", encoding="utf-8")
    executor = SimulatedRestic(tmp_path / "snapshot")
    coordinator = BackupCoordinator(ResticAdapter(restic_config(tmp_path), executor))

    result = coordinator.create_backup(host="node-1", service="api", sources=[source])

    assert result.verified is False


def test_backup_refuses_an_undersized_staging_filesystem(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "app.conf"
    source.write_text("version=1\n", encoding="utf-8")
    coordinator = BackupCoordinator(ResticAdapter(restic_config(tmp_path), FakeExecutor()))

    class Usage:
        free = 1024

    monkeypatch.setattr("guardian.backup.shutil.disk_usage", lambda _: Usage())
    with pytest.raises(BackupError, match="insufficient free space"):
        coordinator.create_backup(
            host="node-1",
            service="api",
            sources=[source],
            minimum_free_bytes=64 * 1024**2,
        )


def test_retention_deletion_requires_approval_and_exact_confirmation(tmp_path: Path) -> None:
    snapshot_id = "b" * 64
    retention_output = json.dumps(
        [
            {
                "host": "node-1",
                "keep": [],
                "remove": [
                    {
                        "id": snapshot_id,
                        "hostname": "node-1",
                        "tags": [
                            "guardian",
                            "guardian-host:node-1",
                            "guardian-service:api",
                            f"guardian-manifest:{'a' * 64}",
                        ],
                    }
                ],
            }
        ]
    )
    executor = FakeExecutor(
        [
            CommandResult(0, retention_output),
            CommandResult(0, retention_output),
            CommandResult(0, retention_output),
            CommandResult(0),
        ]
    )
    adapter = ResticAdapter(restic_config(tmp_path), executor)
    policy = RetentionPolicy()

    plan = adapter.retention_plan(policy, host="node-1", service="api")
    with pytest.raises(BackupError, match="current dry-run plan"):
        adapter.apply_retention(
            policy,
            host="node-1",
            service="api",
            plan_digest=plan.digest,
            approval_id="approval-1",
            confirmation="yes",
        )
    applied = adapter.apply_retention(
        policy,
        host="node-1",
        service="api",
        plan_digest=plan.digest,
        approval_id="approval-1",
        confirmation=f"APPLY RETENTION {plan.digest}",
    )

    assert "--dry-run" in executor.calls[0]["argv"]  # type: ignore[operator]
    assert "guardian,guardian-host:node-1,guardian-service:api" in executor.calls[0]["argv"]  # type: ignore[operator]
    assert executor.calls[-1]["argv"][-1] == snapshot_id  # type: ignore[index]
    assert "--prune" not in executor.calls[-1]["argv"]  # type: ignore[operator]
    assert applied.remove_snapshot_ids == (snapshot_id,)


class SimulatedRecovery(FakeExecutor):
    def __init__(self, snapshot_root: Path, snapshot_id: str, manifest_checksum: str) -> None:
        super().__init__()
        self.snapshot_root = snapshot_root
        self.snapshot_id = snapshot_id
        self.manifest_checksum = manifest_checksum

    def run(self, argv, *, env=None, cwd=None, timeout=900):  # type: ignore[no-untyped-def]
        self.calls.append(
            {"argv": tuple(argv), "env": dict(env or {}), "cwd": cwd, "timeout": timeout}
        )
        arguments = list(argv)
        if "snapshots" in arguments:
            return CommandResult(
                0,
                json.dumps(
                    [
                        {
                            "id": self.snapshot_id,
                            "short_id": self.snapshot_id[:8],
                            "hostname": "node-1",
                            "tags": [
                                "guardian",
                                "guardian-host:node-1",
                                "guardian-service:api",
                                f"guardian-manifest:{self.manifest_checksum}",
                            ],
                        }
                    ]
                ),
            )
        if "dump" in arguments:
            return CommandResult(
                0, (self.snapshot_root / "manifest.json").read_text(encoding="utf-8")
            )
        if "restore" in arguments and "--dry-run" not in arguments:
            target = Path(arguments[arguments.index("--target") + 1])
            shutil.copytree(self.snapshot_root, target)
        return CommandResult(0)


def test_recovery_defaults_to_dry_run_and_execution_needs_confirmation(tmp_path: Path) -> None:
    snapshot_root = tmp_path / "snapshot"
    (snapshot_root / "files").mkdir(parents=True)
    (snapshot_root / "files/api.conf").write_text("healthy=true", encoding="utf-8")
    manifest = build_manifest(snapshot_root, host="node-1", service="api")
    manifest_checksum = write_manifest(snapshot_root, manifest)
    snapshot_id = "a" * 64
    executor = SimulatedRecovery(snapshot_root, snapshot_id, manifest_checksum)
    planner = RecoveryPlanner(ResticAdapter(restic_config(tmp_path), executor))
    target = tmp_path / "isolated-restore"

    planner.restore(snapshot_id[:12], target)
    assert "ls" in executor.calls[-1]["argv"]  # type: ignore[operator]
    assert "restore" not in executor.calls[-1]["argv"]  # type: ignore[operator]
    plan = planner.plan(snapshot_id, target)
    with pytest.raises(BackupError, match="current snapshot"):
        planner.restore(snapshot_id, target, execute=True, approval_id="approval-1")
    planner.restore(
        snapshot_id,
        target,
        execute=True,
        approval_id="approval-1",
        plan_digest=plan.digest,
        confirmation=plan.confirmation,
    )
    assert "--dry-run" not in executor.calls[-1]["argv"]  # type: ignore[operator]
    assert (
        load_and_verify_manifest(
            target,
            expected_checksum=manifest_checksum,
            expected_host="node-1",
            expected_service="api",
        )["service"]
        == "api"
    )


def test_recovery_points_api_requires_operator_access(client: TestClient, owner_token: str) -> None:
    with SessionLocal() as database:
        host = Host(name="backup-node", address="192.0.2.50")
        database.add(host)
        database.flush()
        database.add(
            RecoveryPoint(
                host_id=host.id,
                service_name="controller",
                snapshot_id="abcdef123456",
                manifest={"schema_version": 1},
                checksum="a" * 64,
                verified=True,
                verified_at=datetime.now(UTC),
                verification_version=1,
                attestation_digest="b" * 64,
            )
        )
        database.commit()

    client.cookies.clear()
    unauthorized = client.get("/api/v1/recovery-points")
    authorized = client.get(
        "/api/v1/recovery-points", headers={"Authorization": f"Bearer {owner_token}"}
    )

    assert unauthorized.status_code == 401
    assert authorized.status_code == 200
    assert authorized.json()[0]["service_name"] == "controller"
    assert authorized.json()[0]["verified"] is True


def test_recovery_point_verification_status_is_persisted_once() -> None:
    result = BackupResult(
        snapshot_id="abcdef123456",
        checksum="a" * 64,
        manifest={"schema_version": 1},
        verified=True,
    )
    with SessionLocal() as database:
        host = Host(name="verified-node", address="192.0.2.60")
        database.add(host)
        database.flush()
        first = record_recovery_point(database, host_id=host.id, service="api", result=result)
        second = record_recovery_point(database, host_id=host.id, service="api", result=result)
        database.commit()

        assert first.id == second.id
        assert first.verified is True
        assert first.verified_at is not None
        assert first.verification_version == 1
        assert first.attestation_digest is not None
        assert len(first.attestation_digest) == 64
        assert database.query(RecoveryPoint).count() == 1


def test_record_recovery_point_promotes_pending_and_rejects_checksum_reuse() -> None:
    snapshot_id = "1" * 64
    checksum = "2" * 64
    manifest = {"schema_version": 1, "service": "controller"}
    pending_result = BackupResult(snapshot_id, checksum, manifest, False)
    verified_result = BackupResult(snapshot_id, checksum, manifest, True)
    with SessionLocal() as database:
        host = Host(name="pending-promotion-node", address="192.0.2.63")
        database.add(host)
        database.flush()
        pending = record_recovery_point(
            database,
            host_id=host.id,
            service="controller",
            result=pending_result,
        )
        database.commit()
        point_id = pending.id

        promoted = record_recovery_point(
            database,
            host_id=host.id,
            service="controller",
            result=verified_result,
        )
        database.commit()
        assert promoted.id == point_id
        assert promoted.verified is True
        assert promoted.verification_version == 1
        assert promoted.attestation_digest is not None
        digest = promoted.attestation_digest

        replay = record_recovery_point(
            database,
            host_id=host.id,
            service="controller",
            result=verified_result,
        )
        assert replay.id == point_id
        assert replay.attestation_digest == digest

        with pytest.raises(RecoveryPointPromotionConflict):
            record_recovery_point(
                database,
                host_id=host.id,
                service="controller",
                result=BackupResult(snapshot_id, "3" * 64, manifest, True),
            )
        current = database.get(RecoveryPoint, point_id)
        assert current and current.checksum == checksum
        assert current.attestation_digest == digest


def recovery_attestation(*, evidence_digest: str = "c" * 64) -> RecoveryVerificationAttestation:
    return RecoveryVerificationAttestation(
        verifier="staging-recovery-drill",
        verification_method="isolated_restore",
        target_environment="staging-isolated",
        completed_at=datetime.fromisoformat("2026-07-18T12:00:00+00:00"),
        evidence_digest=evidence_digest,
    )


def test_recovery_verification_attestation_digest_is_canonical_and_content_bound() -> None:
    point_id = "11111111-2222-3333-4444-555555555555"
    utc_attestation = recovery_attestation()
    offset_attestation = RecoveryVerificationAttestation(
        verifier=utc_attestation.verifier,
        verification_method=utc_attestation.verification_method,
        target_environment=utc_attestation.target_environment,
        completed_at=datetime.fromisoformat("2026-07-18T20:00:00+08:00"),
        evidence_digest=utc_attestation.evidence_digest.upper(),
    )
    expected = recovery_verification_attestation_digest(
        recovery_point_id=point_id,
        snapshot_id="A" * 64,
        checksum="B" * 64,
        attestation=utc_attestation,
    )
    normalized = recovery_verification_attestation_digest(
        recovery_point_id=point_id,
        snapshot_id="a" * 64,
        checksum="b" * 64,
        attestation=offset_attestation,
    )
    changed = recovery_verification_attestation_digest(
        recovery_point_id=point_id,
        snapshot_id="a" * 64,
        checksum="b" * 64,
        attestation=recovery_attestation(evidence_digest="d" * 64),
    )

    assert normalized == expected
    assert changed != expected


def test_pending_recovery_point_promotion_is_cas_and_idempotent() -> None:
    snapshot_id = "a" * 64
    checksum = "b" * 64
    attestation = recovery_attestation()
    with SessionLocal() as database:
        host = Host(name="promotion-node", address="192.0.2.61")
        database.add(host)
        database.flush()
        point = RecoveryPoint(
            host_id=host.id,
            service_name="controller",
            snapshot_id=snapshot_id,
            manifest={"schema_version": 1},
            checksum=checksum,
            verified=False,
        )
        database.add(point)
        database.commit()
        point_id = point.id

    with SessionLocal() as database:
        for version, candidate_snapshot, candidate_checksum in (
            (1, snapshot_id, checksum),
            (0, "f" * 64, checksum),
            (0, snapshot_id, "f" * 64),
        ):
            with pytest.raises(RecoveryPointPromotionConflict):
                promote_recovery_point(
                    database,
                    recovery_point_id=point_id,
                    expected_version=version,
                    expected_snapshot_id=candidate_snapshot,
                    expected_checksum=candidate_checksum,
                    attestation=attestation,
                )
        pending = database.get(RecoveryPoint, point_id)
        assert pending and pending.verified is False
        assert pending.verification_version == 0
        assert pending.attestation_digest is None

    with SessionLocal() as database:
        promoted = promote_recovery_point(
            database,
            recovery_point_id=point_id,
            expected_version=0,
            expected_snapshot_id=snapshot_id,
            expected_checksum=checksum,
            attestation=attestation,
        )
        database.commit()
        assert promoted.promoted is True
        assert promoted.recovery_point.verified is True
        assert promoted.recovery_point.verification_version == 1
        assert promoted.recovery_point.attestation_digest == promoted.attestation_digest

    with SessionLocal() as database:
        replay = promote_recovery_point(
            database,
            recovery_point_id=point_id,
            expected_version=0,
            expected_snapshot_id=snapshot_id,
            expected_checksum=checksum,
            attestation=attestation,
        )
        assert replay.promoted is False
        with pytest.raises(RecoveryPointPromotionConflict):
            promote_recovery_point(
                database,
                recovery_point_id=point_id,
                expected_version=0,
                expected_snapshot_id=snapshot_id,
                expected_checksum=checksum,
                attestation=recovery_attestation(evidence_digest="d" * 64),
            )
        point = database.get(RecoveryPoint, point_id)
        assert point and point.attestation_digest == replay.attestation_digest
        assert point.verification_version == 1


def test_recovery_point_verification_api_audits_conflicting_attestation(
    client: TestClient, owner_token: str
) -> None:
    snapshot_id = "d" * 64
    checksum = "e" * 64
    with SessionLocal() as database:
        host = Host(name="api-promotion-node", address="192.0.2.62")
        database.add(host)
        database.flush()
        point = RecoveryPoint(
            host_id=host.id,
            service_name="controller",
            snapshot_id=snapshot_id,
            manifest={"schema_version": 1},
            checksum=checksum,
            verified=False,
        )
        database.add(point)
        database.commit()
        point_id = point.id

    payload = {
        "expected_version": 0,
        "expected_snapshot_id": snapshot_id,
        "expected_checksum": checksum,
        "attestation": {
            "schema_version": 1,
            "verifier": "staging-recovery-drill",
            "verification_method": "isolated_restore",
            "target_environment": "staging-isolated",
            "completed_at": "2026-07-18T12:00:00Z",
            "evidence_digest": "f" * 64,
        },
    }
    path = f"/api/v1/recovery-points/{point_id}/verify"
    client.cookies.clear()
    assert client.post(path, json=payload).status_code == 401
    promoted = client.post(
        path,
        json=payload,
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert promoted.status_code == 200
    assert promoted.json()["promoted"] is True
    assert promoted.json()["recovery_point"]["verification_version"] == 1
    replay = client.post(
        path,
        json=payload,
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert replay.status_code == 200
    assert replay.json()["promoted"] is False
    assert replay.json()["attestation_digest"] == promoted.json()["attestation_digest"]

    conflicting_payload = json.loads(json.dumps(payload))
    conflicting_payload["attestation"]["evidence_digest"] = "0" * 64
    conflict = client.post(
        path,
        json=conflicting_payload,
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert conflict.status_code == 409
    assert conflict.json()["detail"] == "recovery point verification conflict"

    with SessionLocal() as database:
        point = database.get(RecoveryPoint, point_id)
        conflict_audit = database.query(AuditLog).filter_by(
            action="recovery_point.verification_conflict",
            resource_id=point_id,
        ).one()
        assert point and point.attestation_digest == promoted.json()["attestation_digest"]
        assert conflict_audit.outcome == "conflict"
        assert len(str(conflict_audit.details["attestation_digest"])) == 64
