from __future__ import annotations

import ast
import hashlib
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest


def test_revision_identifiers_fit_alembic_version_column() -> None:
    versions = Path("controller/migrations/versions")
    for migration in versions.glob("*.py"):
        tree = ast.parse(migration.read_text(encoding="utf-8"))
        revision = next(
            node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "revision"
                for target in node.targets
            )
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
        assert len(revision) <= 32, f"{migration.name}: revision ID exceeds varchar(32)"


def test_migrations_enforce_audit_append_only(tmp_path: Path) -> None:
    database = tmp_path / "migration.db"
    environment = os.environ.copy()
    environment["GUARDIAN_DATABASE_URL"] = f"sqlite:///{database.as_posix()}"
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "controller/alembic.ini", "upgrade", "head"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr

    connection = sqlite3.connect(database)
    columns = {row[1] for row in connection.execute("PRAGMA table_info(approvals)")}
    assert "expires_at" in columns
    unique_agent_indexes = [
        row[1]
        for row in connection.execute("PRAGMA index_list(agents)")
        if row[2] == 1
    ]
    assert any(
        [column[2] for column in connection.execute(f"PRAGMA index_info({index})")]
        == ["certificate_serial"]
        for index in unique_agent_indexes
    )
    identity_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(agent_identities)")
    }
    assert {
        "generation",
        "rotation_id",
        "state",
        "expires_at",
        "verified_at",
        "successful_heartbeats",
        "last_pending_heartbeat_at",
        "retiring_at",
        "revoked_at",
        "retired_at",
    } <= identity_columns
    identity_indexes = {
        row[1]: row[2] for row in connection.execute("PRAGMA index_list(agent_identities)")
    }
    assert identity_indexes["uq_agent_identity_one_active"] == 1
    assert identity_indexes["uq_agent_identity_one_pending"] == 1
    recovery_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(recovery_points)")
    }
    assert {"verification_version", "attestation_digest"} <= recovery_columns
    recovery_table_sql = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'recovery_points'"
    ).fetchone()[0]
    assert "ck_recovery_point_verification_state" in recovery_table_sql
    assert "ck_recovery_point_attestation_digest" in recovery_table_sql
    host_columns = {row[1] for row in connection.execute("PRAGMA table_info(hosts)")}
    assert {"data_state", "enabled", "group_name", "tags", "enrolled_at", "disabled_at"} <= (
        host_columns
    )
    phase4b_tables = {
        "enrollment_tokens",
        "service_checks",
        "service_check_results",
        "alert_rules",
        "alert_instances",
        "alert_transitions",
        "maintenance_windows",
        "alert_silences",
        "notification_channels",
        "notification_deliveries",
    }
    actual_tables = {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert phase4b_tables <= actual_tables
    task_columns = {row[1] for row in connection.execute("PRAGMA table_info(agent_tasks)")}
    assert {
        "approval_id",
        "requester_id",
        "approver_id",
        "target_host_id",
        "verification_result",
        "started_at",
        "completed_at",
    } <= task_columns
    user_columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
    assert {
        "scopes",
        "session_version",
        "must_change_password",
        "identity_setup_enforced",
        "last_login_at",
        "password_changed_at",
        "totp_enabled_at",
        "disabled_at",
        "disabled_by",
        "created_by",
    } <= user_columns
    assert {"user_sessions", "recovery_codes"} <= actual_tables
    agent_columns = {row[1] for row in connection.execute("PRAGMA table_info(agents)")}
    assert {
        "build_git_sha",
        "build_id",
        "build_time",
        "go_version",
        "platform_os",
        "platform_arch",
        "build_dirty",
        "binary_sha256",
    } <= agent_columns
    alert_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(alert_instances)")
    }
    assert {"assigned_to", "closed_at"} <= alert_columns
    incident_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(incidents)")
    }
    assert {
        "assigned_to",
        "acknowledged_at",
        "updated_at",
        "resolution_summary",
        "postmortem",
    } <= incident_columns
    channel_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(notification_channels)")
    }
    assert {"event_scope", "severity_filter", "retry_policy"} <= channel_columns
    connection.execute(
        """
        INSERT INTO audit_logs
            (actor_id, action, resource_type, resource_id, outcome, details, source_ip, created_at)
        VALUES
            (NULL, 'migration.test', 'test', NULL, 'success', '{}', NULL, CURRENT_TIMESTAMP)
        """
    )
    connection.commit()
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute("UPDATE audit_logs SET outcome = 'tampered'")
    connection.rollback()
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute("DELETE FROM audit_logs")
    connection.close()


def test_phase4_completion_migration_round_trip(tmp_path: Path) -> None:
    database = tmp_path / "phase4-completion-round-trip.db"
    environment = os.environ.copy()
    environment["GUARDIAN_DATABASE_URL"] = f"sqlite:///{database.as_posix()}"
    commands = [
        ["upgrade", "head"],
        ["downgrade", "0007_multivps_alerts"],
        ["upgrade", "head"],
    ]
    for command in commands:
        result = subprocess.run(  # noqa: S603 - fixed Python/Alembic argv, no shell
            [
                sys.executable,
                "-m",
                "alembic",
                "-c",
                "controller/alembic.ini",
                *command,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
    connection = sqlite3.connect(database)
    assert "session_version" in {
        row[1] for row in connection.execute("PRAGMA table_info(users)")
    }
    assert "closed_at" in {
        row[1] for row in connection.execute("PRAGMA table_info(alert_instances)")
    }
    connection.close()


def test_identity_recovery_migrates_isolated_legacy_copy_and_preserves_core_rows(
    tmp_path: Path,
) -> None:
    database = tmp_path / "identity-legacy-copy.db"
    environment = os.environ.copy()
    environment["GUARDIAN_DATABASE_URL"] = f"sqlite:///{database.as_posix()}"

    def migrate(*arguments: str) -> None:
        result = subprocess.run(  # noqa: S603 - fixed Python/Alembic argv, no shell
            [
                sys.executable,
                "-m",
                "alembic",
                "-c",
                "controller/alembic.ini",
                *arguments,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr

    migrate("upgrade", "0009_agent_provenance")
    connection = sqlite3.connect(database)
    connection.execute(
        """
        INSERT INTO users
            (id, email, password_hash, role, totp_enabled, is_active, scopes,
             session_version, created_at)
        VALUES
            ('legacy-owner', 'legacy-owner@example.test', 'argon2id-placeholder',
             'owner', 0, 1, '[]', 1, CURRENT_TIMESTAMP)
        """
    )
    connection.execute(
        """
        INSERT INTO audit_logs
            (actor_id, action, resource_type, resource_id, outcome, details,
             source_ip, created_at)
        VALUES
            ('legacy-owner', 'legacy.identity', 'user', 'legacy-owner',
             'success', '{}', NULL, CURRENT_TIMESTAMP)
        """
    )
    connection.commit()
    connection.close()

    migrate("upgrade", "0010_identity_recovery")
    connection = sqlite3.connect(database)
    assert connection.execute("SELECT COUNT(*) FROM users").fetchone() == (1,)
    assert connection.execute("SELECT COUNT(*) FROM audit_logs").fetchone() == (1,)
    user = connection.execute(
        """
        SELECT email, session_version, must_change_password, identity_setup_enforced,
               last_login_at,
               password_changed_at, totp_enabled_at, disabled_at, disabled_by,
               created_by
        FROM users WHERE id = 'legacy-owner'
        """
    ).fetchone()
    assert user == (
        "legacy-owner@example.test",
        1,
        0,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    digest = "a" * 64
    connection.execute(
        """
        INSERT INTO recovery_codes
            (id, user_id, code_hash, batch_id, created_at)
        VALUES ('code-1', 'legacy-owner', ?, 'batch-1', CURRENT_TIMESTAMP)
        """,
        (digest,),
    )
    connection.execute(
        """
        INSERT INTO user_sessions
            (id, user_id, issued_at, expires_at, user_agent_digest, ip_digest,
             session_version)
        VALUES
            ('session-1', 'legacy-owner', CURRENT_TIMESTAMP,
             datetime(CURRENT_TIMESTAMP, '+30 minutes'), ?, ?, 1)
        """,
        ("b" * 64, "c" * 64),
    )
    connection.commit()
    assert connection.execute(
        "SELECT code_hash FROM recovery_codes WHERE id = 'code-1'"
    ).fetchone() == (digest,)
    assert connection.execute(
        "SELECT session_version FROM user_sessions WHERE id = 'session-1'"
    ).fetchone() == (1,)
    connection.close()

    migrate("upgrade", "head")
    connection = sqlite3.connect(database)
    migrated_session = connection.execute(
        """
        SELECT token_hash, created_via, last_seen_at, idle_expires_at,
               absolute_expires_at
        FROM user_sessions WHERE id = 'session-1'
        """
    ).fetchone()
    assert migrated_session is not None
    assert migrated_session[0] == hashlib.sha256(b"legacy:session-1").hexdigest()
    assert migrated_session[1] == "legacy"
    assert all(migrated_session[index] is not None for index in (2, 3, 4))
    connection.close()

    migrate("downgrade", "0009_agent_provenance")
    connection = sqlite3.connect(database)
    assert connection.execute("SELECT COUNT(*) FROM users").fetchone() == (1,)
    assert connection.execute("SELECT COUNT(*) FROM audit_logs").fetchone() == (1,)
    tables = {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert "user_sessions" not in tables
    assert "recovery_codes" not in tables
    connection.close()

    migrate("upgrade", "0010_identity_recovery")
    connection = sqlite3.connect(database)
    assert connection.execute("SELECT COUNT(*) FROM users").fetchone() == (1,)
    assert connection.execute("SELECT COUNT(*) FROM audit_logs").fetchone() == (1,)
    tables = {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert {"user_sessions", "recovery_codes"} <= tables
    connection.close()


def test_agent_certificate_serials_are_normalized_before_unique_constraint(
    tmp_path: Path,
) -> None:
    database = tmp_path / "serial-migration.db"
    environment = os.environ.copy()
    environment["GUARDIAN_DATABASE_URL"] = f"sqlite:///{database.as_posix()}"
    first = subprocess.run(
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            "controller/alembic.ini",
            "upgrade",
            "0002_approval_audit_guards",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
    )
    assert first.returncode == 0, first.stderr
    connection = sqlite3.connect(database)
    connection.execute(
        "INSERT INTO hosts (id, name, address, status, labels, created_at) "
        "VALUES ('host-1', 'legacy-host', '192.0.2.1', 'unknown', '{}', CURRENT_TIMESTAMP)"
    )
    connection.execute(
        "INSERT INTO agents "
        "(id, host_id, signing_public_key, certificate_fingerprint, certificate_serial) "
        "VALUES ('agent-1', 'host-1', 'public', :fingerprint, '0000100a')",
        {"fingerprint": "AA" * 32},
    )
    connection.commit()
    connection.close()

    second = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "controller/alembic.ini", "upgrade", "head"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
    )
    assert second.returncode == 0, second.stderr
    connection = sqlite3.connect(database)
    serial = connection.execute(
        "SELECT certificate_serial FROM agents WHERE id = 'agent-1'"
    ).fetchone()
    assert serial == ("100A",)
    identity = connection.execute(
        """
        SELECT generation, state, certificate_fingerprint, certificate_serial,
               expires_at, verified_at, activated_at, retired_at
        FROM agent_identities WHERE agent_id = 'agent-1'
        """
    ).fetchone()
    assert identity[:5] == (1, "active", "AA" * 32, "100A", None)
    assert identity[5] is not None
    assert identity[6] is not None
    assert identity[7] is None
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "UPDATE agent_identities SET state = 'invalid' WHERE agent_id = 'agent-1'"
        )
    connection.rollback()
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "UPDATE agent_identities SET generation = 0 WHERE agent_id = 'agent-1'"
        )
    connection.rollback()
    connection.close()


def test_dual_identity_migration_rejects_an_active_agent_without_a_serial(
    tmp_path: Path,
) -> None:
    database = tmp_path / "missing-serial-migration.db"
    environment = os.environ.copy()
    environment["GUARDIAN_DATABASE_URL"] = f"sqlite:///{database.as_posix()}"
    first = subprocess.run(
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            "controller/alembic.ini",
            "upgrade",
            "0003_agent_cert_serial_unique",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
    )
    assert first.returncode == 0, first.stderr
    connection = sqlite3.connect(database)
    connection.execute(
        "INSERT INTO hosts (id, name, address, status, labels, created_at) "
        "VALUES ('host-1', 'legacy-host', '192.0.2.1', 'unknown', '{}', CURRENT_TIMESTAMP)"
    )
    connection.execute(
        "INSERT INTO agents "
        "(id, host_id, signing_public_key, certificate_fingerprint, certificate_serial) "
        "VALUES ('agent-1', 'host-1', 'public', :fingerprint, NULL)",
        {"fingerprint": "AA" * 32},
    )
    connection.commit()
    connection.close()

    second = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "controller/alembic.ini", "upgrade", "head"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
    )

    assert second.returncode != 0
    assert "require a normalized certificate serial" in second.stderr


def test_recovery_attestation_migration_backfills_verified_and_normalizes_pending(
    tmp_path: Path,
) -> None:
    database = tmp_path / "recovery-attestation-migration.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE alembic_version (
            version_num VARCHAR(32) NOT NULL PRIMARY KEY
        );
        INSERT INTO alembic_version (version_num) VALUES ('0004_agent_dual_identity');
        CREATE TABLE recovery_points (
            id VARCHAR(36) NOT NULL PRIMARY KEY,
            host_id VARCHAR(36) NOT NULL,
            service_name VARCHAR(120) NOT NULL,
            snapshot_id VARCHAR(128) NOT NULL UNIQUE,
            manifest JSON NOT NULL,
            checksum VARCHAR(128) NOT NULL,
            verified BOOLEAN NOT NULL,
            verified_at DATETIME,
            created_at DATETIME NOT NULL
        );
        INSERT INTO recovery_points
            (id, host_id, service_name, snapshot_id, manifest, checksum,
             verified, verified_at, created_at)
        VALUES
            ('verified-point', 'host-1', 'controller',
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
             '{}',
             'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
             1, NULL, '2026-07-18 12:00:00'),
            ('pending-point', 'host-1', 'controller',
             'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
             '{}',
             'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
             0, '2026-07-18 12:30:00', '2026-07-18 12:00:00');
        """
    )
    connection.commit()
    connection.close()
    environment = os.environ.copy()
    environment["GUARDIAN_DATABASE_URL"] = f"sqlite:///{database.as_posix()}"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            "controller/alembic.ini",
            "upgrade",
            "0005_recovery_attestation",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr

    connection = sqlite3.connect(database)
    verified = connection.execute(
        """
        SELECT verified, verified_at, verification_version, attestation_digest
        FROM recovery_points WHERE id = 'verified-point'
        """
    ).fetchone()
    pending = connection.execute(
        """
        SELECT verified, verified_at, verification_version, attestation_digest
        FROM recovery_points WHERE id = 'pending-point'
        """
    ).fetchone()
    assert verified[0:3] == (1, "2026-07-18 12:00:00", 1)
    assert len(verified[3]) == 64
    assert pending == (0, None, 0, None)
    with pytest.raises(sqlite3.IntegrityError, match="verification_state"):
        connection.execute(
            "UPDATE recovery_points SET attestation_digest = NULL WHERE id = 'verified-point'"
        )
    connection.rollback()
    with pytest.raises(sqlite3.IntegrityError, match="attestation_digest"):
        connection.execute(
            "UPDATE recovery_points SET attestation_digest = :digest "
            "WHERE id = 'verified-point'",
            {"digest": "z" * 64},
        )
    connection.close()
