from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
import stat
import tempfile
import unicodedata
from collections.abc import Mapping
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import SQLAlchemyError

from guardian.backup import (
    BackupCoordinator,
    BackupError,
    DatabaseBackup,
    MySQLBackup,
    PostgreSQLBackup,
    ResticAdapter,
    RetentionPolicy,
    SQLiteBackup,
    SubprocessExecutor,
    load_restic_config,
    read_controlled_secret_file,
    record_recovery_point,
)
from guardian.config import get_settings

app = typer.Typer(
    name="guardian-backup",
    help="Create encrypted, checksummed, trial-restored Guardian recovery points.",
)


@app.callback()
def main() -> None:
    """Select a backup workflow."""


def _fail(exc: Exception) -> NoReturn:
    typer.echo(f"backup error: {exc}", err=True)
    raise typer.Exit(code=2)


def _restic() -> ResticAdapter:
    return ResticAdapter(load_restic_config())


def _minimum_free_bytes() -> int:
    raw_value = os.getenv("GUARDIAN_BACKUP_MIN_FREE_BYTES", "1073741824")
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise BackupError("invalid backup staging free-space requirement") from exc
    if value < 64 * 1024**2 or value > 10 * 1024**4:
        raise BackupError("backup staging free-space requirement is outside allowed bounds")
    return value


def _escape_pgpass(value: str) -> str:
    return value.replace("\\", "\\\\").replace(":", "\\:")


def _connection_value(value: str, label: str, *, maximum: int = 4096) -> str:
    if (
        not value
        or len(value.encode("utf-8")) > maximum
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        raise BackupError(f"invalid {label}")
    return value


def _url_query(url: URL, allowed: set[str]) -> dict[str, str]:
    unknown = set(url.query) - allowed
    if unknown:
        raise BackupError("database URL contains unsupported connection parameters")
    result: dict[str, str] = {}
    for key, raw_value in url.query.items():
        if not isinstance(raw_value, str):
            raise BackupError("database URL connection parameters must be single values")
        result[key] = _connection_value(raw_value, f"database URL parameter {key}")
    return result


def _database_host_is_local(host: str) -> bool:
    normalized = host.rstrip(".").casefold()
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return normalized in {"localhost", "database", "restore-postgres", "restore-mysql"}


def _postgres_backup(url: URL, temporary: Path) -> PostgreSQLBackup:
    if not url.host or not url.username or not url.database or url.password is None:
        raise BackupError("PostgreSQL URL must include host, user, password, and database")
    port = url.port or 5432
    for value, label in (
        (url.host, "PostgreSQL host"),
        (url.username, "PostgreSQL user"),
        (url.database, "PostgreSQL database"),
        (url.password, "PostgreSQL password"),
    ):
        _connection_value(value, label)
    query_to_environment = {
        "channel_binding": "PGCHANNELBINDING",
        "connect_timeout": "PGCONNECT_TIMEOUT",
        "gssencmode": "PGGSSENCMODE",
        "sslcert": "PGSSLCERT",
        "sslcrl": "PGSSLCRL",
        "sslkey": "PGSSLKEY",
        "ssl_max_protocol_version": "PGSSLMAXPROTOCOLVERSION",
        "ssl_min_protocol_version": "PGSSLMINPROTOCOLVERSION",
        "sslmode": "PGSSLMODE",
        "sslrootcert": "PGSSLROOTCERT",
        "target_session_attrs": "PGTARGETSESSIONATTRS",
    }
    query = _url_query(url, set(query_to_environment))
    if "sslmode" in query and query["sslmode"] not in {
        "disable",
        "allow",
        "prefer",
        "require",
        "verify-ca",
        "verify-full",
    }:
        raise BackupError("invalid PostgreSQL sslmode")
    if not _database_host_is_local(url.host) and query.get("sslmode") != "verify-full":
        raise BackupError("remote PostgreSQL backups require sslmode=verify-full")
    passfile = temporary / "pgpass"
    passfile.write_text(
        ":".join(
            _escape_pgpass(value)
            for value in (url.host, str(port), url.database, url.username, url.password)
        )
        + "\n",
        encoding="utf-8",
    )
    passfile.chmod(0o600)
    return PostgreSQLBackup(
        host=url.host,
        port=port,
        user=url.username,
        database=url.database,
        passfile=passfile,
        executor=SubprocessExecutor(),
        connection_environment={query_to_environment[key]: value for key, value in query.items()},
    )


def _mysql_option(value: str, label: str) -> str:
    cleaned = _connection_value(value, label)
    escaped = cleaned.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _mysql_backup(url: URL, temporary: Path) -> MySQLBackup:
    if not url.host or not url.username or not url.database or url.password is None:
        raise BackupError("MySQL URL must include host, user, password, and database")
    for value, label in (
        (url.host, "MySQL host"),
        (url.username, "MySQL user"),
        (url.database, "MySQL database"),
        (url.password, "MySQL password"),
    ):
        _connection_value(value, label)
    query_to_option = {
        "ssl_ca": "ssl-ca",
        "ssl_cert": "ssl-cert",
        "ssl_key": "ssl-key",
        "ssl_mode": "ssl-mode",
    }
    query = _url_query(url, set(query_to_option))
    if "ssl_mode" in query and query["ssl_mode"].upper() not in {
        "REQUIRED",
        "VERIFY_CA",
        "VERIFY_IDENTITY",
    }:
        raise BackupError("MySQL ssl_mode must require TLS")
    if (
        not _database_host_is_local(url.host)
        and query.get("ssl_mode", "").upper() != "VERIFY_IDENTITY"
    ):
        raise BackupError("remote MySQL backups require ssl_mode=VERIFY_IDENTITY")
    if any(key in query for key in ("ssl_ca", "ssl_cert", "ssl_key")) and (
        query.get("ssl_mode", "").upper() != "VERIFY_IDENTITY"
    ):
        raise BackupError("MySQL TLS files require ssl_mode=VERIFY_IDENTITY")
    option_lines = [
        "[client]",
        f"host={_mysql_option(url.host, 'MySQL host')}",
        f"port={url.port or 3306}",
        f"user={_mysql_option(url.username, 'MySQL user')}",
        f"password={_mysql_option(url.password, 'MySQL password')}",
    ]
    option_lines.extend(
        f"{query_to_option[key]}={_mysql_option(value, f'MySQL {key}')}"
        for key, value in query.items()
    )
    defaults_file = temporary / "mysql.cnf"
    defaults_file.write_text("\n".join(option_lines) + "\n", encoding="utf-8")
    defaults_file.chmod(0o600)
    return MySQLBackup(
        database=url.database,
        defaults_file=defaults_file,
        executor=SubprocessExecutor(),
    )


def _database_backup_from_url(url: URL, temporary: Path) -> DatabaseBackup:
    if url.drivername.startswith("sqlite"):
        if not url.database or url.database == ":memory:":
            raise BackupError("an in-memory SQLite database cannot be backed up")
        return SQLiteBackup(Path(url.database))
    if url.drivername.startswith("postgresql"):
        return _postgres_backup(url, temporary)
    if url.drivername.startswith("mysql"):
        return _mysql_backup(url, temporary)
    raise BackupError(f"unsupported controller database driver: {url.drivername}")


def _database_url_from_file(path: Path, *, controlled: bool = False) -> URL:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise BackupError("database URL file must be an absolute regular file")
    if controlled:
        value = read_controlled_secret_file(path, label="database URL")
    else:
        if path.stat().st_size > 4096:
            raise BackupError("database URL file is unexpectedly large")
        value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise BackupError("database URL file is empty")
    try:
        return make_url(value)
    except ValueError as exc:
        raise BackupError("database URL file is invalid") from exc


def _sqlite_restore_validator(root: Path, _: Mapping[str, object]) -> bool:
    candidates = list(root.rglob("sqlite.db"))
    if len(candidates) != 1:
        return False
    with closing(sqlite3.connect(f"file:{candidates[0].as_posix()}?mode=ro", uri=True)) as db:
        row = db.execute("PRAGMA integrity_check").fetchone()
    return bool(row and row[0] == "ok")


def _source_commit(path: Path, *, platform_name: str = os.name) -> str:
    if not path.is_absolute():
        raise BackupError("source commit file must be an absolute path")
    try:
        resolved = path.resolve(strict=True)
        if path.is_symlink():
            raise BackupError("source commit file is missing or unsafe")
        descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except (OSError, UnicodeError) as exc:
        raise BackupError("source commit file is missing or unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size not in {40, 41}
            or (platform_name == "posix" and (metadata.st_uid != 0 or metadata.st_mode & 0o022))
        ):
            raise BackupError("source commit file is missing or unsafe")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw_payload = handle.read(42)
    finally:
        os.close(descriptor)
    try:
        payload = raw_payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise BackupError("source commit file is missing or unsafe") from exc
    value = payload[:-1] if payload.endswith("\n") else payload
    if (
        value.endswith("\r")
        or payload not in {value, f"{value}\n"}
        or not re.fullmatch(r"(?!0{40})[A-Fa-f0-9]{40}", value)
    ):
        raise BackupError("source commit file is missing or unsafe")
    return value.lower()


def _alembic_revisions(url: URL) -> list[str]:
    engine = create_engine(url, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            revisions = sorted(
                str(value)
                for value in connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalars()
            )
    except SQLAlchemyError as exc:
        raise BackupError("could not read the controller Alembic revision") from exc
    finally:
        engine.dispose()
    if not revisions:
        raise BackupError("controller database has no Alembic revision")
    return revisions


def _controller_recovery_metadata(
    *,
    source_commit_file: Path,
    database_url: URL,
    sources: list[Path],
) -> dict[str, object]:
    return {
        "source_commit": _source_commit(source_commit_file),
        "alembic_revisions": _alembic_revisions(database_url),
        "configuration_references": [
            "controller environment",
            "database URL",
            *(f"backup source: {source.name}" for source in sources),
        ],
        "public_certificate_references": [
            "agent CA certificate",
            "agent certificate revocation list",
            "controller signing public key",
        ],
        "external_secret_references": [
            "agent CA private key",
            "controller signing private key",
            "database credential",
            "field encryption key",
            "JWT secret",
            "Restic password",
            "S3 access key",
        ],
    }


@app.command("repository-init")
def repository_init(
    execute: Annotated[bool, typer.Option("--execute")] = False,
    confirmation: Annotated[str | None, typer.Option("--confirm")] = None,
) -> None:
    """Initialize only the configured repository after an exact confirmation."""
    if not execute or confirmation != "INITIALIZE RESTIC REPOSITORY":
        _fail(BackupError("repository initialization requires --execute and exact confirmation"))
    try:
        _restic().initialize()
    except (BackupError, OSError, ValueError) as exc:
        _fail(exc)
    typer.echo(json.dumps({"status": "initialized"}, ensure_ascii=True))


@app.command("repository-check")
def repository_check(
    read_data_subset: Annotated[str, typer.Option("--read-data-subset")] = "5%",
) -> None:
    """Run Restic integrity checking with a real-data subset."""
    try:
        _restic().check(read_data_subset=read_data_subset)
    except (BackupError, OSError, ValueError) as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            {"status": "checked", "read_data_subset": read_data_subset},
            ensure_ascii=True,
        )
    )


def _retention_policy(hourly: int, daily: int, weekly: int, monthly: int) -> RetentionPolicy:
    return RetentionPolicy(
        keep_hourly=hourly,
        keep_daily=daily,
        keep_weekly=weekly,
        keep_monthly=monthly,
    )


@app.command("retention-plan")
def retention_plan(
    host: Annotated[str, typer.Option(help="Exact Guardian backup host scope.")],
    service: Annotated[str, typer.Option(help="Exact Guardian backup service scope.")],
    hourly: Annotated[int, typer.Option("--keep-hourly")] = 24,
    daily: Annotated[int, typer.Option("--keep-daily")] = 7,
    weekly: Annotated[int, typer.Option("--keep-weekly")] = 4,
    monthly: Annotated[int, typer.Option("--keep-monthly")] = 12,
) -> None:
    """Create a scoped dry-run plan whose digest can be approved exactly."""
    try:
        plan = _restic().retention_plan(
            _retention_policy(hourly, daily, weekly, monthly),
            host=host,
            service=service,
        )
    except (BackupError, OSError, ValueError) as exc:
        _fail(exc)
    typer.echo(json.dumps(asdict(plan), indent=2, ensure_ascii=True))


@app.command("retention-apply")
def retention_apply(
    host: Annotated[str, typer.Option(help="Exact Guardian backup host scope.")],
    service: Annotated[str, typer.Option(help="Exact Guardian backup service scope.")],
    plan_digest: Annotated[str, typer.Option("--plan-digest")],
    approval_id: Annotated[str, typer.Option("--approval-id")],
    confirmation: Annotated[str, typer.Option("--confirm")],
    hourly: Annotated[int, typer.Option("--keep-hourly")] = 24,
    daily: Annotated[int, typer.Option("--keep-daily")] = 7,
    weekly: Annotated[int, typer.Option("--keep-weekly")] = 4,
    monthly: Annotated[int, typer.Option("--keep-monthly")] = 12,
) -> None:
    """Forget only IDs from the currently approved Guardian retention plan."""
    try:
        plan = _restic().apply_retention(
            _retention_policy(hourly, daily, weekly, monthly),
            host=host,
            service=service,
            plan_digest=plan_digest,
            approval_id=approval_id,
            confirmation=confirmation,
        )
    except (BackupError, OSError, ValueError) as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            {
                "status": "applied",
                "plan_digest": plan.digest,
                "removed_snapshot_ids": plan.remove_snapshot_ids,
            },
            ensure_ascii=True,
        )
    )


@app.command("controller")
def controller_backup(
    source: Annotated[
        list[Path] | None,
        typer.Option("--source", help="Configuration or data source to include."),
    ] = None,
    host: Annotated[str, typer.Option(help="Inventory host name.")] = "controller",
    service: Annotated[str, typer.Option(help="Recovery service name.")] = "controller",
    source_commit_file: Annotated[
        Path | None,
        typer.Option("--source-commit-file", help="Root-controlled release commit file."),
    ] = None,
) -> None:
    """Back up controller configuration and its database, then perform an isolated trial restore."""
    try:
        from sqlalchemy import select

        from guardian.database import SessionLocal
        from guardian.models import Host

        configured_commit_file = source_commit_file
        if configured_commit_file is None:
            commit_path = os.getenv("GUARDIAN_SOURCE_COMMIT_FILE", "")
            if not commit_path:
                raise BackupError("GUARDIAN_SOURCE_COMMIT_FILE is required")
            configured_commit_file = Path(commit_path)
        settings = get_settings()
        database_url = make_url(settings.database_url)
        recovery_metadata = _controller_recovery_metadata(
            source_commit_file=configured_commit_file,
            database_url=database_url,
            sources=source or [],
        )
        with tempfile.TemporaryDirectory(prefix="guardian-db-secret-") as temporary:
            database_backup = _database_backup_from_url(database_url, Path(temporary))
            result = BackupCoordinator(_restic()).create_backup(
                host=host,
                service=service,
                sources=source or [],
                database=database_backup,
                verify=True,
                validator=(
                    _sqlite_restore_validator if isinstance(database_backup, SQLiteBackup) else None
                ),
                recovery_metadata=recovery_metadata,
                minimum_free_bytes=_minimum_free_bytes(),
            )
        recorded = False
        recording_error: str | None = None
        try:
            with SessionLocal() as database:
                inventory_host = database.scalar(select(Host).where(Host.name == host))
                if inventory_host:
                    record_recovery_point(
                        database,
                        host_id=inventory_host.id,
                        service=service,
                        result=result,
                    )
                    database.commit()
                    recorded = True
                else:
                    recording_error = "inventory_host_not_found"
        except SQLAlchemyError:
            recording_error = "recovery_point_persistence_failed"
    except (BackupError, OSError, ValueError) as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            {
                "snapshot_id": result.snapshot_id,
                "checksum": result.checksum,
                "source_commit": recovery_metadata["source_commit"],
                "uploaded": True,
                "repository_checked": True,
                "manifest_restored": True,
                "database_restore_verified": result.verified,
                "verified": result.verified,
                "verification_state": "verified" if result.verified else "pending",
                "recorded": recorded,
                "recording_error": recording_error,
            },
            ensure_ascii=True,
        )
    )


@app.command("service")
def service_backup(
    database_url_file: Annotated[
        Path,
        typer.Option("--database-url-file", help="Protected file containing one database URL."),
    ],
    source: Annotated[
        list[Path] | None,
        typer.Option("--source", help="Additional configuration or data source to include."),
    ] = None,
    host: Annotated[str, typer.Option(help="Staging inventory host name.")] = "staging",
    service: Annotated[str, typer.Option(help="Recovery service name.")] = "service",
) -> None:
    """Back up a service database without exposing its URL in argv or controller inventory."""
    try:
        database_url = _database_url_from_file(database_url_file)
        with tempfile.TemporaryDirectory(prefix="guardian-db-secret-") as temporary:
            database_backup = _database_backup_from_url(database_url, Path(temporary))
            result = BackupCoordinator(_restic()).create_backup(
                host=host,
                service=service,
                sources=source or [],
                database=database_backup,
                verify=True,
                validator=(
                    _sqlite_restore_validator if isinstance(database_backup, SQLiteBackup) else None
                ),
                minimum_free_bytes=_minimum_free_bytes(),
            )
    except (BackupError, OSError, ValueError) as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            {
                "snapshot_id": result.snapshot_id,
                "checksum": result.checksum,
                "verified": result.verified,
                "recorded": False,
            },
            ensure_ascii=True,
        )
    )


if __name__ == "__main__":
    app()
