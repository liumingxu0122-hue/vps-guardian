from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess  # noqa: S404 - fixed argv execution is the adapter's purpose.
import tempfile
import unicodedata
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Protocol, cast
from urllib.parse import urlsplit

from sqlalchemy import func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from guardian.models import RecoveryPoint


class BackupError(RuntimeError):
    """A backup or recovery operation failed without exposing command secrets."""


class RecoveryPointNotFoundError(BackupError):
    """The requested RecoveryPoint does not exist."""


class RecoveryPointPromotionConflict(BackupError):
    """The pending RecoveryPoint no longer matches the caller's CAS preconditions."""

    def __init__(self, *, attestation_digest: str) -> None:
        super().__init__("recovery point verification conflict")
        self.attestation_digest = attestation_digest


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandExecutor(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        timeout: int = 900,
    ) -> CommandResult: ...


class SubprocessExecutor:
    _POSIX_SIGTERM = 15
    _POSIX_SIGKILL = 9

    def __init__(self, *, platform_name: str | None = None) -> None:
        self.platform_name = platform_name or os.name

    def _stop(self, process: subprocess.Popen[str], *, force: bool) -> None:
        try:
            if self.platform_name == "posix":
                signal_number = self._POSIX_SIGKILL if force else self._POSIX_SIGTERM
                kill_process_group = os.__dict__.get("killpg")
                if not callable(kill_process_group):
                    raise BackupError("POSIX process-group signaling is unavailable")
                kill_process_group(process.pid, signal_number)
            elif force:
                process.kill()
            else:
                process.terminate()
        except ProcessLookupError:
            pass

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        timeout: int = 900,
    ) -> CommandResult:
        if not argv or any("\x00" in item for item in argv):
            raise BackupError("invalid command arguments")
        try:
            process = subprocess.Popen(  # noqa: S603 - argv is never passed through a shell.
                list(argv),
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=dict(env) if env is not None else None,
                cwd=cwd,
                start_new_session=self.platform_name == "posix",
            )
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                self._stop(process, force=False)
                try:
                    process.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    self._stop(process, force=True)
                    process.communicate()
                else:
                    # The parent may exit while a descendant ignores SIGTERM and closes its pipes.
                    # Signal the original process group once more before returning control.
                    if self.platform_name == "posix":
                        self._stop(process, force=True)
                raise BackupError("command timed out after graceful termination") from exc
        except OSError as exc:
            raise BackupError(f"command execution failed: {type(exc).__name__}") from exc
        return CommandResult(process.returncode, stdout, stderr)


_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$")
_PASSTHROUGH_ENV = {
    "HOME",
    "LANG",
    "PATH",
    "RESTIC_CACHE_DIR",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
}
_RESTIC_CREDENTIAL_FILE_ENV = {
    "AWS_ACCESS_KEY_ID": "AWS_ACCESS_KEY_ID_FILE",
    "AWS_SECRET_ACCESS_KEY": "AWS_SECRET_ACCESS_KEY_FILE",
    "AWS_DEFAULT_REGION": "AWS_DEFAULT_REGION_FILE",
}
_REQUIRED_S3_CREDENTIALS = frozenset(_RESTIC_CREDENTIAL_FILE_ENV)
_CONTROLLED_SECRET_MODES = frozenset({0o400, 0o440, 0o600, 0o640})
_COMPOSE_SECRET_MODE = 0o444
_POSTGRES_CONNECTION_ENV = frozenset(
    {
        "PGCHANNELBINDING",
        "PGCONNECT_TIMEOUT",
        "PGGSSENCMODE",
        "PGSSLCRL",
        "PGSSLCERT",
        "PGSSLKEY",
        "PGSSLMAXPROTOCOLVERSION",
        "PGSSLMINPROTOCOLVERSION",
        "PGSSLMODE",
        "PGSSLROOTCERT",
        "PGTARGETSESSIONATTRS",
    }
)


def _validate_controlled_secret_metadata(
    *,
    path: Path,
    mode: int,
    owner_uid: int,
    platform_name: str,
) -> None:
    if platform_name != "posix":
        return
    if owner_uid != 0:
        raise BackupError("controlled secret file must be root-owned")
    allowed_modes = set(_CONTROLLED_SECRET_MODES)
    if path.is_relative_to(Path("/run/secrets")):
        allowed_modes.add(_COMPOSE_SECRET_MODE)
    if mode not in allowed_modes:
        allowed = ", ".join(f"{item:04o}" for item in sorted(allowed_modes))
        raise BackupError(f"controlled secret file mode must be one of: {allowed}")


def read_controlled_secret_file(
    path: Path,
    *,
    label: str,
    maximum_bytes: int = 4096,
) -> str:
    """Read one root-owned secret without following symlinks or accepting loose modes."""
    if not path.is_absolute():
        raise BackupError(f"{label} file must be an absolute path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise BackupError(f"{label} file is missing or unsafe") from exc
    if resolved != path or path.is_symlink():
        raise BackupError(f"{label} file is missing or unsafe")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BackupError(f"{label} file is missing or unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise BackupError(f"{label} file is missing or unsafe")
        _validate_controlled_secret_metadata(
            path=path,
            mode=stat.S_IMODE(metadata.st_mode),
            owner_uid=metadata.st_uid,
            platform_name=os.name,
        )
        if metadata.st_size < 1 or metadata.st_size > maximum_bytes:
            raise BackupError(f"{label} file has an invalid size")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read(maximum_bytes + 1)
    finally:
        os.close(descriptor)
    if len(payload) > maximum_bytes:
        raise BackupError(f"{label} file has an invalid size")

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BackupError(f"{label} file must contain UTF-8 text") from exc
    if text.endswith("\r\n"):
        value = text[:-2]
    elif text.endswith("\n"):
        value = text[:-1]
    else:
        value = text
    if (
        not value
        or value != value.strip()
        or any(
            character.isspace() or unicodedata.category(character).startswith("C")
            for character in value
        )
    ):
        raise BackupError(f"{label} file contains an invalid value")
    return value


def _configured_credential_files(environment: Mapping[str, str]) -> dict[str, Path]:
    return {
        variable: Path(path)
        for variable, file_variable in _RESTIC_CREDENTIAL_FILE_ENV.items()
        if (path := environment.get(file_variable, ""))
    }


def load_restic_config(
    *,
    repository: str | None = None,
    password_file: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> ResticConfig:
    source = os.environ if environment is None else environment
    repository_file = source.get("RESTIC_REPOSITORY_FILE", "")
    environment_repository = source.get("RESTIC_REPOSITORY", "")
    controlled = bool(repository_file) or source.get("GUARDIAN_CONTROLLED_BACKUP_CONFIG") == "1"
    if repository is None:
        if repository_file and environment_repository:
            raise BackupError("configure only one Restic repository source")
        if repository_file:
            repository = read_controlled_secret_file(
                Path(repository_file),
                label="Restic repository",
            )
        else:
            repository = environment_repository
    if password_file is None:
        configured_password_file = source.get("RESTIC_PASSWORD_FILE", "")
        password_file = Path(configured_password_file) if configured_password_file else None
    if not repository or password_file is None:
        raise BackupError("Restic repository and password file are required")
    timeout_value = source.get("RESTIC_BACKUP_TIMEOUT_SECONDS", "14400")
    try:
        backup_timeout_seconds = int(timeout_value)
    except ValueError as exc:
        raise BackupError("invalid Restic backup timeout") from exc
    return ResticConfig(
        repository=repository,
        password_file=password_file,
        binary=source.get("RESTIC_BINARY", "restic"),
        credential_files=_configured_credential_files(source),
        controlled=controlled,
        local_repository_root=(
            Path(value) if (value := source.get("RESTIC_LOCAL_REPOSITORY_ROOT", "")) else None
        ),
        backup_timeout_seconds=backup_timeout_seconds,
    )


def _validate_name(value: str, label: str) -> str:
    if not _SAFE_NAME.fullmatch(value):
        raise BackupError(f"invalid {label}")
    return value


def _contains_url_credentials(repository: str) -> bool:
    candidate = repository.removeprefix("s3:")
    if "?" in candidate or "#" in candidate:
        return True
    if "://" not in candidate:
        if candidate.startswith("//"):
            candidate = candidate[2:]
        return "@" in candidate.partition("/")[0]
    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise BackupError("invalid Restic repository URL") from exc
    return parsed.username is not None or parsed.password is not None


@dataclass(frozen=True)
class ResticConfig:
    repository: str
    password_file: Path
    binary: str = "restic"
    credential_files: Mapping[str, Path] | None = None
    controlled: bool = False
    local_repository_root: Path | None = None
    backup_timeout_seconds: int = 14400

    def __post_init__(self) -> None:
        if not self.repository.strip():
            raise BackupError("Restic repository is required")
        if _contains_url_credentials(self.repository):
            raise BackupError("repository URLs must not contain credentials")
        if self.repository.startswith("s3:"):
            try:
                transport = urlsplit(self.repository[3:])
            except ValueError as exc:
                raise BackupError("invalid S3 Restic repository URL") from exc
            if transport.scheme.casefold() != "https":
                raise BackupError("S3 Restic repositories must use TLS")
            if (
                not transport.hostname
                or not transport.path.strip("/")
                or transport.username is not None
                or transport.password is not None
                or transport.query
                or transport.fragment
            ):
                raise BackupError(
                    "S3 Restic repositories must use a credential-free TLS URL with a bucket"
                )
        if self.repository.startswith(("http:", "https:")):
            raise BackupError("only local and S3-compatible Restic repositories are supported")
        if "://" in self.repository and not self.repository.startswith("s3:"):
            raise BackupError("only local and S3-compatible Restic repositories are supported")
        if not self.repository.startswith("s3:") and not Path(self.repository).is_absolute():
            raise BackupError("local Restic repositories must use an absolute path")
        if self.local_repository_root is not None:
            if not self.controlled or not self.local_repository_root.is_absolute():
                raise BackupError(
                    "local repository root requires controlled absolute configuration"
                )
            if not self.repository.startswith("s3:"):
                repository_path = Path(self.repository)
                resolved_root = self.local_repository_root.resolve(strict=False)
                resolved_repository = repository_path.resolve(strict=False)
                if (
                    resolved_root != self.local_repository_root
                    or resolved_repository != repository_path
                ):
                    raise BackupError("controlled local Restic paths must be canonical")
                try:
                    resolved_repository.relative_to(resolved_root)
                except ValueError as exc:
                    raise BackupError(
                        "local Restic repository is outside the controlled root"
                    ) from exc
        if not self.binary or any(char.isspace() for char in self.binary):
            raise BackupError("invalid Restic binary")
        if self.backup_timeout_seconds < 900 or self.backup_timeout_seconds > 86400:
            raise BackupError("Restic backup timeout must be between 900 and 86400 seconds")
        unsupported = set(self.credential_files or {}) - set(_RESTIC_CREDENTIAL_FILE_ENV)
        if unsupported:
            raise BackupError("unsupported Restic credential file")
        if self.repository.startswith("s3:"):
            missing = _REQUIRED_S3_CREDENTIALS - set(self.credential_files or {})
            if missing:
                raise BackupError("S3 Restic requires access-key, secret-key, and region files")

    def environment(self) -> dict[str, str]:
        environment = {key: value for key, value in os.environ.items() if key in _PASSTHROUGH_ENV}
        if not self.repository.startswith("s3:"):
            return environment
        for key, path in (self.credential_files or {}).items():
            value = read_controlled_secret_file(path, label=key, maximum_bytes=512)
            if key == "AWS_DEFAULT_REGION" and not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value
            ):
                raise BackupError("AWS_DEFAULT_REGION file contains an invalid region")
            environment[key] = value
        return environment

    def validate_secret_file(self) -> None:
        path = self.password_file.expanduser()
        if self.controlled or self.repository.startswith("s3:"):
            read_controlled_secret_file(path, label="Restic password")
            return
        if not path.is_file() or path.is_symlink():
            raise BackupError("Restic password file is missing or unsafe")
        try:
            if path.stat().st_size > 4096:
                raise BackupError("Restic password file has an invalid size")
            password = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise BackupError("Restic password file is missing or unsafe") from exc
        if not password.strip():
            raise BackupError("Restic password file is empty")


@dataclass(frozen=True)
class SnapshotInfo:
    snapshot_id: str
    short_id: str
    host: str
    time: str
    tags: tuple[str, ...]

    def tag_value(self, prefix: str) -> str | None:
        return next((tag.removeprefix(prefix) for tag in self.tags if tag.startswith(prefix)), None)


@dataclass(frozen=True)
class RetentionPolicy:
    keep_hourly: int = 24
    keep_daily: int = 7
    keep_weekly: int = 4
    keep_monthly: int = 12

    def __post_init__(self) -> None:
        values = (self.keep_hourly, self.keep_daily, self.keep_weekly, self.keep_monthly)
        if any(value < 0 or value > 1000 for value in values) or not any(values):
            raise BackupError("invalid retention policy")


@dataclass(frozen=True)
class RetentionPlan:
    host: str
    service: str
    groups: tuple[dict[str, Any], ...]
    remove_snapshot_ids: tuple[str, ...]
    digest: str


def _canonical_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class ResticAdapter:
    def __init__(self, config: ResticConfig, executor: CommandExecutor | None = None) -> None:
        self.config = config
        self.executor = executor or SubprocessExecutor()

    def _run(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: int = 900,
    ) -> CommandResult:
        self.config.validate_secret_file()
        argv = [
            self.config.binary,
            "--json",
            "--repo",
            self.config.repository,
            "--password-file",
            str(self.config.password_file),
            *arguments,
        ]
        result = self.executor.run(
            argv,
            env=self.config.environment(),
            cwd=cwd,
            timeout=timeout,
        )
        if result.returncode != 0:
            raise BackupError(f"Restic operation failed with exit code {result.returncode}")
        return result

    def initialize(self) -> None:
        self._run(["init"], timeout=120)

    def backup(self, root: Path, *, host: str, service: str, checksum: str) -> str:
        _validate_name(host, "host name")
        _validate_name(service, "service name")
        if not re.fullmatch(r"[A-Fa-f0-9]{64}", checksum):
            raise BackupError("invalid manifest checksum")
        if not root.is_dir() or root.is_symlink():
            raise BackupError("backup staging directory is missing or unsafe")
        tags = (
            "guardian",
            f"guardian-host:{host}",
            f"guardian-service:{service}",
            f"guardian-manifest:{checksum}",
        )
        arguments = ["backup", ".", "--host", host]
        for tag in tags:
            arguments.extend(["--tag", tag])
        result = self._run(
            arguments,
            cwd=root,
            timeout=self.config.backup_timeout_seconds,
        )
        for line in reversed(result.stdout.splitlines()):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and isinstance(payload.get("snapshot_id"), str):
                return str(payload["snapshot_id"])
        raise BackupError("Restic did not return a snapshot ID")

    def snapshots(self) -> list[SnapshotInfo]:
        result = self._run(["snapshots"])
        try:
            payload: object = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise BackupError("Restic returned invalid snapshot metadata") from exc
        if not isinstance(payload, list):
            raise BackupError("Restic returned invalid snapshot metadata")
        snapshots: list[SnapshotInfo] = []
        for item in payload:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                continue
            raw_tags = item.get("tags", [])
            tags = tuple(str(tag) for tag in raw_tags) if isinstance(raw_tags, list) else ()
            snapshots.append(
                SnapshotInfo(
                    snapshot_id=str(item["id"]),
                    short_id=str(item.get("short_id", str(item["id"])[:8])),
                    host=str(item.get("hostname", "unknown")),
                    time=str(item.get("time", "")),
                    tags=tags,
                )
            )
        return snapshots

    def check(self, *, read_data_subset: str = "5%") -> None:
        if not re.fullmatch(r"(?:100|[1-9]\d?)%", read_data_subset):
            raise BackupError("invalid Restic check subset")
        self._run(["check", f"--read-data-subset={read_data_subset}"], timeout=3600)

    def restore(
        self,
        snapshot_id: str,
        target: Path,
        *,
        dry_run: bool = True,
        include: Sequence[str] = (),
    ) -> CommandResult:
        if not re.fullmatch(r"[A-Fa-f0-9]{6,64}|latest", snapshot_id):
            raise BackupError("invalid snapshot ID")
        _validate_restore_target(target, dry_run=dry_run)
        for path in include:
            if "\x00" in path or ".." in Path(path).parts:
                raise BackupError("invalid restore include path")
        if dry_run:
            # Restic 0.14 has no `restore --dry-run`. Snapshot enumeration is
            # read-only and complements the manifest validation in RecoveryPlanner.
            arguments = ["ls", snapshot_id]
            arguments.extend(include)
            return self._run(arguments, timeout=3600)
        arguments = ["restore", snapshot_id, "--target", str(target)]
        for path in include:
            arguments.extend(["--include", path])
        return self._run(arguments, timeout=3600)

    def dump(self, snapshot_id: str, path: str = "manifest.json") -> bytes:
        if not re.fullmatch(r"[A-Fa-f0-9]{6,64}|latest", snapshot_id):
            raise BackupError("invalid snapshot ID")
        if not path or "\x00" in path or ".." in Path(path).parts:
            raise BackupError("invalid snapshot path")
        result = self._run(["dump", snapshot_id, path])
        return result.stdout.encode("utf-8")

    @staticmethod
    def _retention_arguments(
        policy: RetentionPolicy,
        *,
        host: str,
        service: str,
    ) -> list[str]:
        _validate_name(host, "host name")
        _validate_name(service, "service name")
        return [
            "forget",
            "--dry-run",
            "--host",
            host,
            "--tag",
            f"guardian,guardian-host:{host},guardian-service:{service}",
            "--group-by",
            "host",
            "--keep-hourly",
            str(policy.keep_hourly),
            "--keep-daily",
            str(policy.keep_daily),
            "--keep-weekly",
            str(policy.keep_weekly),
            "--keep-monthly",
            str(policy.keep_monthly),
        ]

    def retention_plan(
        self,
        policy: RetentionPolicy,
        *,
        host: str,
        service: str,
    ) -> RetentionPlan:
        result = self._run(self._retention_arguments(policy, host=host, service=service))
        try:
            raw_groups: object = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise BackupError("Restic returned an invalid retention plan") from exc
        if not isinstance(raw_groups, list):
            raise BackupError("Restic returned an invalid retention plan")

        required_tags = {
            "guardian",
            f"guardian-host:{host}",
            f"guardian-service:{service}",
        }
        groups: list[dict[str, Any]] = []
        remove_snapshot_ids: list[str] = []
        for raw_group in raw_groups:
            if not isinstance(raw_group, dict):
                raise BackupError("Restic returned an invalid retention plan")
            remove = raw_group.get("remove", [])
            keep = raw_group.get("keep", [])
            if not isinstance(remove, list) or not isinstance(keep, list):
                raise BackupError("Restic returned an invalid retention plan")
            for snapshot in remove:
                if not isinstance(snapshot, dict):
                    raise BackupError("Restic returned an invalid retention plan")
                snapshot_id = snapshot.get("id")
                hostname = snapshot.get("hostname")
                tags = snapshot.get("tags")
                if (
                    not isinstance(snapshot_id, str)
                    or not re.fullmatch(r"[A-Fa-f0-9]{64}", snapshot_id)
                    or hostname != host
                    or not isinstance(tags, list)
                    or not required_tags.issubset({str(tag) for tag in tags})
                ):
                    raise BackupError("retention plan escaped the Guardian service scope")
                remove_snapshot_ids.append(snapshot_id.lower())
            groups.append(raw_group)
        if len(remove_snapshot_ids) != len(set(remove_snapshot_ids)):
            raise BackupError("Restic returned duplicate retention removals")

        digest_payload: dict[str, Any] = {
            "schema_version": 1,
            "host": host,
            "service": service,
            "policy": {
                "keep_hourly": policy.keep_hourly,
                "keep_daily": policy.keep_daily,
                "keep_weekly": policy.keep_weekly,
                "keep_monthly": policy.keep_monthly,
            },
            "groups": groups,
            "remove_snapshot_ids": sorted(remove_snapshot_ids),
        }
        return RetentionPlan(
            host=host,
            service=service,
            groups=tuple(groups),
            remove_snapshot_ids=tuple(sorted(remove_snapshot_ids)),
            digest=_canonical_digest(digest_payload),
        )

    def apply_retention(
        self,
        policy: RetentionPolicy,
        *,
        host: str,
        service: str,
        plan_digest: str,
        approval_id: str,
        confirmation: str,
    ) -> RetentionPlan:
        if not _SAFE_NAME.fullmatch(approval_id):
            raise BackupError("retention deletion requires a valid approval ID")
        if not re.fullmatch(r"[A-Fa-f0-9]{64}", plan_digest):
            raise BackupError("retention deletion requires an exact plan digest")
        plan = self.retention_plan(policy, host=host, service=service)
        expected_confirmation = f"APPLY RETENTION {plan.digest}"
        if (
            not hmac.compare_digest(plan.digest, plan_digest.lower())
            or confirmation != expected_confirmation
        ):
            raise BackupError("retention deletion requires approval of the current dry-run plan")
        if plan.remove_snapshot_ids:
            self._run(["forget", *plan.remove_snapshot_ids])
        return plan


def _validate_restore_target(target: Path, *, dry_run: bool) -> None:
    expanded = target.expanduser()
    if not expanded.is_absolute():
        raise BackupError("restore target must be an absolute path")
    current = Path(expanded.anchor)
    for part in expanded.parts[1:]:
        current /= part
        if current.is_symlink():
            raise BackupError("restore target cannot contain symbolic-link path components")
    resolved = expanded.resolve(strict=False)
    if resolved != expanded:
        raise BackupError("restore target must be a canonical path")
    if resolved == Path(resolved.anchor) or len(resolved.parts) < 2:
        raise BackupError("restore target cannot be a filesystem root")
    if dry_run:
        return
    if resolved.exists() and (not resolved.is_dir() or any(resolved.iterdir())):
        raise BackupError("restore target must be a new or empty directory")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(path: Path, root: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise BackupError("artifact escaped the staging directory") from exc
    return relative.as_posix()


def _validate_recovery_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    allowed_keys = {
        "source_commit",
        "alembic_revisions",
        "configuration_references",
        "public_certificate_references",
        "external_secret_references",
        "contains_secret_values",
    }
    if set(metadata) - allowed_keys or metadata.get("contains_secret_values", False) is not False:
        raise BackupError("invalid recovery metadata")
    source_commit = metadata.get("source_commit")
    alembic_revisions = metadata.get("alembic_revisions")
    configuration_references = metadata.get("configuration_references")
    public_certificate_references = metadata.get("public_certificate_references")
    external_secret_references = metadata.get("external_secret_references")
    if (
        not isinstance(source_commit, str)
        or not re.fullmatch(r"(?!0{40})[A-Fa-f0-9]{40}", source_commit)
        or not isinstance(alembic_revisions, list)
        or not alembic_revisions
        or not isinstance(configuration_references, list)
        or not isinstance(public_certificate_references, list)
        or not isinstance(external_secret_references, list)
        or not external_secret_references
    ):
        raise BackupError("invalid recovery metadata")
    for values, label in (
        (alembic_revisions, "Alembic revision"),
        (configuration_references, "configuration reference"),
        (public_certificate_references, "public certificate reference"),
        (external_secret_references, "external secret reference"),
    ):
        if any(
            not isinstance(value, str)
            or not value
            or len(value) > 512
            or any(unicodedata.category(character).startswith("C") for character in value)
            for value in values
        ):
            raise BackupError(f"invalid recovery metadata {label}")
    return {
        "source_commit": source_commit.lower(),
        "alembic_revisions": sorted(set(alembic_revisions)),
        "configuration_references": sorted(set(configuration_references)),
        "public_certificate_references": sorted(set(public_certificate_references)),
        "external_secret_references": sorted(set(external_secret_references)),
        "contains_secret_values": False,
    }


def build_manifest(
    root: Path,
    *,
    host: str,
    service: str,
    recovery_metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _validate_name(host, "host name")
    _validate_name(service, "service name")
    artifacts: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.name == "manifest.json" or path.is_dir():
            continue
        if path.is_symlink() or not path.is_file():
            raise BackupError("backup staging contains an unsafe file type")
        artifacts.append(
            {
                "path": _safe_relative(path, root),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    if not artifacts:
        raise BackupError("backup contains no artifacts")
    manifest = {
        "schema_version": 1,
        "host": host,
        "service": service,
        "created_at": datetime.now(UTC).isoformat(),
        "backup_engine": "restic",
        "artifacts": artifacts,
    }
    if recovery_metadata is not None:
        manifest["recovery_metadata"] = _validate_recovery_metadata(recovery_metadata)
    return manifest


def write_manifest(root: Path, manifest: Mapping[str, Any]) -> str:
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    path = root / "manifest.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_bytes((payload + "\n").encode("utf-8"))
    temporary.replace(path)
    return hashlib.sha256((payload + "\n").encode()).hexdigest()


def _parse_manifest_payload(
    payload: object,
    *,
    expected_host: str | None = None,
    expected_service: str | None = None,
) -> tuple[dict[str, Any], dict[str, tuple[int, str]]]:
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise BackupError("unsupported recovery manifest")
    host = payload.get("host")
    service = payload.get("service")
    if not isinstance(host, str) or not isinstance(service, str):
        raise BackupError("invalid recovery manifest scope")
    _validate_name(host, "recovery manifest host")
    _validate_name(service, "recovery manifest service")
    if expected_host is not None and host != expected_host:
        raise BackupError("recovery manifest host does not match the snapshot scope")
    if expected_service is not None and service != expected_service:
        raise BackupError("recovery manifest service does not match the snapshot scope")

    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise BackupError("recovery manifest contains no artifacts")
    normalized: dict[str, tuple[int, str]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise BackupError("invalid recovery manifest artifact")
        relative = artifact.get("path")
        size = artifact.get("size")
        checksum = artifact.get("sha256")
        if (
            not isinstance(relative, str)
            or not relative
            or "\\" in relative
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(checksum, str)
            or not re.fullmatch(r"[A-Fa-f0-9]{64}", checksum)
        ):
            raise BackupError("invalid recovery manifest artifact")
        posix_path = PurePosixPath(relative)
        if (
            posix_path.is_absolute()
            or posix_path.as_posix() != relative
            or any(part in {"", ".", ".."} for part in posix_path.parts)
        ):
            raise BackupError("recovery manifest path traversal detected")
        if relative == "manifest.json" or relative in normalized:
            raise BackupError("recovery manifest contains duplicate or reserved paths")
        normalized[relative] = (size, checksum.lower())
    manifest = dict(payload)
    recovery_metadata = manifest.get("recovery_metadata")
    if recovery_metadata is not None:
        if not isinstance(recovery_metadata, dict):
            raise BackupError("invalid recovery metadata")
        manifest["recovery_metadata"] = _validate_recovery_metadata(recovery_metadata)
    return manifest, normalized


def _restored_regular_files(root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        try:
            directory_metadata = directory_path.lstat()
        except OSError as exc:
            raise BackupError("restored snapshot contains an unreadable path") from exc
        if not stat.S_ISDIR(directory_metadata.st_mode) or stat.S_ISLNK(directory_metadata.st_mode):
            raise BackupError("restored snapshot contains an unsafe file type")
        for name in directory_names:
            candidate = directory_path / name
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                raise BackupError("restored snapshot contains an unreadable path") from exc
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise BackupError("restored snapshot contains an unsafe file type")
        for name in file_names:
            candidate = directory_path / name
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                raise BackupError("restored snapshot contains an unreadable path") from exc
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise BackupError("restored snapshot contains an unsafe file type")
            relative = candidate.relative_to(root).as_posix()
            files[relative] = candidate
    return files


def load_and_verify_manifest(
    root: Path,
    *,
    expected_checksum: str | None = None,
    expected_host: str | None = None,
    expected_service: str | None = None,
) -> dict[str, Any]:
    if expected_checksum is not None and not re.fullmatch(r"[A-Fa-f0-9]{64}", expected_checksum):
        raise BackupError("invalid expected manifest checksum")
    try:
        resolved_root = root.expanduser().resolve(strict=True)
    except OSError as exc:
        raise BackupError("restored snapshot directory is missing or unsafe") from exc
    if root.is_symlink() or not resolved_root.is_dir():
        raise BackupError("restored snapshot directory is missing or unsafe")
    files = _restored_regular_files(resolved_root)
    manifest_paths = [path for path in files if PurePosixPath(path).name == "manifest.json"]
    if manifest_paths != ["manifest.json"]:
        raise BackupError("restored snapshot must contain exactly one root manifest")
    manifest_path = files["manifest.json"]
    if expected_checksum and not hmac.compare_digest(
        sha256_file(manifest_path), expected_checksum.lower()
    ):
        raise BackupError("manifest checksum mismatch")
    try:
        payload: object = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupError("invalid recovery manifest") from exc
    manifest, artifacts = _parse_manifest_payload(
        payload,
        expected_host=expected_host,
        expected_service=expected_service,
    )
    expected_files = {"manifest.json", *artifacts}
    if set(files) != expected_files:
        raise BackupError("restored snapshot file set does not match the manifest")
    for relative, (expected_size, expected_artifact_checksum) in artifacts.items():
        candidate = files[relative]
        metadata = candidate.stat(follow_symlinks=False)
        if metadata.st_size != expected_size or not hmac.compare_digest(
            sha256_file(candidate), expected_artifact_checksum
        ):
            raise BackupError(f"artifact verification failed: {relative}")
    return manifest


def stage_sources(sources: Sequence[Path], destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    seen: set[str] = set()
    for source in sources:
        resolved = source.expanduser().resolve(strict=True)
        if source.is_symlink():
            raise BackupError("symbolic-link backup sources are not allowed")
        name = resolved.name
        if name in seen:
            raise BackupError("backup source names must be unique")
        seen.add(name)
        target = destination / name
        if resolved.is_dir():
            for child in resolved.rglob("*"):
                if child.is_symlink():
                    raise BackupError("symbolic links inside backup sources are not allowed")
            shutil.copytree(resolved, target, symlinks=False)
        elif resolved.is_file():
            shutil.copy2(resolved, target)
        else:
            raise BackupError("unsupported backup source")


class DatabaseBackup(Protocol):
    @property
    def name(self) -> str: ...

    def create(self, destination: Path) -> Path: ...


@dataclass(frozen=True)
class SQLiteBackup:
    source: Path
    name: str = "sqlite"

    def create(self, destination: Path) -> Path:
        source = self.source.expanduser().resolve(strict=True)
        if not source.is_file() or source.is_symlink():
            raise BackupError("SQLite source is missing or unsafe")
        output = destination / "sqlite.db"
        with closing(sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True)) as source_db:
            with closing(sqlite3.connect(output)) as backup_db:
                source_db.backup(backup_db)
                row = backup_db.execute("PRAGMA integrity_check").fetchone()
                if not row or row[0] != "ok":
                    raise BackupError("SQLite backup failed integrity validation")
        return output


@dataclass(frozen=True)
class PostgreSQLBackup:
    host: str
    port: int
    user: str
    database: str
    passfile: Path
    executor: CommandExecutor
    connection_environment: Mapping[str, str] | None = None
    binary: str = "pg_dump"
    name: str = "postgresql"

    def create(self, destination: Path) -> Path:
        for value, label in ((self.host, "database host"), (self.user, "database user")):
            if not value or "\x00" in value:
                raise BackupError(f"invalid {label}")
        _validate_name(self.database, "database name")
        if not 1 <= self.port <= 65535 or not self.passfile.is_file() or self.passfile.is_symlink():
            raise BackupError("invalid PostgreSQL backup configuration")
        output = destination / "postgresql.dump"
        environment = {key: value for key, value in os.environ.items() if key in _PASSTHROUGH_ENV}
        environment["PGPASSFILE"] = str(self.passfile)
        for key, value in (self.connection_environment or {}).items():
            if (
                key not in _POSTGRES_CONNECTION_ENV
                or not value
                or any(
                    character.isspace() or unicodedata.category(character).startswith("C")
                    for character in value
                )
            ):
                raise BackupError("invalid PostgreSQL connection security parameter")
            environment[key] = value
        result = self.executor.run(
            [
                self.binary,
                "--format=custom",
                "--no-password",
                "--host",
                self.host,
                "--port",
                str(self.port),
                "--username",
                self.user,
                "--file",
                str(output),
                self.database,
            ],
            env=environment,
            timeout=3600,
        )
        if result.returncode != 0 or not output.is_file():
            raise BackupError("PostgreSQL dump failed")
        return output


@dataclass(frozen=True)
class MySQLBackup:
    database: str
    defaults_file: Path
    executor: CommandExecutor
    binary: str = "mysqldump"
    name: str = "mysql"

    def create(self, destination: Path) -> Path:
        _validate_name(self.database, "database name")
        if not self.defaults_file.is_file() or self.defaults_file.is_symlink():
            raise BackupError("MySQL defaults file is missing or unsafe")
        output = destination / "mysql.sql"
        result = self.executor.run(
            [
                self.binary,
                f"--defaults-file={self.defaults_file}",
                "--single-transaction",
                "--quick",
                "--skip-lock-tables",
                f"--result-file={output}",
                self.database,
            ],
            env={
                **{key: value for key, value in os.environ.items() if key in _PASSTHROUGH_ENV},
                "HOME": str(self.defaults_file.parent),
            },
            timeout=3600,
        )
        if result.returncode != 0 or not output.is_file():
            raise BackupError("MySQL dump failed")
        return output


@dataclass(frozen=True)
class BackupResult:
    snapshot_id: str
    checksum: str
    manifest: dict[str, Any]
    verified: bool
    verification_completed_at: datetime | None = None


@dataclass(frozen=True)
class RecoveryVerificationAttestation:
    verifier: str
    verification_method: str
    target_environment: str
    completed_at: datetime
    evidence_digest: str
    schema_version: int = 1


@dataclass(frozen=True)
class RecoveryPointPromotion:
    recovery_point: RecoveryPoint
    promoted: bool
    attestation_digest: str


def _normalized_sha256(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Fa-f0-9]{64}", value):
        raise BackupError(f"invalid {label}")
    return value.lower()


def _canonical_attestation_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise BackupError("verification completion time must include a UTC offset")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def recovery_verification_attestation_digest(
    *,
    recovery_point_id: str,
    snapshot_id: str,
    checksum: str,
    attestation: RecoveryVerificationAttestation,
) -> str:
    """Commit a verification statement to one immutable snapshot and manifest."""
    if not _SAFE_NAME.fullmatch(recovery_point_id):
        raise BackupError("invalid recovery point ID")
    if not snapshot_id or len(snapshot_id) > 128 or "\x00" in snapshot_id:
        raise BackupError("invalid recovery snapshot ID")
    manifest_checksum = _normalized_sha256(checksum, "manifest checksum")
    if (
        attestation.schema_version != 1
        or not _SAFE_NAME.fullmatch(attestation.verifier)
        or attestation.verification_method != "isolated_restore"
        or not _SAFE_NAME.fullmatch(attestation.target_environment)
    ):
        raise BackupError("invalid recovery verification attestation")
    evidence_digest = _normalized_sha256(attestation.evidence_digest, "evidence digest")
    return _canonical_digest(
        {
            "schema": "vps-guardian/recovery-verification-attestation/v1",
            "recovery_point": {
                "id": recovery_point_id,
                "snapshot_id": snapshot_id.lower(),
                "manifest_checksum": manifest_checksum,
            },
            "verification": {
                "schema_version": 1,
                "verifier": attestation.verifier,
                "method": attestation.verification_method,
                "target_environment": attestation.target_environment,
                "completed_at": _canonical_attestation_timestamp(attestation.completed_at),
                "evidence_digest": evidence_digest,
            },
        }
    )


def promote_recovery_point(
    database: Session,
    *,
    recovery_point_id: str,
    expected_version: int,
    expected_snapshot_id: str,
    expected_checksum: str,
    attestation: RecoveryVerificationAttestation,
) -> RecoveryPointPromotion:
    """Atomically promote one pending RecoveryPoint, with replay-safe CAS semantics."""
    from guardian.models import RecoveryPoint

    if expected_version < 0:
        raise BackupError("invalid recovery point verification version")
    if not _SAFE_NAME.fullmatch(recovery_point_id):
        raise RecoveryPointNotFoundError("recovery point not found")
    snapshot_id = _normalized_sha256(expected_snapshot_id, "snapshot ID")
    checksum = _normalized_sha256(expected_checksum, "manifest checksum")
    attestation_digest = recovery_verification_attestation_digest(
        recovery_point_id=recovery_point_id,
        snapshot_id=snapshot_id,
        checksum=checksum,
        attestation=attestation,
    )
    claimed = cast(
        CursorResult[Any],
        database.execute(
            update(RecoveryPoint)
            .where(
                RecoveryPoint.id == recovery_point_id,
                RecoveryPoint.verified.is_(False),
                RecoveryPoint.verification_version == expected_version,
                func.lower(RecoveryPoint.snapshot_id) == snapshot_id,
                func.lower(RecoveryPoint.checksum) == checksum,
            )
            .values(
                verified=True,
                verified_at=attestation.completed_at.astimezone(UTC),
                verification_version=RecoveryPoint.verification_version + 1,
                attestation_digest=attestation_digest,
            )
            .execution_options(synchronize_session=False)
        ),
    )
    point = database.scalar(
        select(RecoveryPoint)
        .where(RecoveryPoint.id == recovery_point_id)
        .execution_options(populate_existing=True)
    )
    if claimed.rowcount == 1:
        if point is None:
            raise BackupError("promoted recovery point disappeared")
        return RecoveryPointPromotion(point, True, attestation_digest)
    if point is None:
        raise RecoveryPointNotFoundError("recovery point not found")
    if (
        point.verified
        and point.snapshot_id.lower() == snapshot_id
        and point.checksum.lower() == checksum
        and point.attestation_digest is not None
        and hmac.compare_digest(point.attestation_digest, attestation_digest)
    ):
        return RecoveryPointPromotion(point, False, attestation_digest)
    raise RecoveryPointPromotionConflict(attestation_digest=attestation_digest)


class BackupCoordinator:
    def __init__(self, restic: ResticAdapter) -> None:
        self.restic = restic

    def create_backup(
        self,
        *,
        host: str,
        service: str,
        sources: Sequence[Path],
        database: DatabaseBackup | None = None,
        verify: bool = True,
        validator: Callable[[Path, Mapping[str, Any]], bool] | None = None,
        recovery_metadata: Mapping[str, Any] | None = None,
        minimum_free_bytes: int = 0,
    ) -> BackupResult:
        if minimum_free_bytes < 0 or minimum_free_bytes > 10 * 1024**4:
            raise BackupError("invalid backup staging free-space requirement")
        with tempfile.TemporaryDirectory(prefix="guardian-backup-") as temporary:
            staging = Path(temporary)
            if shutil.disk_usage(staging).free < minimum_free_bytes:
                raise BackupError("backup staging filesystem has insufficient free space")
            if sources:
                stage_sources(sources, staging / "files")
            if database:
                database_dir = staging / "database"
                database_dir.mkdir()
                database.create(database_dir)
            manifest = build_manifest(
                staging,
                host=host,
                service=service,
                recovery_metadata=recovery_metadata,
            )
            checksum = write_manifest(staging, manifest)
            snapshot_id = self.restic.backup(
                staging,
                host=host,
                service=service,
                checksum=checksum,
            )
        self.restic.check()
        verified = False
        verification_completed_at: datetime | None = None
        if verify:
            verified = self.verify_snapshot(snapshot_id, checksum, validator=validator)
            if verified:
                verification_completed_at = datetime.now(UTC)
        return BackupResult(snapshot_id, checksum, manifest, verified, verification_completed_at)

    def verify_snapshot(
        self,
        snapshot_id: str,
        checksum: str,
        *,
        validator: Callable[[Path, Mapping[str, Any]], bool] | None = None,
    ) -> bool:
        with tempfile.TemporaryDirectory(prefix="guardian-restore-test-") as temporary:
            target = Path(temporary) / "restore"
            self.restic.restore(snapshot_id, target, dry_run=False)
            manifest = load_and_verify_manifest(target, expected_checksum=checksum)
            return validator(target, manifest) if validator else False


def record_recovery_point(
    database: Session,
    *,
    host_id: str,
    service: str,
    result: BackupResult,
) -> RecoveryPoint:
    """Persist a backup and CAS-promote a pending point after isolated verification."""
    from guardian.models import RecoveryPoint

    service_name = _validate_name(service, "service name")
    snapshot_id = result.snapshot_id.lower()
    checksum = result.checksum.lower()
    existing = database.scalar(
        select(RecoveryPoint).where(func.lower(RecoveryPoint.snapshot_id) == snapshot_id)
    )
    if existing:
        if (
            existing.host_id != host_id
            or existing.service_name != service_name
            or existing.checksum.lower() != checksum
            or existing.manifest != result.manifest
        ):
            if existing.checksum.lower() != checksum:
                candidate_completed_at = result.verification_completed_at or existing.created_at
                if (
                    candidate_completed_at.tzinfo is None
                    or candidate_completed_at.utcoffset() is None
                ):
                    candidate_completed_at = candidate_completed_at.replace(tzinfo=UTC)
                candidate_digest = recovery_verification_attestation_digest(
                    recovery_point_id=existing.id,
                    snapshot_id=snapshot_id,
                    checksum=checksum,
                    attestation=RecoveryVerificationAttestation(
                        verifier="guardian-backup",
                        verification_method="isolated_restore",
                        target_environment="backup-staging",
                        completed_at=candidate_completed_at,
                        evidence_digest=checksum,
                    ),
                )
                raise RecoveryPointPromotionConflict(attestation_digest=candidate_digest)
            raise BackupError("recovery point content conflicts with existing snapshot")
        if existing.verified or not result.verified:
            return existing
        completed_at = result.verification_completed_at or existing.created_at
        if completed_at.tzinfo is None or completed_at.utcoffset() is None:
            completed_at = completed_at.replace(tzinfo=UTC)
        promotion = promote_recovery_point(
            database,
            recovery_point_id=existing.id,
            expected_version=existing.verification_version,
            expected_snapshot_id=snapshot_id,
            expected_checksum=checksum,
            attestation=RecoveryVerificationAttestation(
                verifier="guardian-backup",
                verification_method="isolated_restore",
                target_environment="backup-staging",
                completed_at=completed_at,
                evidence_digest=checksum,
            ),
        )
        return promotion.recovery_point
    point_id = str(uuid.uuid4())
    verified_at = result.verification_completed_at if result.verified else None
    if verified_at is None and result.verified:
        verified_at = datetime.now(UTC)
    if verified_at is not None and (verified_at.tzinfo is None or verified_at.utcoffset() is None):
        verified_at = verified_at.replace(tzinfo=UTC)
    attestation_digest = None
    if verified_at is not None:
        attestation_digest = recovery_verification_attestation_digest(
            recovery_point_id=point_id,
            snapshot_id=snapshot_id,
            checksum=checksum,
            attestation=RecoveryVerificationAttestation(
                verifier="guardian-backup",
                verification_method="isolated_restore",
                target_environment="backup-staging",
                completed_at=verified_at,
                evidence_digest=checksum,
            ),
        )
    point = RecoveryPoint(
        id=point_id,
        host_id=host_id,
        service_name=service_name,
        snapshot_id=snapshot_id,
        manifest=result.manifest,
        checksum=checksum,
        verified=result.verified,
        verified_at=verified_at,
        verification_version=1 if result.verified else 0,
        attestation_digest=attestation_digest,
    )
    database.add(point)
    database.flush()
    return point


@dataclass(frozen=True)
class RecoveryImpact:
    snapshot_id: str
    host: str
    service: str
    manifest_checksum: str
    artifact_count: int
    total_bytes: int
    paths: tuple[str, ...]
    recovery_metadata: dict[str, Any] | None = None
    requires_approval_for_production: bool = True


@dataclass(frozen=True)
class RecoveryPlan:
    snapshot_id: str
    manifest_checksum: str
    host: str
    service: str
    scope: str
    target: str
    artifact_count: int
    total_bytes: int
    paths: tuple[str, ...]
    digest: str
    confirmation: str


class RecoveryPlanner:
    def __init__(self, restic: ResticAdapter) -> None:
        self.restic = restic

    def list_recovery_points(self) -> list[SnapshotInfo]:
        return [snapshot for snapshot in self.restic.snapshots() if "guardian" in snapshot.tags]

    def _snapshot_manifest(
        self, snapshot_id: str
    ) -> tuple[SnapshotInfo, dict[str, Any], dict[str, tuple[int, str]], str]:
        if snapshot_id == "latest" or not re.fullmatch(r"[A-Fa-f0-9]{6,64}", snapshot_id):
            raise BackupError("recovery planning requires a unique snapshot ID")
        lowered = snapshot_id.lower()
        matches = [
            snapshot
            for snapshot in self.restic.snapshots()
            if snapshot.snapshot_id.lower().startswith(lowered)
        ]
        if len(matches) != 1:
            raise BackupError("recovery snapshot ID is missing or ambiguous")
        snapshot = matches[0]
        if not re.fullmatch(r"[A-Fa-f0-9]{64}", snapshot.snapshot_id):
            raise BackupError("Restic returned a non-canonical snapshot ID")
        host_tags = [
            tag.removeprefix("guardian-host:")
            for tag in snapshot.tags
            if tag.startswith("guardian-host:")
        ]
        service_tags = [
            tag.removeprefix("guardian-service:")
            for tag in snapshot.tags
            if tag.startswith("guardian-service:")
        ]
        manifest_tags = [
            tag.removeprefix("guardian-manifest:")
            for tag in snapshot.tags
            if tag.startswith("guardian-manifest:")
        ]
        if (
            "guardian" not in snapshot.tags
            or len(host_tags) != 1
            or len(service_tags) != 1
            or len(manifest_tags) != 1
            or snapshot.host != host_tags[0]
            or not re.fullmatch(r"[A-Fa-f0-9]{64}", manifest_tags[0])
        ):
            raise BackupError("snapshot is not a scoped Guardian recovery point")
        _validate_name(host_tags[0], "snapshot host")
        _validate_name(service_tags[0], "snapshot service")
        manifest_bytes = self.restic.dump(snapshot.snapshot_id)
        manifest_checksum = hashlib.sha256(manifest_bytes).hexdigest()
        if not hmac.compare_digest(manifest_checksum, manifest_tags[0].lower()):
            raise BackupError("snapshot manifest tag does not match its contents")
        try:
            raw_manifest: object = json.loads(manifest_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BackupError("snapshot contains an invalid manifest") from exc
        manifest, artifacts = _parse_manifest_payload(
            raw_manifest,
            expected_host=host_tags[0],
            expected_service=service_tags[0],
        )
        return snapshot, manifest, artifacts, manifest_checksum

    def impact(self, snapshot_id: str) -> RecoveryImpact:
        snapshot, manifest, artifacts, manifest_checksum = self._snapshot_manifest(snapshot_id)
        return RecoveryImpact(
            snapshot_id=snapshot.snapshot_id.lower(),
            host=str(manifest["host"]),
            service=str(manifest["service"]),
            manifest_checksum=manifest_checksum,
            artifact_count=len(artifacts),
            total_bytes=sum(size for size, _ in artifacts.values()),
            paths=tuple(sorted(artifacts)),
            recovery_metadata=(
                dict(metadata)
                if isinstance((metadata := manifest.get("recovery_metadata")), dict)
                else None
            ),
        )

    def plan(self, snapshot_id: str, target: Path, *, scope: str = "service") -> RecoveryPlan:
        if scope not in {"service", "controller", "host"}:
            raise BackupError("invalid recovery scope")
        _validate_restore_target(target, dry_run=True)
        impact = self.impact(snapshot_id)
        if scope in {"controller", "host"} and impact.recovery_metadata is None:
            raise BackupError("controller and host recovery require complete recovery metadata")
        target_path = str(target.expanduser().resolve())
        digest = _canonical_digest(
            {
                "schema_version": 1,
                "snapshot_id": impact.snapshot_id,
                "manifest_checksum": impact.manifest_checksum,
                "host": impact.host,
                "service": impact.service,
                "scope": scope,
                "target": target_path,
                "artifact_count": impact.artifact_count,
                "total_bytes": impact.total_bytes,
                "paths": list(impact.paths),
            }
        )
        return RecoveryPlan(
            snapshot_id=impact.snapshot_id,
            manifest_checksum=impact.manifest_checksum,
            host=impact.host,
            service=impact.service,
            scope=scope,
            target=target_path,
            artifact_count=impact.artifact_count,
            total_bytes=impact.total_bytes,
            paths=impact.paths,
            digest=digest,
            confirmation=f"RESTORE {scope.upper()} {impact.service} {digest}",
        )

    def restore(
        self,
        snapshot_id: str,
        target: Path,
        *,
        execute: bool = False,
        approval_id: str | None = None,
        plan_digest: str | None = None,
        confirmation: str | None = None,
        scope: str = "service",
    ) -> CommandResult:
        plan = self.plan(snapshot_id, target, scope=scope)
        if not execute:
            return self.restic.restore(plan.snapshot_id, target, dry_run=True)
        if not re.fullmatch(r"[A-Fa-f0-9]{64}", snapshot_id):
            raise BackupError("executed recovery requires the full snapshot ID")
        if not approval_id or not _SAFE_NAME.fullmatch(approval_id):
            raise BackupError("executed recovery requires a valid approval ID")
        if (
            plan_digest is None
            or not re.fullmatch(r"[A-Fa-f0-9]{64}", plan_digest)
            or not hmac.compare_digest(plan.digest, plan_digest.lower())
            or confirmation != plan.confirmation
        ):
            raise BackupError(
                "execution requires approval of the current snapshot, manifest, scope, and target"
            )
        result = self.restic.restore(plan.snapshot_id, target, dry_run=False)
        load_and_verify_manifest(
            target,
            expected_checksum=plan.manifest_checksum,
            expected_host=plan.host,
            expected_service=plan.service,
        )
        return result
