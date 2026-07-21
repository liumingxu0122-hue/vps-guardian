#!/usr/bin/env python3
"""Persist and validate systemd backup freshness markers."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn, cast

UTC = timezone.utc  # noqa: UP017 - staging hosts support Python 3.10.
MARKER_SCHEMA = "vps-guardian-backup-marker/v1"
MARKER_NAMES = {
    "upload": "last-upload-success.json",
    "verified-recovery": "last-verified-recovery.json",
}
MAX_RESULT_BYTES = 64 * 1024
MAX_MARKER_BYTES = 8 * 1024
HEX_64 = re.compile(r"^[A-Fa-f0-9]{64}$")
SOURCE_COMMIT = re.compile(r"^(?!0{40})[A-Fa-f0-9]{40}$")
RECORDING_ERRORS = (
    None,
    "inventory_host_not_found",
    "recovery_point_persistence_failed",
)


class MarkerError(RuntimeError):
    """Backup metadata or marker state violated the runtime contract."""


def fail(message: str) -> NoReturn:
    raise MarkerError(message)


def current_identity() -> tuple[int, int]:
    uid_getter = getattr(os, "geteuid", None)
    gid_getter = getattr(os, "getegid", None)
    if not callable(uid_getter) or not callable(gid_getter):
        fail("backup marker operations require a POSIX service identity")
    return cast(int, uid_getter()), cast(int, gid_getter())


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_state_directory(path: Path) -> os.stat_result:
    if not path.is_absolute() or str(path) != os.path.normpath(path):
        fail("backup state directory must be an absolute canonical path")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise MarkerError("backup state directory cannot be resolved") from exc
    if resolved != path or not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("backup state directory must be a canonical non-symlink directory")
    uid, gid = current_identity()
    if metadata.st_uid != uid or metadata.st_gid != gid or stat.S_IMODE(metadata.st_mode) != 0o750:
        fail("backup state directory must belong to the service identity with mode 0750")
    return metadata


def read_bounded_regular_file(path: Path, *, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise MarkerError(f"{label} cannot be inspected") from exc
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        fail(f"{label} must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise MarkerError(f"{label} cannot be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != (before.st_dev, before.st_ino):
            fail(f"{label} changed while it was opened")
        if not 0 < metadata.st_size <= maximum:
            fail(f"{label} has an invalid size")
        payload = bytearray()
        while len(payload) <= maximum:
            block = os.read(descriptor, min(8192, maximum + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        if len(payload) > maximum:
            fail(f"{label} is too large")
        return bytes(payload)
    finally:
        os.close(descriptor)


def load_json_file(path: Path, *, maximum: int, label: str) -> Mapping[str, object]:
    payload = read_bounded_regular_file(path, maximum=maximum, label=label)
    try:
        value: object = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MarkerError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        fail(f"{label} must contain a JSON object")
    return cast(Mapping[str, object], value)


def validate_backup_result(value: Mapping[str, object]) -> Mapping[str, object]:
    verified = value.get("verified")
    recording_error = value.get("recording_error")
    if (
        value.get("uploaded") is not True
        or value.get("repository_checked") is not True
        or value.get("manifest_restored") is not True
        or not isinstance(verified, bool)
        or value.get("database_restore_verified") is not verified
        or value.get("verification_state") != ("verified" if verified else "pending")
        or not isinstance(value.get("recorded"), bool)
        or recording_error not in RECORDING_ERRORS
        or (value.get("recorded") is True) != (recording_error is None)
        or not isinstance(value.get("snapshot_id"), str)
        or HEX_64.fullmatch(cast(str, value.get("snapshot_id"))) is None
        or not isinstance(value.get("checksum"), str)
        or HEX_64.fullmatch(cast(str, value.get("checksum"))) is None
        or not isinstance(value.get("source_commit"), str)
        or SOURCE_COMMIT.fullmatch(cast(str, value.get("source_commit"))) is None
    ):
        fail("systemd backup did not produce valid upload metadata")
    return value


def marker_document(
    result: Mapping[str, object], *, kind: str, recorded_at: datetime
) -> dict[str, str]:
    if not isinstance(kind, str) or kind not in MARKER_NAMES:
        fail("backup marker kind is unsupported")
    if recorded_at.tzinfo != UTC:
        fail("backup marker timestamp must use UTC")
    return {
        "schema": MARKER_SCHEMA,
        "kind": kind,
        "snapshot_id": cast(str, result["snapshot_id"]),
        "checksum": cast(str, result["checksum"]),
        "source_commit": cast(str, result["source_commit"]),
        "recorded_at": recorded_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
    }


def atomic_write_marker(state_dir: Path, document: Mapping[str, str]) -> Path:
    kind = document.get("kind", "")
    try:
        marker_name = MARKER_NAMES[kind]
    except KeyError as exc:
        raise MarkerError("backup marker kind is unsupported") from exc
    validate_state_directory(state_dir)
    destination = state_dir / marker_name
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{kind}-success.", dir=state_dir)
    temporary = Path(temporary_name)
    descriptor_open = True
    try:
        mode_setter = getattr(os, "fchmod", None)
        if not callable(mode_setter):
            fail("descriptor mode enforcement is unavailable")
        cast(Callable[[int, int], None], mode_setter)(descriptor, 0o400)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor_open = False
        os.replace(temporary, destination)
        fsync_directory(state_dir)
    finally:
        if descriptor_open:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return destination


def record_result(result_path: Path, state_dir: Path, *, now: datetime | None = None) -> bool:
    result = validate_backup_result(
        load_json_file(result_path, maximum=MAX_RESULT_BYTES, label="systemd backup result")
    )
    recorded_at = now or datetime.now(UTC)
    atomic_write_marker(
        state_dir,
        marker_document(result, kind="upload", recorded_at=recorded_at),
    )
    if result["verified"] is True:
        atomic_write_marker(
            state_dir,
            marker_document(result, kind="verified-recovery", recorded_at=recorded_at),
        )
    return result.get("recording_error") is not None


def parse_recorded_at(value: object) -> datetime:
    if not isinstance(value, str):
        fail("backup freshness marker timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MarkerError("backup freshness marker timestamp is invalid") from exc
    if parsed.tzinfo != UTC:
        fail("backup freshness marker timestamp must use UTC")
    return parsed


def check_freshness(
    state_dir: Path,
    *,
    kind: str,
    maximum_age: int,
    now: datetime | None = None,
) -> tuple[int, str]:
    if not isinstance(kind, str) or kind not in MARKER_NAMES:
        fail("backup freshness marker kind is unsupported")
    if maximum_age < 3600 or maximum_age > 604800:
        fail("backup maximum age must be between one hour and seven days")
    validate_state_directory(state_dir)
    marker_path = state_dir / MARKER_NAMES[kind]
    try:
        before = marker_path.lstat()
    except OSError as exc:
        raise MarkerError(f"systemd {kind} marker cannot be inspected") from exc
    marker = load_json_file(marker_path, maximum=MAX_MARKER_BYTES, label=f"systemd {kind} marker")
    try:
        metadata = marker_path.lstat()
    except OSError as exc:
        raise MarkerError(f"systemd {kind} marker cannot be inspected") from exc
    if (metadata.st_dev, metadata.st_ino) != (before.st_dev, before.st_ino):
        fail(f"systemd {kind} marker changed while it was read")
    uid, gid = current_identity()
    recorded_at = parse_recorded_at(marker.get("recorded_at"))
    if (
        metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != 0o400
        or marker.get("schema") != MARKER_SCHEMA
        or marker.get("kind") != kind
        or not isinstance(marker.get("snapshot_id"), str)
        or HEX_64.fullmatch(cast(str, marker.get("snapshot_id"))) is None
        or not isinstance(marker.get("checksum"), str)
        or HEX_64.fullmatch(cast(str, marker.get("checksum"))) is None
        or not isinstance(marker.get("source_commit"), str)
        or SOURCE_COMMIT.fullmatch(cast(str, marker.get("source_commit"))) is None
    ):
        fail(f"systemd {kind} freshness marker is unsafe or invalid")
    current = now or datetime.now(UTC)
    if current.tzinfo != UTC:
        fail("backup freshness check timestamp must use UTC")
    age = current.timestamp() - recorded_at.timestamp()
    mtime_age = current.timestamp() - metadata.st_mtime
    if abs(age - mtime_age) > 5 or age < 0 or age > maximum_age:
        fail(f"systemd {kind} freshness marker is stale or has inconsistent time metadata")
    return int(age), cast(str, marker["snapshot_id"])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    record_parser = subparsers.add_parser("record")
    record_parser.add_argument("--result", required=True, type=Path)
    record_parser.add_argument("--state-dir", required=True, type=Path)

    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--state-dir", required=True, type=Path)
    check_parser.add_argument("--kind", choices=sorted(MARKER_NAMES), required=True)
    check_parser.add_argument("--maximum-age", required=True, type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    try:
        if options.command == "record":
            recording_failed = record_result(options.result, options.state_dir)
            return 3 if recording_failed else 0
        age, snapshot_id = check_freshness(
            options.state_dir,
            kind=options.kind,
            maximum_age=options.maximum_age,
        )
        print(
            f"systemd {options.kind} freshness PASS: age_seconds={age} "
            f"maximum={options.maximum_age} snapshot={snapshot_id[:12]}"
        )
    except (MarkerError, OSError, RuntimeError) as exc:
        print(f"systemd backup marker check failed: {exc}", file=sys.stderr)
        return 72
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
