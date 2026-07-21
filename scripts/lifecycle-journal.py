#!/usr/bin/env python3
"""Persist fail-closed lifecycle transaction state for VPS Guardian."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import posixpath
import re
import stat
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import NoReturn, Protocol, cast

SCHEMA_VERSION = 1
MAX_JOURNAL_BYTES = 64 * 1024
UTC = timezone.utc  # noqa: UP017 - staging hosts support Python 3.10.

OPERATIONS = frozenset(
    {
        "install",
        "upgrade",
        "rollback",
        "staging-deploy",
        "staging-rollback",
    }
)
PHASE_TRANSITIONS: dict[str, frozenset[str]] = {
    "initialized": frozenset({"prepared", "recovery_required", "aborted"}),
    "prepared": frozenset(
        {
            "quiesced",
            "database_updated",
            "units_updated",
            "recovery_required",
            "aborted",
        }
    ),
    "quiesced": frozenset(
        {"database_updated", "units_updated", "candidate_activated", "recovery_required"}
    ),
    "database_updated": frozenset({"units_updated", "candidate_activated", "recovery_required"}),
    "units_updated": frozenset({"candidate_activated", "recovery_required"}),
    "candidate_activated": frozenset({"verified", "recovery_required"}),
    "verified": frozenset({"committed", "recovery_required"}),
    "recovery_required": frozenset({"recovery_started"}),
    "recovery_started": frozenset({"previous_restored", "aborted"}),
    "committed": frozenset(),
    "previous_restored": frozenset(),
    "aborted": frozenset(),
}
TERMINAL_PHASES = frozenset({"committed", "previous_restored", "aborted"})
TIMER_STATES = frozenset({"active", "inactive", "failed", "unknown"})
CONTROLLER_STATES = frozenset({"active", "inactive", "failed", "unknown"})
DOCUMENT_FIELDS = frozenset(
    {
        "schema_version",
        "operation",
        "phase",
        "previous_release",
        "candidate_release",
        "db_revision_before",
        "db_revision_after",
        "unit_metadata_refs",
        "image_metadata_refs",
        "timer_state",
        "controller_state",
        "created_at",
        "updated_at",
    }
)
MUTABLE_FIELDS = frozenset(
    {
        "db_revision_after",
        "unit_metadata_refs",
        "image_metadata_refs",
        "timer_state",
        "controller_state",
    }
)
REVISION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+:-]{0,127}$")
TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)
JOURNAL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,126}\.json$")

JournalDocument = dict[str, object]


class JournalError(RuntimeError):
    """A lifecycle journal invariant was not satisfied."""


class FcntlModule(Protocol):
    LOCK_EX: int
    LOCK_UN: int

    def flock(self, descriptor: int, operation: int) -> None: ...


def fail(message: str) -> NoReturn:
    raise JournalError(message)


def utc_timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_timestamp(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not TIMESTAMP_PATTERN.fullmatch(value):
        fail(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise JournalError(f"{label} must be a canonical UTC timestamp") from exc
    if parsed.tzinfo != UTC:
        fail(f"{label} must use UTC")
    return parsed


def validate_posix_path(value: object, *, label: str, optional: bool) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value or value == "/":
        fail(f"{label} must be an absolute canonical path")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        fail(f"{label} contains a control character")
    if not value.startswith("/") or value.startswith("//") or posixpath.normpath(value) != value:
        fail(f"{label} must be an absolute canonical path without traversal")
    if any(component in {"", ".", ".."} for component in value.split("/")[1:]):
        fail(f"{label} must be an absolute canonical path without traversal")
    return value


def validate_revision(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not REVISION_PATTERN.fullmatch(value):
        fail(f"{label} is invalid")
    return value


def validate_reference_list(value: object, *, label: str) -> list[str]:
    if not isinstance(value, list):
        fail(f"{label} must be a JSON array")
    references: list[str] = []
    for item in cast(list[object], value):
        reference = validate_posix_path(item, label=label, optional=False)
        if reference is None:
            raise AssertionError("required metadata reference unexpectedly validated as null")
        references.append(reference)
    if len(references) != len(set(references)):
        fail(f"{label} cannot contain duplicate paths")
    return references


def validate_document(value: object) -> JournalDocument:
    if not isinstance(value, dict):
        fail("journal must contain a JSON object")
    raw = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        fail("journal field names must be strings")
    document = {cast(str, key): item for key, item in raw.items()}
    actual_fields = frozenset(document)
    if actual_fields != DOCUMENT_FIELDS:
        unknown = sorted(actual_fields - DOCUMENT_FIELDS)
        missing = sorted(DOCUMENT_FIELDS - actual_fields)
        detail = []
        if unknown:
            detail.append(f"unknown={','.join(unknown)}")
        if missing:
            detail.append(f"missing={','.join(missing)}")
        fail(f"journal fields do not match the strict schema ({'; '.join(detail)})")

    if type(document["schema_version"]) is not int or document["schema_version"] != SCHEMA_VERSION:
        fail("journal schema version is unsupported")
    operation = document["operation"]
    if not isinstance(operation, str) or operation not in OPERATIONS:
        fail("journal operation is invalid")
    phase = document["phase"]
    if not isinstance(phase, str) or phase not in PHASE_TRANSITIONS:
        fail("journal phase is invalid")

    previous_release = validate_posix_path(
        document["previous_release"], label="previous_release", optional=True
    )
    candidate_release = validate_posix_path(
        document["candidate_release"], label="candidate_release", optional=False
    )
    if operation == "install" and previous_release is not None:
        fail("install cannot declare a previous release")
    if operation in {"upgrade", "rollback", "staging-rollback"} and previous_release is None:
        fail(f"{operation} requires a previous release")
    if previous_release is not None and previous_release == candidate_release:
        fail("previous and candidate releases must differ")
    if phase == "previous_restored" and previous_release is None:
        fail("previous_restored requires a previous release")

    validate_revision(document["db_revision_before"], label="db_revision_before")
    validate_revision(document["db_revision_after"], label="db_revision_after")
    validate_reference_list(document["unit_metadata_refs"], label="unit_metadata_refs")
    validate_reference_list(document["image_metadata_refs"], label="image_metadata_refs")

    timer_state = document["timer_state"]
    if not isinstance(timer_state, str) or timer_state not in TIMER_STATES:
        fail("timer_state is invalid")
    controller_state = document["controller_state"]
    if not isinstance(controller_state, str) or controller_state not in CONTROLLER_STATES:
        fail("controller_state is invalid")

    created_at = parse_timestamp(document["created_at"], label="created_at")
    updated_at = parse_timestamp(document["updated_at"], label="updated_at")
    if updated_at < created_at:
        fail("updated_at cannot precede created_at")
    return document


def create_document(
    *,
    operation: str,
    previous_release: str | None,
    candidate_release: str,
    db_revision_before: str | None = None,
    db_revision_after: str | None = None,
    unit_metadata_refs: Sequence[str] = (),
    image_metadata_refs: Sequence[str] = (),
    timer_state: str = "unknown",
    controller_state: str = "unknown",
    timestamp: str | None = None,
) -> JournalDocument:
    now = timestamp or utc_timestamp()
    document: JournalDocument = {
        "schema_version": SCHEMA_VERSION,
        "operation": operation,
        "phase": "initialized",
        "previous_release": previous_release,
        "candidate_release": candidate_release,
        "db_revision_before": db_revision_before,
        "db_revision_after": db_revision_after,
        "unit_metadata_refs": list(unit_metadata_refs),
        "image_metadata_refs": list(image_metadata_refs),
        "timer_state": timer_state,
        "controller_state": controller_state,
        "created_at": now,
        "updated_at": now,
    }
    return validate_document(document)


def next_timestamp(previous: object, supplied: str | None) -> str:
    previous_value = parse_timestamp(previous, label="updated_at")
    candidate_text = supplied or utc_timestamp()
    candidate = parse_timestamp(candidate_text, label="updated_at")
    if candidate <= previous_value:
        candidate = previous_value + timedelta(microseconds=1)
    return candidate.isoformat(timespec="microseconds").replace("+00:00", "Z")


def update_document(
    value: object,
    *,
    phase: str,
    changes: Mapping[str, object] | None = None,
    timestamp: str | None = None,
) -> JournalDocument:
    current = validate_document(value)
    current_phase = cast(str, current["phase"])
    allowed = PHASE_TRANSITIONS[current_phase]
    if phase not in allowed:
        fail(f"illegal lifecycle phase transition: {current_phase} -> {phase}")
    supplied_changes = dict(changes or {})
    unknown = frozenset(supplied_changes) - MUTABLE_FIELDS
    if unknown:
        fail(f"update contains immutable or unknown fields: {','.join(sorted(unknown))}")
    updated = dict(current)
    updated.update(supplied_changes)
    updated["phase"] = phase
    updated["updated_at"] = next_timestamp(current["updated_at"], timestamp)
    return validate_document(updated)


def assert_can_initialize(existing: object | None) -> None:
    if existing is None:
        return
    document = validate_document(existing)
    phase = cast(str, document["phase"])
    if phase not in TERMINAL_PHASES:
        fail(f"an unfinished {document['operation']} transaction already exists at phase {phase}")
    fail("a completed lifecycle journal already exists; clear it before initializing another")


def assert_can_clear(value: object) -> JournalDocument:
    document = validate_document(value)
    if document["phase"] not in TERMINAL_PHASES:
        fail("an unfinished lifecycle transaction cannot be cleared")
    return document


def validate_secure_directory_metadata(*, mode: int, uid: int, label: str) -> None:
    if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
        fail(f"{label} must be a regular directory")
    if uid != 0 or stat.S_IMODE(mode) & 0o022:
        fail(f"{label} must be root-owned and not group/other writable")


def validate_secure_file_metadata(*, mode: int, uid: int, label: str) -> None:
    if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
        fail(f"{label} must be a regular non-symlink file")
    if uid != 0 or stat.S_IMODE(mode) != 0o600:
        fail(f"{label} must be root-owned with mode 0600")


def require_linux_root() -> None:
    if sys.platform != "linux":
        fail("lifecycle journal runtime operations require Linux")
    getter = getattr(os, "geteuid", None)
    if not callable(getter) or cast(Callable[[], int], getter)() != 0:
        fail("lifecycle journal runtime operations require root")


def validate_canonical_directory(path: Path, *, label: str) -> None:
    if not path.is_absolute() or path.parent == path:
        fail(f"{label} must be an absolute non-root path")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise JournalError(f"{label} cannot be resolved") from exc
    if resolved != path:
        fail(f"{label} must be canonical without symbolic-link components")
    validate_secure_directory_metadata(mode=metadata.st_mode, uid=metadata.st_uid, label=label)


def validate_journal_file(path: Path) -> None:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise JournalError("journal file cannot be resolved") from exc
    if resolved != path:
        fail("journal file must be canonical without symbolic-link components")
    validate_secure_file_metadata(
        mode=metadata.st_mode,
        uid=metadata.st_uid,
        label="journal file",
    )


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def set_fd_root_mode(descriptor: int, mode: int) -> None:
    mode_setter = getattr(os, "fchmod", None)
    if not callable(mode_setter):
        fail("descriptor mode enforcement is unavailable")
    cast(Callable[[int, int], None], mode_setter)(descriptor, mode)
    owner = getattr(os, "fchown", None)
    if not callable(owner):
        fail("root ownership enforcement is unavailable")
    cast(Callable[[int, int, int], None], owner)(descriptor, 0, 0)


def prepare_runtime_paths(root: Path, journal: Path, *, create_root: bool) -> None:
    require_linux_root()
    if not root.is_absolute() or root.parent == root or str(root) != os.path.normpath(root):
        fail("journal root must be an absolute canonical non-root path")
    validate_canonical_directory(root.parent, label="journal root parent")
    if root.is_symlink():
        fail("journal root cannot be a symbolic link")
    if not root.exists():
        if not create_root:
            fail("journal root does not exist")
        try:
            root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        os.chmod(root, 0o700)
        fsync_directory(root.parent)
    validate_canonical_directory(root, label="journal root")

    if not journal.is_absolute() or str(journal) != os.path.normpath(journal):
        fail("journal path must be absolute and canonical")
    if journal.parent != root or not JOURNAL_NAME_PATTERN.fullmatch(journal.name):
        fail("journal must be a direct JSON child of the journal root")
    if journal.exists() or journal.is_symlink():
        validate_journal_file(journal)


@contextmanager
def journal_lock(root: Path) -> Iterator[None]:
    lock_path = root / ".lifecycle-journal.lock"
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(lock_path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        descriptor = os.open(lock_path, flags)
    try:
        if created:
            set_fd_root_mode(descriptor, 0o600)
            os.fsync(descriptor)
            fsync_directory(root)
        metadata = os.fstat(descriptor)
        validate_secure_file_metadata(
            mode=metadata.st_mode,
            uid=metadata.st_uid,
            label="journal lock",
        )
        fcntl_module = cast(FcntlModule, importlib.import_module("fcntl"))
        fcntl_module.flock(descriptor, fcntl_module.LOCK_EX)
        try:
            yield
        finally:
            fcntl_module.flock(descriptor, fcntl_module.LOCK_UN)
    finally:
        os.close(descriptor)


def serialize_document(document: object) -> bytes:
    validated = validate_document(document)
    return (json.dumps(validated, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def read_document(path: Path) -> JournalDocument:
    validate_journal_file(path)
    before = path.lstat()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        validate_secure_file_metadata(
            mode=metadata.st_mode,
            uid=metadata.st_uid,
            label="journal file",
        )
        if (metadata.st_dev, metadata.st_ino) != (before.st_dev, before.st_ino):
            fail("journal file changed while it was being opened")
        if metadata.st_size <= 0 or metadata.st_size > MAX_JOURNAL_BYTES:
            fail("journal file has an invalid size")
        payload = bytearray()
        while len(payload) <= MAX_JOURNAL_BYTES:
            block = os.read(descriptor, min(8192, MAX_JOURNAL_BYTES + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        if len(payload) > MAX_JOURNAL_BYTES:
            fail("journal file is too large")
    finally:
        os.close(descriptor)
    try:
        decoded: object = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise JournalError("journal file is not valid UTF-8 JSON") from exc
    return validate_document(decoded)


def atomic_write_document(path: Path, document: object) -> None:
    payload = serialize_document(document)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    descriptor_open = True
    try:
        set_fd_root_mode(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor_open = False
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        if descriptor_open:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def durable_clear(path: Path) -> None:
    validate_journal_file(path)
    path.unlink()
    fsync_directory(path.parent)


def print_document(document: object) -> None:
    sys.stdout.buffer.write(serialize_document(document))


def command_init(root: Path, journal: Path, options: argparse.Namespace) -> None:
    prepare_runtime_paths(root, journal, create_root=True)
    with journal_lock(root):
        existing = read_document(journal) if journal.exists() or journal.is_symlink() else None
        assert_can_initialize(existing)
        document = create_document(
            operation=cast(str, options.operation),
            previous_release=cast(str | None, options.previous_release),
            candidate_release=cast(str, options.candidate_release),
            db_revision_before=cast(str | None, options.db_revision_before),
            db_revision_after=cast(str | None, options.db_revision_after),
            unit_metadata_refs=cast(list[str], options.unit_metadata_ref),
            image_metadata_refs=cast(list[str], options.image_metadata_ref),
            timer_state=cast(str, options.timer_state),
            controller_state=cast(str, options.controller_state),
        )
        atomic_write_document(journal, document)
    print_document(document)


def command_update(root: Path, journal: Path, options: argparse.Namespace) -> None:
    prepare_runtime_paths(root, journal, create_root=False)
    with journal_lock(root):
        current = read_document(journal)
        raw_options = vars(options)
        changes: dict[str, object] = {}
        for field in MUTABLE_FIELDS:
            option_name = field[:-1] if field.endswith("_refs") else field
            if option_name in raw_options:
                changes[field] = raw_options[option_name]
        document = update_document(
            current,
            phase=cast(str, options.phase),
            changes=changes,
        )
        atomic_write_document(journal, document)
    print_document(document)


def command_show(root: Path, journal: Path) -> None:
    prepare_runtime_paths(root, journal, create_root=False)
    with journal_lock(root):
        document = read_document(journal)
    print_document(document)


def command_clear(root: Path, journal: Path) -> None:
    prepare_runtime_paths(root, journal, create_root=False)
    with journal_lock(root):
        document = read_document(journal)
        assert_can_clear(document)
        durable_clear(journal)


def add_common_metadata_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db-revision-after")
    parser.add_argument("--unit-metadata-ref", action="append", default=[])
    parser.add_argument("--image-metadata-ref", action="append", default=[])
    parser.add_argument("--timer-state", choices=sorted(TIMER_STATES), default="unknown")
    parser.add_argument(
        "--controller-state",
        choices=sorted(CONTROLLER_STATES),
        default="unknown",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--journal", required=True, type=Path)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--operation", choices=sorted(OPERATIONS), required=True)
    init_parser.add_argument("--previous-release")
    init_parser.add_argument("--candidate-release", required=True)
    init_parser.add_argument("--db-revision-before")
    add_common_metadata_arguments(init_parser)

    update_parser = subparsers.add_parser("update")
    update_parser.add_argument("--phase", choices=sorted(PHASE_TRANSITIONS), required=True)
    update_parser.add_argument("--db-revision-after", default=argparse.SUPPRESS)
    update_parser.add_argument(
        "--unit-metadata-ref",
        action="append",
        default=argparse.SUPPRESS,
    )
    update_parser.add_argument(
        "--image-metadata-ref",
        action="append",
        default=argparse.SUPPRESS,
    )
    update_parser.add_argument(
        "--timer-state",
        choices=sorted(TIMER_STATES),
        default=argparse.SUPPRESS,
    )
    update_parser.add_argument(
        "--controller-state",
        choices=sorted(CONTROLLER_STATES),
        default=argparse.SUPPRESS,
    )

    subparsers.add_parser("show")
    subparsers.add_parser("clear")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    root = cast(Path, options.root)
    journal = cast(Path, options.journal)
    try:
        command = cast(str, options.command)
        if command == "init":
            command_init(root, journal, options)
        elif command == "update":
            command_update(root, journal, options)
        elif command == "show":
            command_show(root, journal)
        else:
            command_clear(root, journal)
    except (JournalError, OSError) as exc:
        print(f"lifecycle journal failed: {exc}", file=sys.stderr)
        return 74
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
