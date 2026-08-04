#!/usr/bin/env python3
"""Atomically materialize one canonical Secret for one fixed non-root service UID."""

from __future__ import annotations

import argparse
import os
import signal
import stat
import sys
import tempfile
from pathlib import Path
from types import FrameType
from typing import NoReturn


class MaterializationError(RuntimeError):
    """The canonical source or runtime destination violates the security contract."""


def fail(message: str) -> NoReturn:
    raise MaterializationError(message)


def _inside(path: Path, root: Path, label: str) -> None:
    try:
        path.relative_to(root)
    except ValueError:
        fail(f"{label} escapes its approved root")


def _regular_nonsymlink(path: Path, label: str) -> os.stat_result:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} must be a regular non-symlink file")
    if metadata.st_nlink != 1:
        fail(f"{label} must not have multiple hard links")
    return metadata


def _approved_root(path: Path, label: str, mode: int) -> Path:
    resolved = path.resolve(strict=True)
    metadata = path.lstat()
    if resolved != path or stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} must be a canonical non-symlink directory")
    if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != mode:
        fail(f"{label} must be root:root with mode {mode:04o}")
    return resolved


def validate_source(source: Path, canonical_root: Path, maximum_bytes: int) -> os.stat_result:
    root = _approved_root(canonical_root, "canonical root", 0o700)
    resolved = source.resolve(strict=True)
    if resolved != source:
        fail("canonical Secret path must not contain symlinks")
    _inside(resolved, root, "canonical Secret")
    metadata = _regular_nonsymlink(source, "canonical Secret")
    if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
        fail("canonical Secret must be root:root with mode 0600")
    if metadata.st_size < 1 or metadata.st_size > maximum_bytes:
        fail("canonical Secret size is outside its approved bounds")
    return metadata


def validate_destination(
    target: Path, runtime_root: Path, target_uid: int, target_gid: int
) -> Path:
    root = _approved_root(runtime_root, "runtime root", 0o711)
    parent = target.parent.resolve(strict=True)
    if parent != target.parent:
        fail("runtime service directory must not contain symlinks")
    _inside(parent, root, "runtime service directory")
    metadata = target.parent.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        fail("runtime service directory must be a non-symlink directory")
    if (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) != (
        target_uid,
        target_gid,
        0o500,
    ):
        fail("runtime service directory owner or mode does not match its service")
    if target.exists() or target.is_symlink():
        existing = _regular_nonsymlink(target, "runtime Secret")
        if (existing.st_uid, existing.st_gid, stat.S_IMODE(existing.st_mode)) != (
            target_uid,
            target_gid,
            0o400,
        ):
            fail("existing runtime Secret owner or mode does not match its service")
    return root


def _interrupted(signum: int, _frame: FrameType | None) -> NoReturn:
    raise InterruptedError(f"interrupted by signal {signum}")


def materialize(
    source: Path,
    target: Path,
    canonical_root: Path,
    runtime_root: Path,
    target_uid: int,
    target_gid: int,
    maximum_bytes: int,
) -> None:
    source_metadata = validate_source(source, canonical_root, maximum_bytes)
    validate_destination(target, runtime_root, target_uid, target_gid)
    old_umask = os.umask(0o077)
    temporary: Path | None = None
    source_fd = -1
    target_fd = -1
    previous_handlers: dict[int, signal.Handlers] = {}
    try:
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.signal(signum, _interrupted)
        source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(source_fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            source_metadata.st_dev,
            source_metadata.st_ino,
            source_metadata.st_size,
        ):
            fail("canonical Secret changed while it was opened")
        target_fd, raw_temporary = tempfile.mkstemp(
            prefix=f".{target.name}.new.", dir=target.parent
        )
        temporary = Path(raw_temporary)
        while True:
            chunk = os.read(source_fd, 65536)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(target_fd, view)
                view = view[written:]
        os.fchown(target_fd, target_uid, target_gid)
        os.fchmod(target_fd, 0o400)
        os.fsync(target_fd)
        os.close(target_fd)
        target_fd = -1
        os.replace(temporary, target)
        temporary = None
        directory_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if target_fd >= 0:
            os.close(target_fd)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        os.umask(old_umask)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--canonical-root", required=True, type=Path)
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--gid", required=True, type=int)
    parser.add_argument("--maximum-bytes", type=int, default=32768)
    arguments = parser.parse_args()
    try:
        materialize(
            arguments.source,
            arguments.target,
            arguments.canonical_root,
            arguments.runtime_root,
            arguments.uid,
            arguments.gid,
            arguments.maximum_bytes,
        )
        metadata = arguments.target.stat()
    except (MaterializationError, OSError, InterruptedError) as exc:
        print(f"runtime Secret materialization failed: {exc}", file=sys.stderr)
        return 74
    print(
        f"{arguments.target.name}|uid={metadata.st_uid}|gid={metadata.st_gid}|"
        f"mode={stat.S_IMODE(metadata.st_mode):04o}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
