#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import errno
import os
import stat
import sys
from pathlib import Path
from typing import NoReturn

AT_FDCWD = -100
RENAME_EXCHANGE = 2


def fail(message: str) -> NoReturn:
    raise RuntimeError(message)


def validate_directory(path: Path, *, must_exist: bool) -> None:
    if not path.is_absolute() or path.parent == path or path.name in {"", ".", ".."}:
        fail("directory switch paths must be absolute direct children")
    if not must_exist:
        if path.exists() or path.is_symlink():
            fail("directory switch destination already exists")
        return
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("directory switch source is not a regular directory")
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("directory switch source must be root-owned with mode 0700")
    if path.resolve(strict=True) != path:
        fail("directory switch source is not canonical")


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_tree(root: Path) -> None:
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in directory_names:
            child = directory_path / name
            metadata = child.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                fail("staged Secret tree contains an unsafe directory")
        for name in file_names:
            child = directory_path / name
            metadata = child.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                fail("staged Secret tree contains an unsafe file")
            descriptor = os.open(child, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        fsync_directory(directory_path)


def rename_exchange(first: Path, second: Path) -> None:
    if sys.platform != "linux":
        fail("atomic Secret refresh requires Linux renameat2")
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as exc:
        fail("atomic Secret refresh is unavailable on this libc")
        raise AssertionError from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        AT_FDCWD,
        os.fsencode(first),
        AT_FDCWD,
        os.fsencode(second),
        RENAME_EXCHANGE,
    )
    if result != 0:
        error = ctypes.get_errno()
        if error in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP, errno.EXDEV}:
            fail("atomic Secret refresh is not supported by this filesystem")
        raise OSError(error, os.strerror(error))


def install(staged: Path, runtime: Path) -> None:
    validate_directory(staged, must_exist=True)
    validate_directory(runtime, must_exist=False)
    if staged.parent != runtime.parent:
        fail("directory switch paths must share one parent")
    fsync_tree(staged)
    os.rename(staged, runtime)
    fsync_directory(runtime.parent)


def refresh(staged: Path, runtime: Path, previous: Path) -> None:
    validate_directory(staged, must_exist=True)
    validate_directory(runtime, must_exist=True)
    validate_directory(previous, must_exist=False)
    if len({staged.parent, runtime.parent, previous.parent}) != 1:
        fail("directory switch paths must share one parent")
    if staged.stat().st_dev != runtime.stat().st_dev:
        fail("atomic Secret refresh requires one filesystem")
    fsync_tree(staged)
    rename_exchange(staged, runtime)
    fsync_directory(runtime.parent)
    try:
        os.rename(staged, previous)
    except OSError:
        rename_exchange(staged, runtime)
        fsync_directory(runtime.parent)
        raise
    os.chmod(previous, 0)
    fsync_directory(runtime)
    fsync_directory(previous)
    fsync_directory(runtime.parent)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)
    install_parser = subparsers.add_parser("install")
    install_parser.add_argument("staged", type=Path)
    install_parser.add_argument("runtime", type=Path)
    refresh_parser = subparsers.add_parser("refresh")
    refresh_parser.add_argument("staged", type=Path)
    refresh_parser.add_argument("runtime", type=Path)
    refresh_parser.add_argument("previous", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.operation == "install":
            install(arguments.staged, arguments.runtime)
        else:
            refresh(arguments.staged, arguments.runtime, arguments.previous)
    except (OSError, RuntimeError) as exc:
        print(f"atomic directory switch failed: {exc}", file=sys.stderr)
        return 74
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
