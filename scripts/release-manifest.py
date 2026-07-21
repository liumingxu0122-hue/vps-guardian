#!/usr/bin/env python3
"""Create or verify an exact, non-symlink release-tree manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

SCHEMA = "vps-guardian-release-manifest/v1"


class ManifestError(RuntimeError):
    pass


def canonical_root(value: str) -> Path:
    supplied = Path(value)
    if not supplied.is_absolute():
        raise ManifestError("release root must be an absolute path")
    try:
        if stat.S_ISLNK(supplied.lstat().st_mode):
            raise ManifestError("release root cannot be a symbolic link")
        root = supplied.resolve(strict=True)
    except OSError as exc:
        raise ManifestError("release root cannot be resolved") from exc
    if not root.is_dir():
        raise ManifestError("release root must be a directory")
    if root != supplied:
        raise ManifestError("release root cannot contain symbolic-link path components")
    return root


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def entry_for(path: Path, relative: str) -> dict[str, Any]:
    metadata = path.lstat()
    common: dict[str, Any] = {
        "path": relative,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }
    if stat.S_ISDIR(metadata.st_mode):
        return {**common, "type": "directory"}
    if stat.S_ISREG(metadata.st_mode):
        return {
            **common,
            "type": "file",
            "size": metadata.st_size,
            "sha256": hash_file(path),
        }
    if stat.S_ISLNK(metadata.st_mode):
        raise ManifestError(f"release contains a symbolic link: {relative}")
    raise ManifestError(f"release contains an unsupported file type: {relative}")


def collect_entries(root: Path) -> list[dict[str, Any]]:
    entries = [entry_for(root, ".")]

    def walk(directory: Path) -> None:
        try:
            children = sorted(os.scandir(directory), key=lambda item: os.fsencode(item.name))
        except OSError as exc:
            raise ManifestError(f"cannot scan release directory: {directory}") from exc
        for child in children:
            child_path = Path(child.path)
            relative = child_path.relative_to(root).as_posix()
            item = entry_for(child_path, relative)
            entries.append(item)
            if item["type"] == "directory":
                walk(child_path)

    walk(root)
    return entries


def build_manifest(root: Path) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "release_root": str(root),
        "entries": collect_entries(root),
    }


def manifest_path(value: str, root: Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ManifestError("manifest path must be absolute")
    try:
        resolved_parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise ManifestError("manifest parent cannot be resolved") from exc
    resolved = resolved_parent / path.name
    if resolved != path:
        raise ManifestError("manifest path cannot contain symbolic-link path components")
    if resolved == root or root in resolved.parents:
        raise ManifestError("manifest must be stored outside the release tree")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ManifestError("manifest must already be a regular file") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ManifestError("manifest must be a regular file")
    return path


def write_manifest(root: Path, destination: Path) -> None:
    payload = build_manifest(root)
    with destination.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        handle.write("\n")


def load_manifest(source: Path) -> dict[str, Any]:
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError("release manifest is unreadable or invalid") from exc
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise ManifestError("release manifest schema is invalid")
    if not isinstance(payload.get("release_root"), str) or not isinstance(
        payload.get("entries"), list
    ):
        raise ManifestError("release manifest structure is invalid")
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("write", "verify"))
    parser.add_argument("release_root")
    parser.add_argument("manifest")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        root = canonical_root(args.release_root)
        path = manifest_path(args.manifest, root)
        if args.action == "write":
            write_manifest(root, path)
        else:
            expected = load_manifest(path)
            actual = build_manifest(root)
            if expected != actual:
                raise ManifestError("release tree does not exactly match its manifest")
    except ManifestError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
