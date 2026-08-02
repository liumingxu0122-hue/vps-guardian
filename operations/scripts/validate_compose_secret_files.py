#!/usr/bin/env python3
"""Fail closed unless rendered Compose secret files stay inside an approved root."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


class SecretPathError(ValueError):
    """A rendered Compose secret path is unsafe or unusable."""


def _parse_config(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SecretPathError("Compose config output is not valid JSON") from exc
    if not isinstance(value, dict):
        raise SecretPathError("Compose config must be a JSON object")
    return value


def validate_secret_files(
    config: dict[str, Any], approved_root: Path, relative_to: Path
) -> list[tuple[str, Path, int, int]]:
    root = approved_root.resolve(strict=True)
    if not root.is_dir():
        raise SecretPathError("approved secret root is not a directory")

    secrets = config.get("secrets")
    if not isinstance(secrets, dict) or not secrets:
        raise SecretPathError("rendered Compose config has no secrets")

    validated: list[tuple[str, Path, int, int]] = []
    for name, definition in sorted(secrets.items()):
        if not isinstance(name, str) or not isinstance(definition, dict):
            raise SecretPathError("invalid rendered secret definition")
        raw_path = definition.get("file")
        if not isinstance(raw_path, str) or not raw_path:
            raise SecretPathError(f"secret {name!r} has no file path")

        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = relative_to / candidate
        path = candidate.resolve(strict=True)
        lowered_parts = [part.casefold() for part in path.parts]
        if any(
            left == "runtime" and right == "runtime"
            for left, right in zip(lowered_parts, lowered_parts[1:], strict=False)
        ):
            raise SecretPathError(f"secret {name!r} contains repeated runtime path components")
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise SecretPathError(f"secret {name!r} escapes the approved root") from exc

        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise SecretPathError(f"secret {name!r} is not a regular file")
        mode = stat.S_IMODE(info.st_mode)
        if info.st_uid != 0:
            raise SecretPathError(f"secret {name!r} is not owned by root")
        if mode not in {0o400, 0o600}:
            raise SecretPathError(f"secret {name!r} mode must be 0400 or 0600")
        validated.append((name, path, info.st_uid, mode))
    return validated


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--approved-root", required=True, type=Path)
    parser.add_argument("--relative-to", type=Path, default=Path.cwd())
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--config-file", type=Path)
    source.add_argument("--compose-command", nargs=argparse.REMAINDER)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    try:
        if args.config_file is not None:
            raw = args.config_file.read_text(encoding="utf-8")
        else:
            command = args.compose_command
            if not command:
                raise SecretPathError("missing Compose config command")
            result = subprocess.run(  # noqa: S603 - caller supplies an explicit argv vector
                command,
                check=False,
                capture_output=True,
                text=True,
                env=os.environ.copy(),
            )
            if result.returncode != 0:
                raise SecretPathError("Compose config command failed")
            raw = result.stdout
        config = _parse_config(raw)
        validated = validate_secret_files(config, args.approved_root, args.relative_to)
    except (OSError, SecretPathError) as exc:
        print(f"compose secret validation failed: {exc}", file=sys.stderr)
        return 1

    for name, path, uid, mode in validated:
        print(f"{name}|{path}|uid={uid}|mode={mode:04o}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
