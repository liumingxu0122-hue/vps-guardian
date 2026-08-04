#!/usr/bin/env python3
"""Generate a checksummed Agent release manifest and CycloneDX SBOM."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
GIT_SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")
TARGET_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
SCHEMA = "vps-guardian-agent-release/v1"


class MetadataError(RuntimeError):
    pass


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_artifact(path_value: str) -> Path:
    path = Path(path_value)
    if not path.is_absolute():
        raise MetadataError("Agent artifact paths must be absolute")
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise MetadataError("Agent artifact must be a canonical regular file")
    return path


def safe_output(path_value: str) -> Path:
    path = Path(path_value)
    if not path.is_absolute():
        raise MetadataError("metadata output paths must be absolute")
    parent = path.parent.resolve(strict=True)
    if parent != path.parent or path.exists():
        raise MetadataError("metadata output must be a new file in a canonical directory")
    return path


def parse_time(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MetadataError("build time must be RFC 3339") from exc
    if parsed.utcoffset() is None:
        raise MetadataError("build time must include a UTC offset")
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--sbom-output", required=True)
    parser.add_argument("--sbom-reference", default="sbom/agent.cdx.json")
    parser.add_argument("--version", required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--build-time", required=True)
    parser.add_argument("--build-id-prefix", required=True)
    parser.add_argument("--go-version", required=True)
    parser.add_argument("--dirty", choices=("true", "false"), required=True)
    parser.add_argument(
        "--artifact",
        action="append",
        nargs=3,
        metavar=("OS", "ARCH", "PATH"),
        required=True,
    )
    return parser.parse_args()


def build_documents(arguments: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    if not arguments.version or len(arguments.version) > 64:
        raise MetadataError("Agent version is invalid")
    if not GIT_SHA_PATTERN.fullmatch(arguments.git_sha):
        raise MetadataError("Agent Git SHA must contain 40 lowercase hexadecimal characters")
    build_time = parse_time(arguments.build_time)
    dirty = arguments.dirty == "true"
    sbom_reference = arguments.sbom_reference
    if (
        not sbom_reference
        or len(sbom_reference) > 128
        or sbom_reference.startswith(("/", "."))
        or "\\" in sbom_reference
        or ".." in sbom_reference.split("/")
    ):
        raise MetadataError("Agent SBOM reference is invalid")
    artifacts: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []
    for target_os, target_arch, path_value in arguments.artifact:
        if not TARGET_PATTERN.fullmatch(target_os) or not TARGET_PATTERN.fullmatch(target_arch):
            raise MetadataError("Agent target OS/architecture is invalid")
        path = safe_artifact(path_value)
        sha256 = file_sha256(path)
        if not SHA256_PATTERN.fullmatch(sha256):
            raise MetadataError("Agent artifact SHA-256 is invalid")
        build_id = f"{arguments.build_id_prefix}-{target_os}-{target_arch}"
        artifacts.append(
            {
                "filename": path.name,
                "sha256": sha256,
                "size": path.stat().st_size,
                "os": target_os,
                "arch": target_arch,
                "git_sha": arguments.git_sha,
                "build_id": build_id,
                "sbom": sbom_reference,
            }
        )
        package_url = (
            f"pkg:generic/vps-guardian-agent@{arguments.version}"
            f"?os={target_os}&arch={target_arch}"
        )
        components.append(
            {
                "type": "application",
                "bom-ref": package_url,
                "name": "vps-guardian-agent",
                "version": arguments.version,
                "hashes": [{"alg": "SHA-256", "content": sha256}],
                "properties": [
                    {"name": "vps-guardian:git-sha", "value": arguments.git_sha},
                    {"name": "vps-guardian:build-id", "value": build_id},
                    {"name": "vps-guardian:target-os", "value": target_os},
                    {"name": "vps-guardian:target-arch", "value": target_arch},
                    {"name": "vps-guardian:dirty", "value": str(dirty).lower()},
                ],
            }
        )
    manifest = {
        "schema": SCHEMA,
        "version": arguments.version,
        "git_sha": arguments.git_sha,
        "build_time": build_time,
        "go_version": arguments.go_version,
        "dirty": dirty,
        "artifacts": artifacts,
    }
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{arguments.git_sha[:8]}-{arguments.git_sha[8:12]}-4"
        f"{arguments.git_sha[13:16]}-8{arguments.git_sha[17:20]}-{arguments.git_sha[20:32]}",
        "version": 1,
        "metadata": {
            "timestamp": build_time,
            "component": {
                "type": "application",
                "name": "vps-guardian-agent-release",
                "version": arguments.version,
            },
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "Go",
                        "version": arguments.go_version,
                    }
                ]
            },
        },
        "components": components,
    }
    return manifest, sbom


def main() -> int:
    arguments = parse_args()
    try:
        output = safe_output(arguments.output)
        sbom_output = safe_output(arguments.sbom_output)
        manifest, sbom = build_documents(arguments)
        output.write_text(
            json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        sbom_output.write_text(
            json.dumps(sbom, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except (MetadataError, OSError) as exc:
        print(str(exc))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
