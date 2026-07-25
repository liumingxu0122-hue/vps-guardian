from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_agent_release_metadata_records_artifact_hashes_and_sbom(tmp_path: Path) -> None:
    amd64 = tmp_path / "vps-guardian-agent-linux-amd64"
    arm64 = tmp_path / "vps-guardian-agent-linux-arm64"
    amd64.write_bytes(b"amd64-agent")
    arm64.write_bytes(b"arm64-agent")
    output = tmp_path / "agent-release-manifest.json"
    sbom = tmp_path / "agent.cdx.json"
    result = subprocess.run(  # noqa: S603 - fixed interpreter and repository script.
        [
            sys.executable,
            "scripts/agent-release-metadata.py",
            "--output",
            str(output.resolve()),
            "--sbom-output",
            str(sbom.resolve()),
            "--version",
            "0.4.0-phase4-rc2",
            "--git-sha",
            "a" * 40,
            "--build-time",
            "2026-07-25T00:00:00Z",
            "--build-id-prefix",
            "0.4.0-phase4-rc2+aaaaaaaaaaaa",
            "--go-version",
            "go1.24.0",
            "--dirty",
            "false",
            "--artifact",
            "linux",
            "amd64",
            str(amd64.resolve()),
            "--artifact",
            "linux",
            "arm64",
            str(arm64.resolve()),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert manifest["schema"] == "vps-guardian-agent-release/v1"
    assert manifest["git_sha"] == "a" * 40
    assert manifest["dirty"] is False
    assert [item["arch"] for item in manifest["artifacts"]] == ["amd64", "arm64"]
    assert all(len(item["sha256"]) == 64 for item in manifest["artifacts"])
    assert all(item["sbom"] == "sbom/agent.cdx.json" for item in manifest["artifacts"])
    document = json.loads(sbom.read_text(encoding="utf-8"))
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    assert len(document["components"]) == 2
