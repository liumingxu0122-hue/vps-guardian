from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "scripts" / "release-manifest.py"


def run_manifest(action: str, release: Path, manifest: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter and repository script
        [sys.executable, str(TOOL), action, str(release), str(manifest)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_release_manifest_detects_content_metadata_and_file_set_changes(tmp_path: Path) -> None:
    release = tmp_path / "release"
    directory = release / "bin"
    directory.mkdir(parents=True)
    executable = directory / "guardian"
    executable.write_bytes(b"release-payload\n")
    executable.chmod(0o550)
    manifest = tmp_path / "RELEASE.MANIFEST.json"
    manifest.touch()

    written = run_manifest("write", release, manifest)
    assert written.returncode == 0, written.stderr
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["schema"] == "vps-guardian-release-manifest/v1"
    assert payload["release_root"] == str(release)
    assert run_manifest("verify", release, manifest).returncode == 0

    executable.chmod(0o750)
    executable.write_bytes(b"tampered\n")
    executable.chmod(0o550)
    assert run_manifest("verify", release, manifest).returncode == 1
    executable.chmod(0o750)
    executable.write_bytes(b"release-payload\n")
    executable.chmod(0o550)

    extra = release / "unlisted"
    extra.write_text("unexpected", encoding="utf-8")
    assert run_manifest("verify", release, manifest).returncode == 1
    extra.unlink()

    executable.chmod(0o750)
    assert run_manifest("verify", release, manifest).returncode == 1


def test_release_manifest_rejects_in_tree_manifest_and_symlinks(tmp_path: Path) -> None:
    release = tmp_path / "release"
    release.mkdir()
    (release / "payload").write_text("ok", encoding="utf-8")
    in_tree_manifest = release / "manifest.json"
    in_tree_manifest.touch()
    rejected = run_manifest("write", release, in_tree_manifest)
    assert rejected.returncode == 1
    assert "outside the release tree" in rejected.stderr

    link = release / "link"
    try:
        os.symlink(release / "payload", link)
    except OSError:
        return
    manifest = tmp_path / "manifest.json"
    manifest.touch()
    rejected = run_manifest("write", release, manifest)
    assert rejected.returncode == 1
    assert "symbolic link" in rejected.stderr
