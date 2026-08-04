from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
TAG = "v0.4.0-alpha.1"
VERSION = "0.4.0-alpha.1"
PYTHON_VERSION = "0.4.0a1"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_user_visible_release_versions_are_consistent() -> None:
    assert f'version = "{PYTHON_VERSION}"' in read("pyproject.toml")
    assert f'__version__ = "{PYTHON_VERSION}"' in read("controller/guardian/__init__.py")
    assert f'agentVersion = "{VERSION}"' in read("agent/version.go")
    assert json.loads(read("web/package.json"))["version"] == VERSION
    assert json.loads(read("web/package-lock.json"))["version"] == VERSION
    assert f"GUARDIAN_AGENT_INSTALL_RELEASE_VERSION={TAG}" in read(".env.example")
    assert f"VPS_GUARDIAN_RELEASE_VERSION={VERSION}" in read(".env.example")
    assert TAG in read("README.md")
    assert TAG in read("README.zh-CN.md")
    assert f"# VPS Guardian {TAG}" in read("RELEASE_NOTES_v0.4.0-alpha.1.md")
    assert f"# VPS Guardian {TAG}" in read("RELEASE_NOTES_v0.4.0-alpha.1.zh-CN.md")


def test_release_urls_and_assets_are_version_bound() -> None:
    expected_key = f"vps-guardian-release-signing-key-{TAG}.pem"
    for path in (".env.example", "docker-compose.yml", "controller/guardian/config.py"):
        document = read(path)
        assert TAG in document
        assert expected_key in document
        assert "downloads.example.com/SHA256SUMS" not in document
    builder = read("scripts/build-release.sh")
    assert f'release_version="${{VPS_GUARDIAN_RELEASE_VERSION:-{TAG}}}"' in builder
    assert "manifest_signature_asset=\"${manifest_asset}.sig\"" in builder
    assert "openssl pkeyutl -sign" in builder
    assert "openssl pkeyutl -verify" in builder
