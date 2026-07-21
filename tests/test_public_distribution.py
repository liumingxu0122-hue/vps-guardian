from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]


def test_public_release_files_exist() -> None:
    required = {
        "README.md",
        "README.zh-CN.md",
        "LICENSE",
        "CHANGELOG.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "THIRD_PARTY_NOTICES.md",
        "docs/ARCHITECTURE.md",
        "docs/QUICKSTART.md",
        "docs/AGENT_INSTALLATION.md",
        "docs/BACKUP_AND_RESTORE.md",
        ".env.example",
    }
    assert not [name for name in sorted(required) if not (ROOT / name).is_file()]


def test_public_tree_excludes_internal_acceptance_material() -> None:
    assert not (ROOT / "scripts/staging").exists()
    assert not list((ROOT / "deploy/staging-fixtures").glob("**/*"))
    assert not list((ROOT / "tests").glob("test_staging_*.py"))
    assert not list(ROOT.glob("*.bundle"))
    assert not (ROOT / "artifacts/staging").exists()


def test_env_example_contains_only_placeholders() -> None:
    content = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "example.com" in content
    assert not re.search(r"(?m)^\s*(?:PASSWORD|TOKEN|SECRET|ACCESS_KEY)\s*=\s*\S+", content)
    addresses = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
    assert set(addresses) <= {".".join(["0", "0", "0", "0"])}


def test_compose_references_existing_local_files() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    for service in compose["services"].values():
        build = service.get("build")
        if build:
            assert (ROOT / build["dockerfile"]).is_file()
        for volume in service.get("volumes", []):
            source = str(volume).split(":", 1)[0]
            if source.startswith("./") and "${" not in source:
                assert (ROOT / source).exists()


def test_admin_bootstrap_never_accepts_password_as_plain_option() -> None:
    bootstrap = (ROOT / "controller/guardian/bootstrap.py").read_text(encoding="utf-8")
    assert "hide_input=True" in bootstrap
    assert "confirmation_prompt=True" in bootstrap
    assert "--password-file" in bootstrap
    assert "password file must be an absolute regular file" in bootstrap


def test_windows_launcher_is_parameterized_and_experimental() -> None:
    path = ROOT / "scripts/windows/Open-VpsGuardianDashboard.ps1"
    content = path.read_text(encoding="utf-8")
    assert "Experimental" in content
    assert "[Parameter(Mandatory)] [string]$SshTarget" in content
    assert "[Parameter(Mandatory)] [string]$IdentityFile" in content
    assert "[Parameter(Mandatory)] [string]$DashboardDomain" in content
    assert "IdentitiesOnly=yes" in content
    assert "--host-resolver-rules=MAP" in content
    assert "SSH tunnel was not ready" in content
    assert "hosts" not in content.lower()
