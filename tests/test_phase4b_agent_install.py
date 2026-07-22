import subprocess
from pathlib import Path


def test_agent_installer_verifies_artifact_runs_nonroot_and_rolls_back() -> None:
    installer = Path("scripts/install-agent.sh").read_text(encoding="utf-8")
    unit = Path("deploy/systemd/vps-guardian-agent.service").read_text(encoding="utf-8")
    assert "sha256sum --check --status" in installer
    assert "rollback_install()" in installer
    assert "trap rollback_install EXIT" in installer
    assert "Agent installation failed; previous installation was restored" in installer
    assert "useradd --system" in installer
    assert "User=vps-guardian-agent" in unit
    assert "NoNewPrivileges=yes" in unit
    assert (
        "ReadWritePaths=/var/lib/vps-guardian-agent "
        "/etc/vps-guardian-agent/identities" in unit
    )
    assert "SupplementaryGroups=docker" not in unit
    assert "curl |" not in installer
    assert installer.index("systemctl stop vps-guardian-agent.service") < installer.index(
        'install -m 0755 "$binary" /usr/local/sbin/vps-guardian-agent'
    )


def test_agent_uninstall_preserves_state_and_controller_history_by_default() -> None:
    uninstaller = Path("scripts/uninstall-agent.sh").read_text(encoding="utf-8")
    assert "--purge-local-state" in uninstaller
    assert "Local queue and state were preserved" in uninstaller
    assert "Controller-side host history and audit records were not modified" in uninstaller
    assert "SHA256SUMS" in uninstaller
    assert "rm -rf /var/lib/vps-guardian-agent" in uninstaller
    purge_guard = uninstaller.index('if [ "$purge_state" = true ]')
    assert purge_guard < uninstaller.index("rm -rf /var/lib/vps-guardian-agent")


def test_generated_command_uses_token_file_and_complete_installer_contract() -> None:
    api = Path("controller/guardian/api.py").read_text(encoding="utf-8")
    installer = Path("scripts/install-agent.sh").read_text(encoding="utf-8")
    for option in (
        "--binary",
        "--sha256",
        "--controller-url",
        "--host-id",
        "--server-ca",
        "--controller-public-key",
        "--enrollment-token-file",
    ):
        assert option in api
        assert option in installer
    generated_command = api.split("command = (", 1)[1].split(
        "return EnrollmentTokenView", 1
    )[0]
    for forbidden in ("--private-key", "--certificate", "--signing-key"):
        assert forbidden not in generated_command


def test_runtime_entrypoints_are_executable_in_git() -> None:
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "--stage",
            "deploy/agent-gateway-entrypoint.sh",
            "scripts/install-agent.sh",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    modes = {line.split(maxsplit=1)[0] for line in result.stdout.splitlines()}
    assert modes == {"100755"}
