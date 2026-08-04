import shutil
import subprocess
from pathlib import Path


def test_agent_installer_verifies_artifact_runs_nonroot_and_rolls_back() -> None:
    installer = Path("scripts/install-agent.sh").read_text(encoding="utf-8")
    assert "sha256sum --check --status" in installer
    assert "rollback()" in installer
    assert "trap rollback EXIT" in installer
    assert "prior VPS Guardian files and service state were restored" in installer
    assert "useradd --system" in installer
    assert "User=vps-guardian-agent" in installer
    assert "NoNewPrivileges=true" in installer
    assert "CapabilityBoundingSet=" in installer
    assert "systemd-detect-virt --quiet --container" in installer
    assert 'systemd_privileged_hardening=""' in installer
    assert "Rootless/container guests commonly lack CAP_SYS_ADMIN" in installer
    assert "install seccomp filters after switching to User=" in installer
    assert "SupplementaryGroups=docker" not in installer
    assert "curl |" not in installer and "curl|" not in installer
    assert "rm -rf /etc/vps-guardian\n" not in installer
    assert "rm -rf /etc/vps-guardian/agent" in installer
    assert installer.index("systemctl stop vps-guardian-agent.service") < installer.index(
        'install -o root -g root -m 0755 "$work_directory/agent"'
    )
    for distribution in ("ubuntu", "debian", "rocky", "almalinux", "rhel", "fedora", "alpine"):
        assert distribution in installer
    for forbidden in (
        "apt upgrade",
        "apt-get upgrade",
        "dnf upgrade",
        "yum update",
        "iptables",
        "firewall-cmd",
        "setenforce",
        "systemctl restart ssh",
        "systemctl restart komari",
    ):
        assert forbidden not in installer


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
    command_builder = Path("controller/guardian/agent_installation.py").read_text(
        encoding="utf-8"
    )
    installer = Path("scripts/install-agent.sh").read_text(encoding="utf-8")
    for option in (
        "--controller-url",
        "--host-id",
        "--enrollment-token-file",
        "--release-version",
        "--os-family",
        "--agent-url-amd64",
        "--agent-sha256-amd64",
        "--agent-url-arm64",
        "--agent-sha256-arm64",
        "--enrollment-https-ca-bundle-sha256",
        "--controller-public-key-url",
        "--controller-public-key-sha256",
        "--release-manifest-url",
        "--release-manifest-signature-url",
        "--release-signing-public-key-url",
        "--release-signing-public-key-sha256",
    ):
        assert option in command_builder
        assert option in installer
    for forbidden in ("--private-key", "--certificate", "--signing-key"):
        assert forbidden not in command_builder
    assert "latest" not in command_builder
    assert 'curl --config' in command_builder


def test_installer_refuses_redirects_when_sending_short_lived_credentials() -> None:
    installer = Path("scripts/install-agent.sh").read_text(encoding="utf-8")
    credential_request_blocks = [
        block for block in installer.split("\n\n") if '-H "@$header_file"' in block
    ]
    assert credential_request_blocks
    assert all("--location" not in block for block in credential_request_blocks)
    assert all("enrollment_https_curl" in block for block in credential_request_blocks)
    assert '--cacert "$work_directory/enrollment-https-ca-bundle.pem"' not in installer


def test_installer_keeps_https_and_mtls_ca_material_isolated_and_ephemeral() -> None:
    installer = Path("scripts/install-agent.sh").read_text(encoding="utf-8")
    assert 'chmod 0600 "$work_directory/enrollment-https-ca-bundle.pem"' in installer
    assert 'rm -rf -- "$work_directory"' in installer
    assert "trap rollback EXIT" in installer
    assert "trap 'exit 129' HUP" in installer
    assert "trap 'exit 130' INT" in installer
    assert "trap 'exit 143' TERM" in installer
    assert "/trust/enrollment-https-ca-bundle.pem" in installer
    assert "/trust/agent-mtls-ca-bundle.pem" in installer
    assert "controller-ca.crt" not in installer
    assert "curl -k" not in installer
    assert "--insecure" not in installer


def test_generated_secrets_use_a_distinct_enrollment_https_ca() -> None:
    generator = Path("scripts/generate-controller-secrets.sh").read_text(
        encoding="utf-8"
    )
    assert "enrollment-https-ca-bundle.pem" in generator
    assert "VPS Guardian Enrollment HTTPS CA" in generator
    assert '-CA "$target/enrollment-https-pki/enrollment-https-ca-bundle.pem"' in generator
    assert '-CA "$target/pki/agent-ca.crt"' not in generator
    assert "extendedKeyUsage=serverAuth" in generator


def test_gateway_allows_only_bounded_unauthenticated_enrollment_paths() -> None:
    gateway = Path("deploy/agent-gateway.haproxy.cfg").read_text(encoding="utf-8")
    assert "path -m str /api/v1/agents/bootstrap" in gateway
    assert "path -m str /api/v1/agents/enrollment-progress" in gateway
    assert (
        "deny deny_status 403 if !client_certificate_present "
        "!bootstrap_path !enrollment_progress_path"
    ) in gateway
    assert "set-header X-Guardian-Proxy-Auth" in gateway
    assert "set-header X-Forwarded-For %[src]" in gateway


def test_runtime_entrypoints_are_executable_in_git() -> None:
    git = shutil.which("git")
    assert git is not None
    result = subprocess.run(  # noqa: S603 - executable is resolved to an absolute path.
        [
            git,
            "ls-files",
            "--stage",
            "deploy/agent-gateway-entrypoint.sh",
            "scripts/install-agent.sh",
            "scripts/maintain-agent.sh",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    modes = {line.split(maxsplit=1)[0] for line in result.stdout.splitlines()}
    assert modes == {"100755"}
