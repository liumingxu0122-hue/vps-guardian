from __future__ import annotations

import re
import shlex
from urllib.parse import urljoin

from guardian.config import Settings


class AgentInstallationConfigurationError(ValueError):
    pass


def _sha256(value: str, label: str) -> str:
    if not re.fullmatch(r"[a-f0-9]{64}", value):
        raise AgentInstallationConfigurationError(f"{label} SHA-256 is not configured")
    return value


def build_one_command_install(
    *,
    settings: Settings,
    host_id: str,
    enrollment_token: str,
    os_family: str,
) -> str:
    if not settings.one_command_install_enabled:
        raise AgentInstallationConfigurationError(
            "one-command Agent installation is not enabled"
        )
    version = settings.agent_install_release_version
    base = settings.agent_install_assets_base_url.rstrip("/") + "/"
    release_base = urljoin(base, f"{version}/")
    installer_url = urljoin(release_base, "install-agent.sh")
    agent_amd64_url = urljoin(release_base, "vps-guardian-agent-linux-amd64")
    agent_arm64_url = urljoin(release_base, "vps-guardian-agent-linux-arm64")
    values = {
        "installer_sha": _sha256(
            settings.agent_installer_sha256, "installer"
        ),
        "agent_amd64_sha": _sha256(
            settings.agent_binary_amd64_sha256, "amd64 Agent"
        ),
        "agent_arm64_sha": _sha256(
            settings.agent_binary_arm64_sha256, "arm64 Agent"
        ),
        "controller_ca_sha": _sha256(
            settings.agent_controller_ca_sha256, "Controller CA"
        ),
        "controller_key_sha": _sha256(
            settings.agent_controller_public_key_sha256,
            "Controller public key",
        ),
    }
    quoted = {key: shlex.quote(value) for key, value in values.items()}
    q = shlex.quote
    return " ".join(
        (
            "umask 077;",
            'guardian_tmp="$(mktemp -d)"',
            "&&",
            "trap",
            q('rm -rf -- "$guardian_tmp"'),
            "EXIT HUP INT TERM",
            "&&",
            "printf",
            q("%s"),
            q(enrollment_token),
            '>"$guardian_tmp/enrollment-token"',
            "&&",
            "curl --fail --show-error --location --proto '=https'",
            "--connect-timeout 10 --max-time 120",
            "-o",
            '"$guardian_tmp/install-agent.sh"',
            q(installer_url),
            "&&",
            "printf",
            q("%s  %s\\n"),
            quoted["installer_sha"],
            '"$guardian_tmp/install-agent.sh"',
            "|",
            "sha256sum --check --status",
            "&&",
            "sudo sh",
            '"$guardian_tmp/install-agent.sh"',
            "--controller-url",
            q(settings.agent_gateway_url),
            "--host-id",
            q(host_id),
            "--enrollment-token-file",
            '"$guardian_tmp/enrollment-token"',
            "--release-version",
            q(version),
            "--os-family",
            q(os_family),
            "--agent-url-amd64",
            q(agent_amd64_url),
            "--agent-sha256-amd64",
            quoted["agent_amd64_sha"],
            "--agent-url-arm64",
            q(agent_arm64_url),
            "--agent-sha256-arm64",
            quoted["agent_arm64_sha"],
            "--server-ca-url",
            q(settings.agent_controller_ca_url),
            "--server-ca-sha256",
            quoted["controller_ca_sha"],
            "--controller-public-key-url",
            q(settings.agent_controller_public_key_url),
            "--controller-public-key-sha256",
            quoted["controller_key_sha"],
        )
    )
