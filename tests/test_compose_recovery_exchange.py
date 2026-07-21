from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_recovery_exchange_is_initialized_before_controller_start() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    initializer = services["recovery-volume-init"]

    assert initializer["image"] == (
        "${VPS_GUARDIAN_CONTROLLER_IMAGE:-vps-guardian-controller:local}"
    )
    assert initializer["pull_policy"] == "never"
    assert initializer["user"] == "0:0"
    assert initializer["network_mode"] == "none"
    assert initializer["read_only"] is True
    assert initializer["volumes"] == ["recovery_exchange:/exchange"]
    assert initializer["cap_drop"] == ["ALL"]
    assert set(initializer["cap_add"]) == {"CHOWN", "DAC_OVERRIDE", "FOWNER"}
    assert initializer["security_opt"] == ["no-new-privileges:true"]

    command = initializer["command"][0]
    assert "0:0:755|10002:10001:750" in command
    assert "chown 10002:10001 /exchange" in command
    assert "chmod 0750 /exchange" in command
    assert "unsafe recovery exchange metadata" in command
    assert "-R" not in command

    assert services["controller"]["depends_on"]["recovery-volume-init"] == {
        "condition": "service_completed_successfully"
    }
    assert "recovery_exchange:/var/lib/vps-guardian-recovery:ro" in services["controller"][
        "volumes"
    ]
    assert "recovery_exchange:/var/lib/vps-guardian-backup/recovery" in services["backup"][
        "volumes"
    ]
