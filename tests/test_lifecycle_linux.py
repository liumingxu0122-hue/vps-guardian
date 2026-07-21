from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("VPS_GUARDIAN_LIFECYCLE_TEST_IMAGE")
DOCKER = shutil.which("docker")
PINNED_IMAGE = bool(
    IMAGE
    and (
        re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", IMAGE)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", IMAGE)
    )
)


def test_controller_lifecycle_fixture_covers_recovery_matrix() -> None:
    fixture = (ROOT / "tests/lifecycle/controller_lifecycle_test.sh").read_text(encoding="utf-8")

    for marker in (
        "Complete A install, A -> B, B -> A, and B redeployment",
        "timer-stop SIGKILL did not leave a durable journal",
        "recovery did not stop the candidate before restoring units",
        "schema-incompatible recovery restarted the Controller",
        "schema-incompatible recovery restarted the backup timer",
        "schema-incompatible recovery restarted the backup freshness timer",
        "LIFECYCLE_INJECT_SIGNAL='TERM'",
        "LIFECYCLE_INJECT_SIGNAL='KILL'",
        "run_upgrade_recovery",
        "run_rollback_recovery",
    ):
        assert marker in fixture


@pytest.mark.skipif(
    os.name == "nt" or DOCKER is None or IMAGE is None,
    reason=(
        "Linux lifecycle behavior tests require Docker and a digest-pinned "
        "VPS_GUARDIAN_LIFECYCLE_TEST_IMAGE"
    ),
)
def test_controller_lifecycle_security_contract_in_ephemeral_linux() -> None:
    assert DOCKER is not None
    assert IMAGE is not None
    assert PINNED_IMAGE, (
        "VPS_GUARDIAN_LIFECYCLE_TEST_IMAGE must use a RepoDigest or exact image ID"
    )
    inspect = subprocess.run(  # noqa: S603 - resolved local Docker binary, fixed arguments
        [DOCKER, "image", "inspect", IMAGE],
        check=False,
        capture_output=True,
        text=True,
    )
    if inspect.returncode != 0:
        pytest.skip(f"required local lifecycle test image is unavailable: {IMAGE}")

    subprocess.run(  # noqa: S603 - isolated fixed image and read-only repository mount
        [
            DOCKER,
            "run",
            "--rm",
            "--network",
            "none",
            "--env",
            "VPS_GUARDIAN_EPHEMERAL_LIFECYCLE_TEST=1",
            "--volume",
            f"{ROOT}:/workspace:ro",
            IMAGE,
            "sh",
            "/workspace/tests/lifecycle/controller_lifecycle_test.sh",
        ],
        check=True,
        timeout=120,
    )
