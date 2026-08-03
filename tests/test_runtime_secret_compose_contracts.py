from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]


def compose() -> dict[str, object]:
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


def test_core_services_use_fixed_numeric_nonroot_identities() -> None:
    services = compose()["services"]

    assert services["database"]["user"] == "70:70"
    assert services["controller"]["user"] == "10001:10001"
    assert services["agent-gateway"]["user"] == "99:99"
    assert services["backup"]["user"] == "10002:10002"
    assert 'USER 70:70' in (ROOT / "deploy/postgres.Dockerfile").read_text(encoding="utf-8")
    assert 'USER 10001:10001' in (ROOT / "deploy/controller.Dockerfile").read_text(
        encoding="utf-8"
    )
    assert 'USER 99:99' in (ROOT / "deploy/agent-gateway.Dockerfile").read_text(
        encoding="utf-8"
    )


def test_each_service_receives_only_its_runtime_secret_directory() -> None:
    services = compose()["services"]
    expected = {
        "database": "/postgresql/",
        "controller": "/controller/",
        "agent-gateway": "/gateway/",
        "backup": "/backup/",
    }
    for service, directory in expected.items():
        volumes = services[service]["volumes"]
        secret_mounts = [mount for mount in volumes if ":/run/secrets/" in mount]
        assert secret_mounts
        assert all(directory in mount and mount.endswith(":ro") for mount in secret_mounts)
        assert "secrets" not in services[service]


def test_compose_does_not_use_local_file_secret_permission_emulation() -> None:
    model = compose()

    assert "secrets" not in model
    for overlay in ("deploy/restic-s3.compose.yml", "deploy/offsite-backup.compose.yml"):
        contents = (ROOT / overlay).read_text(encoding="utf-8")
        assert "secrets:" not in contents
        assert ":/run/secrets/" in contents


def test_runtime_secret_tree_is_excluded_from_source_and_build_context() -> None:
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()

    assert "secrets" in dockerignore
    assert "secrets/" in gitignore
