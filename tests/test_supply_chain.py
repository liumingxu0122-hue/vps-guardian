from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_python_lockfiles_pin_and_hash_every_dependency_set() -> None:
    for filename in ("requirements.lock", "requirements-dev.lock", "requirements-build.lock"):
        content = (ROOT / filename).read_text(encoding="utf-8")
        assert "==" in content
        assert "--hash=sha256:" in content
        requirement_lines = [
            line for line in content.splitlines() if line and not line.startswith((" ", "#"))
        ]
        assert requirement_lines
        assert all("==" in line for line in requirement_lines)


def test_controller_image_uses_hashed_locks_and_separate_wheel_builder() -> None:
    dockerfile = (ROOT / "deploy" / "controller.Dockerfile").read_text(encoding="utf-8")
    assert "AS build" in dockerfile
    assert "python -m build --wheel --no-isolation" in dockerfile
    assert dockerfile.count("--require-hashes") == 2
    assert "python -m pip install --no-cache-dir ." not in dockerfile
    assert "python -m pip install --no-cache-dir --no-deps /tmp/vps_guardian-*.whl" in dockerfile
    assert "AS restic-build" in dockerfile
    assert "RESTIC_COMMIT=6aa3a516ce654808a1f28f9fa21e9b7c8e6e90bf" in dockerfile
    assert (
        "RESTIC_SOURCE_SHA256="
        "6318c51f187bafbaf33d1ab6dcb5abde9a94de11476651cbb2982f1ba89ca8a8"
    ) in dockerfile
    assert "COPY --from=restic-build /out/restic /usr/local/bin/restic" in dockerfile
    assert "restic 0\\.19\\.1 compiled with go1\\.26\\.5" in dockerfile
    assert "USER guardian:guardian" in dockerfile


def test_controller_runtime_apt_inputs_use_a_fixed_snapshot_and_explicit_packages() -> None:
    dockerfile = (ROOT / "deploy" / "controller.Dockerfile").read_text(encoding="utf-8")
    assert "ARG DEBIAN_SNAPSHOT=20260720T000000Z" in dockerfile
    assert "trixie main" in dockerfile
    assert "trixie-security main" in dockerfile
    assert "snapshot.debian.org/archive/debian/$DEBIAN_SNAPSHOT" in dockerfile
    assert "snapshot.debian.org/archive/debian-security/$DEBIAN_SNAPSHOT" in dockerfile
    assert "Acquire::Check-Valid-Until=false" in dockerfile
    for package in (
        "ca-certificates",
        "libpq5",
        "mariadb-client-core",
    ):
        assert f"      {package}" in dockerfile
    assert "AS database-client-build" in dockerfile
    assert "install -D -m 0555 /usr/bin/mariadb-dump /out/mysqldump" in dockerfile
    assert "install -m 0555 /usr/lib/postgresql/17/bin/pg_dump /out/pg_dump" in dockerfile
    assert "COPY --from=database-client-build" in dockerfile
    runtime = dockerfile.split(" AS runtime", maxsplit=1)[1]
    assert "      curl" not in runtime
    assert "default-mysql-client" not in runtime
    assert "      postgresql-client" not in runtime
    assert "apt-get update " not in dockerfile


def test_postgres_image_rebuilds_gosu_with_the_fixed_go_toolchain() -> None:
    dockerfile = (ROOT / "deploy" / "postgres.Dockerfile").read_text(encoding="utf-8")
    assert "GOSU_COMMIT=6456aaa0f3c854d199d0f037f068eb97515b7513" in dockerfile
    assert (
        "GOSU_SOURCE_SHA256="
        "33d7537d588ea49458b9509bcf4554bdf5ceacc66da71e5caa1058ea3b689c3b"
    ) in dockerfile
    assert dockerfile.count("^1\\.19 \\(go1\\.26\\.5 on linux/") == 2


def test_web_image_rebuilds_versioned_caddy_with_the_fixed_go_toolchain() -> None:
    dockerfile = (ROOT / "deploy" / "web.Dockerfile").read_text(encoding="utf-8")
    assert "CADDY_COMMIT=e2eee6a7fce366321294c9c2a79f3146891dcbdf" in dockerfile
    assert (
        "CADDY_SOURCE_SHA256="
        "a593bd7077c76102ca76d19287a5e247d4e359dd67eddbc933f865afd3c131eb"
    ) in dockerfile
    assert "github.com/caddyserver/caddy/v2.CustomVersion=$CADDY_VERSION" in dockerfile
    assert dockerfile.count("^v2\\.11\\.4( |$)") == 2
    assert "apk del --no-cache curl libcurl c-ares" in dockerfile
    assert "! apk info --exists curl libcurl c-ares" in dockerfile


def test_every_dockerfile_base_image_is_digest_pinned() -> None:
    for path in (
        ROOT / "deploy" / "controller.Dockerfile",
        ROOT / "deploy" / "postgres.Dockerfile",
        ROOT / "deploy" / "web.Dockerfile",
        ROOT / "tests" / "lifecycle" / "Dockerfile",
    ):
        dockerfile = path.read_text(encoding="utf-8")
        from_lines = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
        assert from_lines
        assert all(
            re.match(r"^FROM [^\s]+@sha256:[a-f0-9]{64}(?: AS [A-Za-z0-9_-]+)?$", line)
            for line in from_lines
        )
    lifecycle = (ROOT / "tests/lifecycle/Dockerfile").read_text(encoding="utf-8")
    assert "ARG DEBIAN_SNAPSHOT=20260720T000000Z" in lifecycle
    assert "trixie main" in lifecycle
    assert "trixie-security main" in lifecycle
    assert "snapshot.debian.org/archive/debian/$DEBIAN_SNAPSHOT" in lifecycle
    assert "snapshot.debian.org/archive/debian-security/$DEBIAN_SNAPSHOT" in lifecycle
    for package in (
        "coreutils",
        "curl",
        "findutils",
        "git",
        "grep",
        "passwd",
        "sed",
        "tar",
        "util-linux",
    ):
        assert f"      {package}" in lifecycle


def test_release_builder_emits_checksums_and_available_sbom_or_blocker() -> None:
    script = (ROOT / "scripts" / "build-release.sh").read_text(encoding="utf-8")
    assert "npm sbom --package-lock-only --sbom-format cyclonedx" in script
    assert "agent-build-info.txt" in script
    assert "python-sbom.BLOCKED.txt" in script
    assert "images.BLOCKED.txt" in script
    assert "sha256sum" in script
    assert "git status --short" in script


def test_systemd_release_sources_are_exported_from_an_exact_clean_commit() -> None:
    for script_name in ("install-controller.sh", "upgrade-controller.sh"):
        script = (ROOT / "scripts" / script_name).read_text(encoding="utf-8")
        assert "release source must be the root of its Git worktree" in script
        assert "status --porcelain=v1 --untracked-files=all" in script
        assert "release source must be a clean Git worktree" in script
        assert "rev-parse --verify 'HEAD^{commit}'" in script
        assert 'git -C "$source_dir" archive --format=tar' in script
        assert '"$source_commit" -- controller deploy/systemd runbooks scripts web' in script
        assert "pyproject.toml requirements-build.lock requirements.lock" in script
        assert 'printf \'%s\\n\' "$source_commit" > "$release_dir/SOURCE_COMMIT"' in script
        assert "tar --exclude" not in script
        assert "release source status could not be read" in script
        assert "release-manifest.py" in script
        assert "RELEASE.MANIFEST.json" in script

        assert "python3 -m venv --copies" in script
        assert "remove_node_modules_tree" in script
        assert 'find "$node_modules" -depth -delete' in script
        assert "rm -rf" not in script
        assert script.count("reject_release_symlinks") >= 3
