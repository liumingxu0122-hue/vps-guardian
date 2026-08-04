from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).parents[1]
HELPER = ROOT / "scripts" / "materialize-runtime-secret.py"
pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="runtime Secret ownership tests require root on Linux",
)


def load_helper() -> ModuleType:
    specification = importlib.util.spec_from_file_location("materialize_runtime_secret", HELPER)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def roots(tmp_path: Path) -> tuple[Path, Path]:
    canonical = tmp_path / "canonical"
    runtime = tmp_path / "runtime"
    canonical.mkdir(mode=0o700)
    runtime.mkdir(mode=0o711)
    return canonical, runtime


def source_file(canonical: Path, name: str = "value", value: bytes = b"first") -> Path:
    path = canonical / name
    path.write_bytes(value)
    path.chmod(0o600)
    return path


def service_directory(runtime: Path, name: str, uid: int, gid: int) -> Path:
    path = runtime / name
    path.mkdir(mode=0o500)
    os.chown(path, uid, gid)
    return path


def test_atomic_materialization_isolated_readability_and_idempotency(tmp_path: Path) -> None:
    helper = load_helper()
    canonical, runtime = roots(tmp_path)
    source = source_file(canonical)
    controller = service_directory(runtime, "controller", 10001, 10001)
    target = controller / "value"

    helper.materialize(source, target, canonical, runtime, 10001, 10001, 32)
    first_inode = target.stat().st_ino
    assert (target.stat().st_uid, target.stat().st_gid, target.stat().st_mode & 0o777) == (
        10001,
        10001,
        0o400,
    )

    source.write_bytes(b"second")
    source.chmod(0o600)
    helper.materialize(source, target, canonical, runtime, 10001, 10001, 32)
    assert target.stat().st_ino != first_inode
    assert target.read_bytes() == b"second"


def test_service_directories_prevent_cross_service_reads(tmp_path: Path) -> None:
    helper = load_helper()
    canonical, runtime = roots(tmp_path)
    controller_source = source_file(canonical, "controller")
    gateway_source = source_file(canonical, "gateway")
    controller = service_directory(runtime, "controller", 10001, 10001)
    gateway = service_directory(runtime, "gateway", 99, 99)
    controller_target = controller / "controller"
    gateway_target = gateway / "gateway"

    helper.materialize(
        controller_source, controller_target, canonical, runtime, 10001, 10001, 32
    )
    helper.materialize(gateway_source, gateway_target, canonical, runtime, 99, 99, 32)

    assert (controller.stat().st_uid, controller.stat().st_mode & 0o777) == (10001, 0o500)
    assert (gateway.stat().st_uid, gateway.stat().st_mode & 0o777) == (99, 0o500)
    assert controller_target.stat().st_uid != gateway_target.stat().st_uid


@pytest.mark.parametrize("defect", ["mode", "owner", "symlink", "missing", "escape"])
def test_rejects_unsafe_canonical_sources(tmp_path: Path, defect: str) -> None:
    helper = load_helper()
    canonical, runtime = roots(tmp_path)
    source = source_file(canonical)
    service = service_directory(runtime, "controller", 10001, 10001)
    if defect == "mode":
        source.chmod(0o640)
    elif defect == "owner":
        os.chown(source, 10001, 10001)
    elif defect == "symlink":
        original = source
        source = canonical / "link"
        source.symlink_to(original)
    elif defect == "missing":
        source = canonical / "missing"
    elif defect == "escape":
        source = source_file(tmp_path, "outside")

    with pytest.raises((helper.MaterializationError, FileNotFoundError)):
        helper.materialize(source, service / "value", canonical, runtime, 10001, 10001, 32)


def test_interruption_removes_temporary_file_and_preserves_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = load_helper()
    canonical, runtime = roots(tmp_path)
    source = source_file(canonical)
    service = service_directory(runtime, "controller", 10001, 10001)
    target = service / "value"
    helper.materialize(source, target, canonical, runtime, 10001, 10001, 32)
    original_inode = target.stat().st_ino
    real_write = helper.os.write

    def interrupted_write(descriptor: int, value: bytes | memoryview) -> int:
        real_write(descriptor, value)
        raise InterruptedError("simulated interruption")

    monkeypatch.setattr(helper.os, "write", interrupted_write)
    with pytest.raises(InterruptedError, match="simulated interruption"):
        helper.materialize(source, target, canonical, runtime, 10001, 10001, 32)

    assert target.stat().st_ino == original_inode
    assert not list(service.glob(".value.new.*"))


@pytest.mark.parametrize("defect", ["directory-mode", "directory-owner", "target-symlink"])
def test_rejects_unsafe_runtime_destination(tmp_path: Path, defect: str) -> None:
    helper = load_helper()
    canonical, runtime = roots(tmp_path)
    source = source_file(canonical)
    service = service_directory(runtime, "controller", 10001, 10001)
    target = service / "value"
    if defect == "directory-mode":
        service.chmod(0o700)
    elif defect == "directory-owner":
        os.chown(service, 0, 0)
    else:
        target.symlink_to(source)

    with pytest.raises(helper.MaterializationError):
        helper.materialize(source, target, canonical, runtime, 10001, 10001, 32)
