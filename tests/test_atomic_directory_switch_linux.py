from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).parents[1]
HELPER = ROOT / "scripts" / "atomic-directory-switch.py"

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="atomic directory exchange requires a root Linux filesystem test",
)


def run_helper(*arguments: Path | str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed helper and test-owned paths only.
        [sys.executable, str(HELPER), *(str(argument) for argument in arguments)],
        check=False,
        capture_output=True,
        text=True,
    )


def load_helper() -> ModuleType:
    specification = importlib.util.spec_from_file_location("atomic_directory_switch", HELPER)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_install_and_refresh_never_remove_the_runtime_path(tmp_path: Path) -> None:
    staged = tmp_path / ".runtime.new.first"
    runtime = tmp_path / "runtime"
    staged.mkdir(mode=0o700)
    (staged / "value").write_text("first\n", encoding="utf-8")

    installed = run_helper("install", staged, runtime)
    assert installed.returncode == 0, installed.stderr
    assert (runtime / "value").read_text(encoding="utf-8") == "first\n"

    replacement = tmp_path / ".runtime.new.second"
    previous = tmp_path / "runtime.previous.test"
    replacement.mkdir(mode=0o700)
    (replacement / "value").write_text("second\n", encoding="utf-8")
    refreshed = run_helper("refresh", replacement, runtime, previous)

    assert refreshed.returncode == 0, refreshed.stderr
    assert runtime.is_dir()
    assert (runtime / "value").read_text(encoding="utf-8") == "second\n"
    assert (previous / "value").read_text(encoding="utf-8") == "first\n"
    assert previous.stat().st_mode & 0o777 == 0


def test_refresh_failure_leaves_the_original_runtime_in_place(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    staged = tmp_path / ".runtime.new.failure"
    previous = tmp_path / "runtime.previous.existing"
    runtime.mkdir(mode=0o700)
    staged.mkdir(mode=0o700)
    previous.mkdir(mode=0o700)
    (runtime / "value").write_text("original\n", encoding="utf-8")
    (staged / "value").write_text("replacement\n", encoding="utf-8")

    result = run_helper("refresh", staged, runtime, previous)

    assert result.returncode != 0
    assert runtime.is_dir()
    assert (runtime / "value").read_text(encoding="utf-8") == "original\n"


def test_interruption_after_exchange_preserves_both_secret_trees(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = load_helper()
    runtime = tmp_path / "runtime"
    staged = tmp_path / ".runtime.new.interrupted"
    previous = tmp_path / "runtime.previous.interrupted"
    runtime.mkdir(mode=0o700)
    staged.mkdir(mode=0o700)
    (runtime / "value").write_text("original\n", encoding="utf-8")
    (staged / "value").write_text("replacement\n", encoding="utf-8")
    rename_exchange = helper.rename_exchange

    def exchange_then_interrupt(first: Path, second: Path) -> None:
        rename_exchange(first, second)
        raise RuntimeError("simulated interruption after atomic exchange")

    monkeypatch.setattr(helper, "rename_exchange", exchange_then_interrupt)

    with pytest.raises(RuntimeError, match="simulated interruption"):
        helper.refresh(staged, runtime, previous)

    assert (runtime / "value").read_text(encoding="utf-8") == "replacement\n"
    assert (staged / "value").read_text(encoding="utf-8") == "original\n"
    assert not previous.exists()
