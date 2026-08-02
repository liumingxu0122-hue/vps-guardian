from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).parents[1] / "operations" / "scripts" / "validate_compose_secret_files.py"
)
SPEC = importlib.util.spec_from_file_location("validate_compose_secret_files", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _root_secret(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("test-only\n", encoding="utf-8")
    path.chmod(0o600)
    if getattr(os, "geteuid", lambda: -1)() != 0:
        pytest.skip("root ownership validation requires root")


def test_accepts_relative_and_absolute_paths(tmp_path: Path) -> None:
    root = tmp_path / "runtime" / "secrets"
    relative = root / "relative"
    absolute = root / "absolute"
    _root_secret(relative)
    _root_secret(absolute)
    config = {
        "secrets": {
            "relative": {"file": str(relative.relative_to(tmp_path))},
            "absolute": {"file": str(absolute)},
        }
    }

    result = MODULE.validate_secret_files(config, root, tmp_path)

    assert [item[0] for item in result] == ["absolute", "relative"]


@pytest.mark.parametrize(
    ("path_parts", "message"),
    [
        (("runtime", "runtime", "secret"), "repeated runtime"),
        (("outside", "secret"), "escapes the approved root"),
    ],
)
def test_rejects_duplicate_runtime_and_escape(
    tmp_path: Path, path_parts: tuple[str, ...], message: str
) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    candidate = tmp_path.joinpath(*path_parts)
    _root_secret(candidate)

    with pytest.raises(MODULE.SecretPathError, match=message):
        MODULE.validate_secret_files({"secrets": {"bad": {"file": str(candidate)}}}, root, tmp_path)


def test_cli_config_fixture_is_json_serializable(tmp_path: Path) -> None:
    root = tmp_path / "secrets"
    secret = root / "value"
    _root_secret(secret)
    raw = json.dumps({"secrets": {"value": {"file": str(secret)}}})

    assert MODULE._parse_config(raw)["secrets"]["value"]["file"] == str(secret)
