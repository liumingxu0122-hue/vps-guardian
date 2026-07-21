from __future__ import annotations

from pathlib import Path

import pytest
import typer
from guardian.bootstrap import _password_from_file, app
from guardian.database import SessionLocal
from guardian.models import AuditLog
from typer.testing import CliRunner


def test_automation_password_is_read_only_from_absolute_regular_file(tmp_path: Path) -> None:
    password_file = tmp_path / "owner-password"
    password_file.write_text("long-staging-password-value\n", encoding="utf-8")
    assert _password_from_file(password_file) == "long-staging-password-value"

    with pytest.raises(typer.BadParameter, match="absolute regular file"):
        _password_from_file(Path("owner-password"))
    short = tmp_path / "short"
    short.write_text("too-short\n", encoding="utf-8")
    with pytest.raises(typer.BadParameter, match="at least 14"):
        _password_from_file(short)


def test_crl_publication_cli_appends_bounded_audit_event() -> None:
    result = CliRunner().invoke(
        app,
        [
            "record-crl-publication",
            "--crl-number",
            "4097",
            "--sha256",
            "a" * 64,
            "--outcome",
            "success",
            "--reason-code",
            "published",
            "--execute",
            "--confirm",
            "RECORD VPS GUARDIAN CRL PUBLICATION",
        ],
    )

    assert result.exit_code == 0
    with SessionLocal() as database:
        entry = database.query(AuditLog).one()
        assert entry.action == "gateway.crl_publication"
        assert entry.outcome == "success"
        assert entry.details["sha256"] == "a" * 64


@pytest.mark.parametrize(
    "replacement",
    [
        ["--crl-number", "invalid"],
        ["--sha256", "short"],
        ["--outcome", "ignored"],
        ["--reason-code", "contains spaces"],
    ],
)
def test_crl_publication_cli_rejects_unbounded_metadata(
    replacement: list[str],
) -> None:
    values = {
        "--crl-number": "4097",
        "--sha256": "a" * 64,
        "--outcome": "success",
        "--reason-code": "published",
    }
    values[replacement[0]] = replacement[1]
    arguments = ["record-crl-publication"]
    for option, value in values.items():
        arguments.extend([option, value])
    arguments.extend(
        ["--execute", "--confirm", "RECORD VPS GUARDIAN CRL PUBLICATION"]
    )

    result = CliRunner().invoke(app, arguments)

    assert result.exit_code != 0


def test_crl_publication_cli_requires_explicit_confirmation() -> None:
    result = CliRunner().invoke(
        app,
        [
            "record-crl-publication",
            "--crl-number",
            "unknown",
            "--sha256",
            "a" * 64,
            "--outcome",
            "attempt",
            "--reason-code",
            "validation_started",
        ],
    )

    assert result.exit_code != 0
