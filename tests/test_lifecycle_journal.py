from __future__ import annotations

import importlib.util
import os
import stat
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "lifecycle-journal.py"
SPEC = importlib.util.spec_from_file_location("lifecycle_journal", SCRIPT)
assert SPEC and SPEC.loader
journal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(journal)
assert isinstance(journal, ModuleType)

T0 = "2026-07-18T00:00:00.000000Z"
T1 = "2026-07-18T00:00:01.000000Z"


def document_for(operation: str = "upgrade") -> dict[str, object]:
    previous = (
        None
        if operation in {"install", "staging-deploy"}
        else "/opt/vps-guardian/releases/previous"
    )
    return journal.create_document(
        operation=operation,
        previous_release=previous,
        candidate_release="/opt/vps-guardian/releases/candidate",
        db_revision_before="0003_agent_auth",
        unit_metadata_refs=["/var/lib/vps-guardian-units/candidate/UNITS.json"],
        image_metadata_refs=["/var/lib/vps-guardian-images/candidate/IMAGES.json"],
        timer_state="active",
        controller_state="active",
        timestamp=T0,
    )


@pytest.mark.parametrize(
    "operation",
    ["install", "upgrade", "rollback", "staging-deploy", "staging-rollback"],
)
def test_schema_covers_each_lifecycle_boundary(operation: str) -> None:
    document = document_for(operation)
    assert journal.validate_document(document) == document
    assert document["schema_version"] == 1
    assert document["phase"] == "initialized"
    assert set(document) == journal.DOCUMENT_FIELDS


def test_schema_rejects_unknown_missing_and_ill_typed_fields() -> None:
    document = document_for()
    document["unexpected_secret"] = "must-not-be-accepted"
    with pytest.raises(journal.JournalError, match="unknown=unexpected_secret"):
        journal.validate_document(document)

    document = document_for()
    del document["timer_state"]
    with pytest.raises(journal.JournalError, match="missing=timer_state"):
        journal.validate_document(document)

    document = document_for()
    document["unit_metadata_refs"] = "not-an-array"
    with pytest.raises(journal.JournalError, match="JSON array"):
        journal.validate_document(document)


@pytest.mark.parametrize(
    "field,value",
    [
        ("candidate_release", "relative/release"),
        ("candidate_release", "/opt/releases/../escape"),
        ("candidate_release", "/opt//releases/candidate"),
        ("candidate_release", "/"),
        ("unit_metadata_refs", ["/var/lib/units/../../etc/shadow"]),
        ("image_metadata_refs", ["metadata.json"]),
    ],
)
def test_schema_rejects_noncanonical_or_traversing_paths(field: str, value: object) -> None:
    document = document_for()
    document[field] = value
    with pytest.raises(journal.JournalError, match="absolute canonical|without traversal"):
        journal.validate_document(document)


def test_schema_rejects_operation_release_mismatches_and_duplicate_refs() -> None:
    install = document_for("install")
    install["previous_release"] = "/opt/vps-guardian/releases/previous"
    with pytest.raises(journal.JournalError, match="install cannot declare"):
        journal.validate_document(install)

    upgrade = document_for("upgrade")
    upgrade["previous_release"] = None
    with pytest.raises(journal.JournalError, match="requires a previous release"):
        journal.validate_document(upgrade)

    first_staging_deploy = document_for("staging-deploy")
    assert first_staging_deploy["previous_release"] is None
    assert journal.validate_document(first_staging_deploy) == first_staging_deploy

    for operation in ("rollback", "staging-rollback"):
        missing_previous = document_for(operation)
        missing_previous["previous_release"] = None
        with pytest.raises(journal.JournalError, match="requires a previous release"):
            journal.validate_document(missing_previous)

    duplicate = document_for()
    duplicate["unit_metadata_refs"] = ["/var/lib/units/a", "/var/lib/units/a"]
    with pytest.raises(journal.JournalError, match="duplicate"):
        journal.validate_document(duplicate)


def test_happy_path_phase_transitions_are_forward_only() -> None:
    document = document_for()
    phases = (
        "prepared",
        "quiesced",
        "database_updated",
        "units_updated",
        "candidate_activated",
        "verified",
        "committed",
    )
    for index, phase in enumerate(phases, start=1):
        document = journal.update_document(
            document,
            phase=phase,
            changes={"db_revision_after": "0004_dual_identity"}
            if phase == "database_updated"
            else None,
            timestamp=f"2026-07-18T00:00:{index:02d}.000000Z",
        )
        assert document["phase"] == phase

    with pytest.raises(journal.JournalError, match="illegal lifecycle phase transition"):
        journal.update_document(document, phase="verified", timestamp=T1)


def test_recovery_path_is_one_way_and_requires_explicit_completion() -> None:
    document = journal.update_document(document_for(), phase="prepared", timestamp=T1)
    document = journal.update_document(
        document,
        phase="recovery_required",
        changes={"controller_state": "failed"},
        timestamp="2026-07-18T00:00:02.000000Z",
    )
    document = journal.update_document(
        document,
        phase="recovery_started",
        timestamp="2026-07-18T00:00:03.000000Z",
    )
    document = journal.update_document(
        document,
        phase="previous_restored",
        changes={"controller_state": "active"},
        timestamp="2026-07-18T00:00:04.000000Z",
    )
    assert journal.assert_can_clear(document) == document
    with pytest.raises(journal.JournalError, match="illegal lifecycle phase transition"):
        journal.update_document(document, phase="committed")


def test_update_rejects_same_phase_skips_and_immutable_fields() -> None:
    document = document_for()
    with pytest.raises(journal.JournalError, match="initialized -> initialized"):
        journal.update_document(document, phase="initialized")
    with pytest.raises(journal.JournalError, match="initialized -> committed"):
        journal.update_document(document, phase="committed")
    with pytest.raises(journal.JournalError, match="immutable or unknown"):
        journal.update_document(
            document,
            phase="prepared",
            changes={"candidate_release": "/opt/vps-guardian/releases/other"},
        )


def test_update_timestamp_remains_monotonic_when_clock_moves_back() -> None:
    document = document_for()
    updated = journal.update_document(document, phase="prepared", timestamp=T0)
    assert updated["updated_at"] == "2026-07-18T00:00:00.000001Z"
    assert updated["created_at"] == T0


def test_unfinished_or_completed_journal_must_be_explicitly_resolved() -> None:
    document = document_for()
    with pytest.raises(journal.JournalError, match="unfinished upgrade transaction"):
        journal.assert_can_initialize(document)
    with pytest.raises(journal.JournalError, match="cannot be cleared"):
        journal.assert_can_clear(document)

    aborted = journal.update_document(document, phase="aborted", timestamp=T1)
    assert journal.assert_can_clear(aborted) == aborted
    with pytest.raises(journal.JournalError, match="clear it before initializing"):
        journal.assert_can_initialize(aborted)


def test_runtime_metadata_checks_require_root_and_secure_modes() -> None:
    journal.validate_secure_directory_metadata(
        mode=stat.S_IFDIR | 0o755,
        uid=0,
        label="root",
    )
    with pytest.raises(journal.JournalError, match="not group/other writable"):
        journal.validate_secure_directory_metadata(
            mode=stat.S_IFDIR | 0o775,
            uid=0,
            label="root",
        )
    with pytest.raises(journal.JournalError, match="root-owned"):
        journal.validate_secure_directory_metadata(
            mode=stat.S_IFDIR | 0o700,
            uid=1000,
            label="root",
        )

    journal.validate_secure_file_metadata(
        mode=stat.S_IFREG | 0o600,
        uid=0,
        label="journal",
    )
    with pytest.raises(journal.JournalError, match="mode 0600"):
        journal.validate_secure_file_metadata(
            mode=stat.S_IFREG | 0o640,
            uid=0,
            label="journal",
        )
    with pytest.raises(journal.JournalError, match="non-symlink"):
        journal.validate_secure_file_metadata(
            mode=stat.S_IFLNK | 0o600,
            uid=0,
            label="journal",
        )


def test_runtime_root_check_has_no_windows_or_nonroot_bypass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(journal.JournalError, match="require Linux"):
        journal.require_linux_root()

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(journal.JournalError, match="require root"):
        journal.require_linux_root()


def test_atomic_write_fsyncs_file_replaces_and_fsyncs_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "transaction.json"
    fsync_descriptors: list[int] = []
    fsynced_directories: list[Path] = []
    replacements: list[tuple[Path, Path]] = []
    real_replace = os.replace

    monkeypatch.setattr(journal, "set_fd_root_mode", lambda _descriptor, _mode: None)
    monkeypatch.setattr(os, "fsync", lambda descriptor: fsync_descriptors.append(descriptor))
    monkeypatch.setattr(
        journal,
        "fsync_directory",
        lambda path: fsynced_directories.append(path),
    )

    def replace(
        source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        target: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    ) -> None:
        source_path = Path(source)
        target_path = Path(target)
        replacements.append((source_path, target_path))
        real_replace(source, target)

    monkeypatch.setattr(os, "replace", replace)
    journal.atomic_write_document(destination, document_for())

    assert fsync_descriptors
    assert replacements and replacements[0][1] == destination
    assert fsynced_directories == [tmp_path]
    assert journal.validate_document(__import__("json").loads(destination.read_text()))


def test_durable_clear_unlinks_and_fsyncs_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "transaction.json"
    destination.write_text("placeholder", encoding="utf-8")
    fsynced_directories: list[Path] = []
    monkeypatch.setattr(journal, "validate_journal_file", lambda _path: None)
    monkeypatch.setattr(
        journal,
        "fsync_directory",
        lambda path: fsynced_directories.append(path),
    )

    journal.durable_clear(destination)

    assert not destination.exists()
    assert fsynced_directories == [tmp_path]


def test_parser_exposes_only_root_checked_runtime_commands() -> None:
    parser = journal.build_parser()
    options = parser.parse_args(
        [
            "--root",
            "/var/lib/vps-guardian-lifecycle",
            "--journal",
            "/var/lib/vps-guardian-lifecycle/controller.json",
            "init",
            "--operation",
            "upgrade",
            "--previous-release",
            "/opt/vps-guardian/releases/previous",
            "--candidate-release",
            "/opt/vps-guardian/releases/candidate",
        ]
    )
    assert options.command == "init"
    assert not hasattr(options, "no_root_check")


def test_controller_lifecycle_scripts_persist_and_recover_journals() -> None:
    scripts = {
        "install": (ROOT / "scripts/install-controller.sh").read_text(encoding="utf-8"),
        "upgrade": (ROOT / "scripts/upgrade-controller.sh").read_text(encoding="utf-8"),
        "rollback": (ROOT / "scripts/rollback-controller.sh").read_text(encoding="utf-8"),
    }
    for operation, script in scripts.items():
        assert "journal_root='/var/lib/vps-guardian-lifecycle'" in script
        assert 'recovery_helper="$script_dir/recover-controller-lifecycle.sh"' in script
        assert f"--expected-operation {operation} --lock-fd 9" in script
        assert f"exec sh \"$recovery_helper\" --expected-operation {operation}" in script
        assert "lifecycle_journal clear" in script
        assert f"--operation {operation}" in script

    assert scripts["install"].index('exec sh "$recovery_helper"') < scripts["install"].index(
        'if [ -z "$source_dir" ]'
    )
    assert scripts["upgrade"].index('exec sh "$recovery_helper"') < scripts["upgrade"].index(
        'source_canonical="$(readlink -f -- "$source_dir")"'
    )
    assert scripts["rollback"].index('exec sh "$recovery_helper"') < scripts["rollback"].index(
        "install_root='/opt/vps-guardian'"
    )

    recovery = (ROOT / "scripts/recover-controller-lifecycle.sh").read_text(encoding="utf-8")
    assert 'lock_reference="/proc/self/fd/$lock_fd"' in recovery
    assert 'flock -n "$lock_fd"' in recovery
    assert "--phase recovery_required" in recovery
    assert "--phase recovery_started" in recovery
    assert "--phase aborted" in recovery
    assert "--phase previous_restored" in recovery
    assert "previous release is incompatible with the live schema" in recovery
    assert "Controller and backup timers stopped, journal retained" in recovery
    assert "--property MainPID --value" in recovery


def test_controller_lifecycle_journals_precede_mutation_and_phases_follow_actions() -> None:
    install = (ROOT / "scripts/install-controller.sh").read_text(encoding="utf-8")
    upgrade = (ROOT / "scripts/upgrade-controller.sh").read_text(encoding="utf-8")
    rollback = (ROOT / "scripts/rollback-controller.sh").read_text(encoding="utf-8")

    for script, operation in ((upgrade, "upgrade"), (rollback, "rollback")):
        transaction = script[script.index(f"lifecycle_journal init --operation {operation}") :]
        assert transaction.index("lifecycle_journal init") < transaction.index(
            "systemctl stop vps-guardian-backup.timer"
        )
        controller_stop = transaction.index("systemctl stop vps-guardian-controller.service")
        quiesced_phase = transaction.index("lifecycle_journal update --phase quiesced")
        assert controller_stop < quiesced_phase
        assert transaction.index("systemctl daemon-reload") < transaction.index(
            "lifecycle_journal update --phase units_updated"
        )
        assert transaction.index("switch_current") < transaction.index(
            "lifecycle_journal update --phase candidate_activated"
        )

    install_transaction = install[install.index("lifecycle_journal init --operation install") :]
    assert install_transaction.index("systemctl daemon-reload") < install_transaction.index(
        "lifecycle_journal update --phase units_updated"
    )
    assert install_transaction.index('ln -s "$release_dir"') < install_transaction.index(
        "lifecycle_journal update --phase candidate_activated"
    )


def test_systemd_identity_boundaries_use_fixed_secret_paths() -> None:
    controller_unit = (ROOT / "deploy/systemd/vps-guardian-controller.service").read_text(
        encoding="utf-8"
    )
    backup_unit = (ROOT / "deploy/systemd/vps-guardian-backup.service").read_text(encoding="utf-8")
    backup_wrapper = (ROOT / "scripts/run-backup-command.sh").read_text(encoding="utf-8")
    lifecycle_scripts = "\n".join(
        (ROOT / f"scripts/{name}-controller.sh").read_text(encoding="utf-8")
        for name in ("install", "upgrade", "rollback")
    )

    fixed_groups = "SupplementaryGroups=guardian-release guardian-database"
    fixed_database = "GUARDIAN_DATABASE_URL_FILE=/etc/vps-guardian/database-url"
    assert fixed_groups in controller_unit
    assert fixed_groups in backup_unit
    assert fixed_database in controller_unit
    assert fixed_database in backup_unit
    assert "GUARDIAN_CONTROLLER_SIGNING_KEY_FILE=/etc/vps-guardian/controller-ed25519.pem" in (
        controller_unit
    )
    assert "InaccessiblePaths=/etc/vps-guardian/controller.env" in backup_unit
    assert "/etc/vps-guardian/controller-ed25519.pem" in backup_unit
    assert "SupplementaryGroups=guardian\n" not in backup_unit
    assert "/etc/vps-guardian-backup-secrets/database-url" not in backup_unit
    assert "/etc/vps-guardian/database-url" in backup_wrapper
    assert "root:guardian-database:750" in backup_wrapper
    assert "root:guardian-database:640" in backup_wrapper
    assert "root:guardian-release:550" in lifecycle_scripts
    assert "guardian-backup must not belong to the guardian" in lifecycle_scripts
    assert "cannot override the fixed Controller signing-key path" in lifecycle_scripts
    assert lifecycle_scripts.count("cannot define GUARDIAN_DATABASE_URL") == 3
    assert "GUARDIAN_DATABASE_URL[[:space:]]*=" in (
        ROOT / "scripts/recover-controller-lifecycle.sh"
    ).read_text(encoding="utf-8")
