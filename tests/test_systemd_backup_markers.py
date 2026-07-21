from __future__ import annotations

import importlib.util
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "systemd-backup-markers.py"
SPEC = importlib.util.spec_from_file_location("systemd_backup_markers", SCRIPT)
assert SPEC and SPEC.loader
markers = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(markers)
assert isinstance(markers, ModuleType)

NOW = datetime(2026, 7, 19, 0, 0, 0, tzinfo=UTC)


def backup_result(
    *, verified: bool, recording_error: str | None = None
) -> dict[str, object]:
    return {
        "uploaded": True,
        "repository_checked": True,
        "manifest_restored": True,
        "verified": verified,
        "database_restore_verified": verified,
        "verification_state": "verified" if verified else "pending",
        "recorded": recording_error is None,
        "recording_error": recording_error,
        "snapshot_id": "a" * 64,
        "checksum": "b" * 64,
        "source_commit": "c" * 40,
    }


def write_result(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_pending_result_advances_only_the_upload_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result_path = tmp_path / "result.json"
    write_result(result_path, backup_result(verified=False))
    written: list[dict[str, str]] = []
    monkeypatch.setattr(
        markers,
        "atomic_write_marker",
        lambda _state, document: written.append(dict(document)),
    )

    assert markers.record_result(result_path, tmp_path, now=NOW) is False
    assert [document["kind"] for document in written] == ["upload"]
    assert written[0] == {
        "schema": "vps-guardian-backup-marker/v1",
        "kind": "upload",
        "snapshot_id": "a" * 64,
        "checksum": "b" * 64,
        "source_commit": "c" * 40,
        "recorded_at": "2026-07-19T00:00:00Z",
    }


def test_verified_result_advances_upload_before_verified_and_preserves_recording_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result_path = tmp_path / "result.json"
    write_result(
        result_path,
        backup_result(verified=True, recording_error="recovery_point_persistence_failed"),
    )
    written: list[str] = []
    monkeypatch.setattr(
        markers,
        "atomic_write_marker",
        lambda _state, document: written.append(document["kind"]),
    )

    assert markers.record_result(result_path, tmp_path, now=NOW) is True
    assert written == ["upload", "verified-recovery"]


@pytest.mark.skipif(os.name == "nt", reason="durable marker modes require Linux")
def test_atomic_markers_are_private_and_freshness_reads_the_verified_marker(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o750)
    state_dir.chmod(0o750)
    result_path = tmp_path / "result.json"
    write_result(result_path, backup_result(verified=True))

    assert markers.record_result(result_path, state_dir, now=NOW) is False
    for name in ("last-upload-success.json", "last-verified-recovery.json"):
        marker = state_dir / name
        assert marker.stat().st_mode & 0o777 == 0o400
        os.utime(marker, (NOW.timestamp(), NOW.timestamp()))

    age, snapshot = markers.check_freshness(
        state_dir,
        kind="verified-recovery",
        maximum_age=28_800,
        now=NOW + timedelta(seconds=2),
    )
    assert age == 2
    assert snapshot == "a" * 64


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(uploaded=False),
        lambda value: value.update(snapshot_id="short"),
        lambda value: value.update(checksum="0" * 63),
        lambda value: value.update(source_commit="0" * 40),
        lambda value: value.update(verification_state="verified"),
        lambda value: value.update(database_restore_verified=True),
        lambda value: value.update(recording_error={"unexpected": "object"}),
    ],
)
def test_invalid_upload_metadata_never_writes_a_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: object,
) -> None:
    result = backup_result(verified=False)
    mutation(result)  # type: ignore[operator]
    result_path = tmp_path / "result.json"
    write_result(result_path, result)
    monkeypatch.setattr(
        markers,
        "atomic_write_marker",
        lambda *_args, **_kwargs: pytest.fail("invalid metadata wrote a marker"),
    )

    with pytest.raises(markers.MarkerError, match="valid upload metadata"):
        markers.record_result(result_path, tmp_path, now=NOW)


def prepare_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, recorded_at: datetime = NOW
) -> Path:
    marker = tmp_path / "last-verified-recovery.json"
    document = markers.marker_document(
        markers.validate_backup_result(backup_result(verified=True)),
        kind="verified-recovery",
        recorded_at=recorded_at,
    )
    marker.write_text(json.dumps(document), encoding="ascii")
    marker.chmod(0o400)
    os.utime(marker, (recorded_at.timestamp(), recorded_at.timestamp()))
    metadata = marker.stat()
    monkeypatch.setattr(markers, "validate_state_directory", lambda _path: metadata)
    monkeypatch.setattr(markers, "current_identity", lambda: (metadata.st_uid, metadata.st_gid))
    return marker


@pytest.mark.skipif(os.name == "nt", reason="marker mode/ownership checks require Linux")
def test_verified_freshness_uses_marker_time_and_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepare_marker(tmp_path, monkeypatch)

    age, snapshot = markers.check_freshness(
        tmp_path,
        kind="verified-recovery",
        maximum_age=28_800,
        now=NOW + timedelta(seconds=15),
    )
    assert age == 15
    assert snapshot == "a" * 64


@pytest.mark.skipif(os.name == "nt", reason="marker mode/ownership checks require Linux")
def test_verified_freshness_rejects_stale_or_retimestamped_markers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = prepare_marker(tmp_path, monkeypatch)
    with pytest.raises(markers.MarkerError, match="stale"):
        markers.check_freshness(
            tmp_path,
            kind="verified-recovery",
            maximum_age=3600,
            now=NOW + timedelta(seconds=3601),
        )

    os.utime(marker, (NOW.timestamp() + 60, NOW.timestamp() + 60))
    with pytest.raises(markers.MarkerError, match="inconsistent"):
        markers.check_freshness(
            tmp_path,
            kind="verified-recovery",
            maximum_age=3600,
            now=NOW + timedelta(seconds=120),
        )


def test_systemd_scheduler_and_units_keep_upload_and_verified_freshness_separate() -> None:
    scheduler = (ROOT / "scripts" / "run-systemd-backup.sh").read_text(encoding="utf-8")
    backup_unit = (ROOT / "deploy/systemd/vps-guardian-backup.service").read_text(
        encoding="utf-8"
    )
    freshness_unit = (
        ROOT / "deploy/systemd/vps-guardian-backup-freshness.service"
    ).read_text(encoding="utf-8")
    freshness_timer = (
        ROOT / "deploy/systemd/vps-guardian-backup-freshness.timer"
    ).read_text(encoding="utf-8")

    assert "run-systemd-backup.sh backup" in backup_unit
    assert "check-freshness" in freshness_unit
    assert "GUARDIAN_BACKUP_MAX_AGE_SECONDS=28800" in freshness_unit
    assert "OnUnitActiveSec=15min" in freshness_timer
    assert "Persistent=true" in freshness_timer
    assert "check-upload-freshness" in scheduler
    assert "marker_kind='verified-recovery'" in scheduler
    assert scheduler.index("run-backup-command.sh") < scheduler.index(" record --result")
    assert "RecoveryPoint recording needs reconciliation" in scheduler


def test_controller_lifecycle_manages_freshness_units_and_legacy_snapshots() -> None:
    installer = (ROOT / "scripts/install-controller.sh").read_text(encoding="utf-8")
    upgrade = (ROOT / "scripts/upgrade-controller.sh").read_text(encoding="utf-8")
    rollback = (ROOT / "scripts/rollback-controller.sh").read_text(encoding="utf-8")
    recovery = (ROOT / "scripts/recover-controller-lifecycle.sh").read_text(encoding="utf-8")

    for script in (installer, upgrade, rollback, recovery):
        assert "vps-guardian-backup-freshness.service" in script
        assert "vps-guardian-backup-freshness.timer" in script
    assert 'installed_systemd_units="$core_systemd_units"' in upgrade
    assert "installed systemd freshness unit set is incomplete" in upgrade
    assert 'target_systemd_units="$core_systemd_units"' in rollback
    assert "candidate freshness unit $unit could not be removed" in recovery
    assert recovery.index("systemctl stop vps-guardian-backup-freshness.timer") < recovery.index(
        "systemctl stop vps-guardian-controller.service"
    )
