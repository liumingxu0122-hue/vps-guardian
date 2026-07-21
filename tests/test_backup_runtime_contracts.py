from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_compose_scheduler_separates_upload_and_verified_recovery_freshness() -> None:
    script = (ROOT / "scripts" / "run-compose-backup.sh").read_text(encoding="utf-8")

    initialization = script.index("recovery-volume-init")
    backup = script.index("guardian-backup controller")
    upload_validation = script.index('result.get("uploaded") is not True')
    upload_marker = script.index('write_success_marker upload "$upload_success_marker"')
    verified_condition = script.index('json.load(handle).get("verified") is True')
    verified_marker = script.index(
        'write_success_marker verified-recovery "$verified_success_marker"'
    )

    assert initialization < backup < upload_validation < upload_marker
    assert upload_marker < verified_condition < verified_marker
    assert 're.fullmatch(r"[A-Fa-f0-9]{64}", result["checksum"])' in script
    assert 're.fullmatch(r"[A-Fa-f0-9]{64}", result["snapshot_id"])' in script
    assert 'last-upload-success.json' in script
    assert 'last-verified-recovery.json' in script
    assert "check-upload-freshness" in script
    assert "expected_kind='verified-recovery'" in script


def test_secret_refresh_never_cleans_a_tree_after_exchange_can_start() -> None:
    script = (ROOT / "scripts" / "prepare-compose-secrets.sh").read_text(encoding="utf-8")
    refresh_block = script[script.index('refresh_staged="$staged"') :]

    clear_cleanup_target = refresh_block.index("staged=''")
    execute_exchange = refresh_block.index(
        'python3 "$switch_helper" refresh "$refresh_staged" "$runtime_dir" "$previous"'
    )

    assert clear_cleanup_target < execute_exchange
    assert "the transaction trees were preserved for review" in refresh_block
