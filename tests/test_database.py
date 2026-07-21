from __future__ import annotations

from pathlib import Path

from guardian.database import build_engine


def test_sqlite_engine_creates_only_missing_parent_directory(tmp_path: Path) -> None:
    database = tmp_path / "nested" / "guardian.db"
    engine = build_engine(f"sqlite:///{database.as_posix()}")
    try:
        assert database.parent.is_dir()
        assert not database.exists()
    finally:
        engine.dispose()
