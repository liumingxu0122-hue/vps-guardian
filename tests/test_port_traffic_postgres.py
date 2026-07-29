from __future__ import annotations

import os
import subprocess
import sys
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.schema import CreateSchema, DropSchema

POSTGRES_DSN = os.environ.get("VPS_GUARDIAN_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(
    not POSTGRES_DSN,
    reason="set VPS_GUARDIAN_TEST_POSTGRES_DSN to run PostgreSQL migration tests",
)


@pytest.fixture
def isolated_postgres_migration_url() -> Iterator[URL]:
    assert POSTGRES_DSN
    control_engine = create_engine(POSTGRES_DSN, pool_pre_ping=True)
    if control_engine.dialect.name != "postgresql":
        control_engine.dispose()
        pytest.fail("VPS_GUARDIAN_TEST_POSTGRES_DSN must select PostgreSQL")
    schema = f"guardian_traffic_{uuid.uuid4().hex}"
    with control_engine.begin() as connection:
        connection.execute(CreateSchema(schema))
    url = make_url(POSTGRES_DSN).update_query_dict(
        {"options": f"-csearch_path={schema}"}
    )
    try:
        yield url
    finally:
        with control_engine.begin() as connection:
            connection.execute(DropSchema(schema, cascade=True, if_exists=True))
        control_engine.dispose()


def test_postgresql_port_traffic_migration_forward_reverse_forward(
    isolated_postgres_migration_url: URL,
) -> None:
    environment = os.environ.copy()
    environment["GUARDIAN_DATABASE_URL"] = isolated_postgres_migration_url.render_as_string(
        hide_password=False
    )

    def migrate(command: str, revision: str) -> None:
        result = subprocess.run(  # noqa: S603 - fixed Python/Alembic argv, no shell
            [
                sys.executable,
                "-m",
                "alembic",
                "-c",
                "controller/alembic.ini",
                command,
                revision,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            timeout=90,
        )
        assert result.returncode == 0, result.stderr

    migrate("upgrade", "head")
    engine = create_engine(isolated_postgres_migration_url)
    with engine.connect() as connection:
        assert connection.scalar(
            text(
                "SELECT COUNT(*) FROM information_schema.tables "
                "WHERE table_schema = current_schema() "
                "AND table_name LIKE 'port_traffic_%'"
            )
        ) == 6
        assert connection.scalar(
            text(
                "SELECT COUNT(*) FROM pg_trigger "
                "WHERE tgname IN "
                "('guardian_traffic_reset_no_update', 'guardian_traffic_reset_no_delete')"
            )
        ) == 2
    engine.dispose()

    migrate("downgrade", "0012_persistent_sessions")
    engine = create_engine(isolated_postgres_migration_url)
    with engine.connect() as connection:
        assert connection.scalar(
            text(
                "SELECT COUNT(*) FROM information_schema.tables "
                "WHERE table_schema = current_schema() "
                "AND table_name LIKE 'port_traffic_%'"
            )
        ) == 0
    engine.dispose()

    migrate("upgrade", "head")
    engine = create_engine(isolated_postgres_migration_url)
    with engine.connect() as connection:
        assert connection.scalar(
            text(
                "SELECT COUNT(*) FROM information_schema.tables "
                "WHERE table_schema = current_schema() "
                "AND table_name LIKE 'port_traffic_%'"
            )
        ) == 6
    engine.dispose()
