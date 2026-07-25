from __future__ import annotations

import os
import threading
import time
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest
from guardian import api
from guardian.database import Base
from guardian.models import Role, User
from guardian.security import hash_password
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.schema import CreateSchema, DropSchema

POSTGRES_DSN = os.environ.get("VPS_GUARDIAN_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(
    not POSTGRES_DSN,
    reason="set VPS_GUARDIAN_TEST_POSTGRES_DSN to run PostgreSQL concurrency tests",
)


@pytest.fixture
def postgres_identity_sessions() -> Iterator[sessionmaker[Session]]:
    assert POSTGRES_DSN
    control_engine = create_engine(POSTGRES_DSN, pool_pre_ping=True)
    if control_engine.dialect.name != "postgresql":
        control_engine.dispose()
        pytest.fail("VPS_GUARDIAN_TEST_POSTGRES_DSN must select PostgreSQL")
    schema = f"guardian_owner_{uuid.uuid4().hex}"
    with control_engine.begin() as connection:
        connection.execute(CreateSchema(schema))
    test_engine: Engine = control_engine.execution_options(
        schema_translate_map={None: schema}
    )
    Base.metadata.create_all(test_engine)
    sessions = sessionmaker(bind=test_engine, expire_on_commit=False, class_=Session)
    try:
        yield sessions
    finally:
        test_engine.dispose()
        with control_engine.begin() as connection:
            connection.execute(DropSchema(schema, cascade=True, if_exists=True))
        control_engine.dispose()


def test_postgresql_owner_row_lock_serializes_concurrent_demotions(
    postgres_identity_sessions: sessionmaker[Session],
) -> None:
    with postgres_identity_sessions() as database:
        owners = [
            User(
                email=f"owner-{index}@example.test",
                password_hash=hash_password(f"concurrent-owner-passphrase-{index}"),
                role=Role.owner.value,
            )
            for index in range(2)
        ]
        database.add_all(owners)
        database.commit()
        owner_ids = [owner.id for owner in owners]

    start = threading.Barrier(2)

    def demote(owner_id: str) -> str:
        with postgres_identity_sessions() as database:
            target = database.get(User, owner_id)
            assert target is not None
            start.wait(timeout=5)
            locked = api._lock_active_owners(database)
            if not any(owner.id != owner_id for owner in locked):
                database.rollback()
                return "rejected"
            target.role = Role.admin.value
            time.sleep(0.1)
            database.commit()
            return "demoted"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(demote, owner_ids))

    assert sorted(results) == ["demoted", "rejected"]
    with postgres_identity_sessions() as database:
        assert len(api._lock_active_owners(database)) == 1
