from __future__ import annotations

import os
import threading
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import UTC, datetime

import pytest
from guardian.backup import (
    RecoveryPointPromotionConflict,
    RecoveryVerificationAttestation,
    promote_recovery_point,
)
from guardian.database import Base
from guardian.models import Host, RecoveryPoint
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
def postgres_recovery_sessions() -> Iterator[sessionmaker[Session]]:
    assert POSTGRES_DSN
    control_engine = create_engine(POSTGRES_DSN, pool_pre_ping=True)
    if control_engine.dialect.name != "postgresql":
        control_engine.dispose()
        pytest.fail("VPS_GUARDIAN_TEST_POSTGRES_DSN must select PostgreSQL")
    schema = f"guardian_recovery_{uuid.uuid4().hex}"
    with control_engine.begin() as connection:
        connection.execute(CreateSchema(schema))
    test_engine: Engine = control_engine.execution_options(schema_translate_map={None: schema})
    Base.metadata.create_all(test_engine)
    sessions = sessionmaker(bind=test_engine, expire_on_commit=False, class_=Session)
    try:
        yield sessions
    finally:
        test_engine.dispose()
        with control_engine.begin() as connection:
            connection.execute(DropSchema(schema, cascade=True, if_exists=True))
        control_engine.dispose()


def attestation(evidence_digest: str) -> RecoveryVerificationAttestation:
    return RecoveryVerificationAttestation(
        verifier="postgres-recovery-race",
        verification_method="isolated_restore",
        target_environment="postgres-isolated",
        completed_at=datetime(2026, 7, 18, 12, 0, tzinfo=UTC),
        evidence_digest=evidence_digest,
    )


@pytest.mark.parametrize("same_attestation", [True, False])
def test_postgresql_recovery_promotion_serializes_concurrent_attestations(
    postgres_recovery_sessions: sessionmaker[Session],
    same_attestation: bool,
) -> None:
    snapshot_id = "a" * 64
    checksum = "b" * 64
    with postgres_recovery_sessions() as database:
        host = Host(name=f"recovery-race-{uuid.uuid4().hex}", address="192.0.2.140")
        database.add(host)
        database.flush()
        point = RecoveryPoint(
            host_id=host.id,
            service_name="controller",
            snapshot_id=snapshot_id,
            manifest={"schema_version": 1},
            checksum=checksum,
            verified=False,
        )
        database.add(point)
        database.commit()
        point_id = point.id

    first_has_update = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()
    first_attestation = attestation("c" * 64)
    second_attestation = first_attestation if same_attestation else attestation("d" * 64)

    def promote(*, first: bool) -> object:
        if not first:
            second_started.set()
        with postgres_recovery_sessions() as database:
            result = promote_recovery_point(
                database,
                recovery_point_id=point_id,
                expected_version=0,
                expected_snapshot_id=snapshot_id,
                expected_checksum=checksum,
                attestation=first_attestation if first else second_attestation,
            )
            if first:
                first_has_update.set()
                if not release_first.wait(10):
                    raise AssertionError("timed out waiting to release first promotion")
            database.commit()
            return result

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(promote, first=True)
        assert first_has_update.wait(10)
        second_future = executor.submit(promote, first=False)
        assert second_started.wait(10)
        try:
            with pytest.raises(FutureTimeoutError):
                second_future.result(timeout=0.25)
        finally:
            release_first.set()
        first_result = first_future.result(timeout=10)
        assert first_result.promoted is True  # type: ignore[attr-defined]
        if same_attestation:
            second_result = second_future.result(timeout=10)
            assert second_result.promoted is False  # type: ignore[attr-defined]
            assert second_result.attestation_digest == first_result.attestation_digest  # type: ignore[attr-defined]
        else:
            with pytest.raises(RecoveryPointPromotionConflict):
                second_future.result(timeout=10)

    with postgres_recovery_sessions() as database:
        point = database.get(RecoveryPoint, point_id)
        assert point and point.verified is True
        assert point.verification_version == 1
        assert point.attestation_digest == first_result.attestation_digest  # type: ignore[attr-defined]
