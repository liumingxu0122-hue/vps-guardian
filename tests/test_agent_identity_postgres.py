from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
import threading
import time
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException, Request, Response
from guardian import api
from guardian.agent_security import build_agent_signing_message
from guardian.config import Settings
from guardian.database import Base
from guardian.enrollment import (
    EnrollmentTokenError,
    consume_enrollment_token,
    issue_enrollment_token,
)
from guardian.models import (
    Agent,
    AgentIdentity,
    AgentIdentityState,
    AgentTask,
    AuditLog,
    Host,
    MetricSnapshot,
    Role,
    User,
)
from guardian.schemas import (
    AgentHeartbeat,
    AgentIdentityActivateRequest,
    AgentIdentityRetireRequest,
    AgentIdentityRevokeRequest,
    AgentIdentityValidateRequest,
    AgentRotateRequest,
)
from sqlalchemy import create_engine, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.schema import CreateSchema, DropSchema

POSTGRES_DSN = os.environ.get("VPS_GUARDIAN_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(
    not POSTGRES_DSN,
    reason="set VPS_GUARDIAN_TEST_POSTGRES_DSN to run PostgreSQL concurrency tests",
)


@pytest.fixture
def postgres_sessions() -> Iterator[sessionmaker[Session]]:
    assert POSTGRES_DSN
    control_engine = create_engine(POSTGRES_DSN, pool_pre_ping=True)
    if control_engine.dialect.name != "postgresql":
        control_engine.dispose()
        pytest.fail("VPS_GUARDIAN_TEST_POSTGRES_DSN must select PostgreSQL")
    schema = f"guardian_identity_{uuid.uuid4().hex}"
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


def public_key_base64(private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode()


def request_with_body(body: bytes, headers: dict[str, str]) -> Request:
    consumed = False

    async def receive() -> dict[str, object]:
        nonlocal consumed
        if consumed:
            return {"type": "http.request", "body": b"", "more_body": False}
        consumed = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [
                (key.lower().encode("ascii"), value.encode("ascii"))
                for key, value in headers.items()
            ],
            "client": ("127.0.0.1", 12345),
        },
        receive,
    )


def signed_request(
    *,
    agent_id: str,
    private_key: Ed25519PrivateKey,
    fingerprint: str,
    body: bytes,
) -> Request:
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    signature = base64.b64encode(
        private_key.sign(build_agent_signing_message(agent_id, timestamp, nonce, body))
    ).decode()
    return request_with_body(
        body,
        {
            "Content-Type": "application/json",
            "X-Agent-Timestamp": timestamp,
            "X-Agent-Nonce": nonce,
            "X-Agent-Signature": signature,
            "X-Client-Cert-Fingerprint": fingerprint,
        },
    )


def owner_request() -> Request:
    return request_with_body(b"", {})


def seed_dual_identity(
    sessions: sessionmaker[Session], *, pending_verified: bool
) -> tuple[str, str, Ed25519PrivateKey, Ed25519PrivateKey, User]:
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    owner = User(
        id=str(uuid.uuid4()),
        email=f"owner-{uuid.uuid4().hex}@example.test",
        password_hash="unused",
        role=Role.owner.value,
    )
    with sessions() as database:
        host = Host(name=f"postgres-race-{uuid.uuid4().hex}", address="192.0.2.120")
        database.add_all([owner, host])
        database.flush()
        agent = Agent(
            host_id=host.id,
            signing_public_key=public_key_base64(old_key),
            certificate_fingerprint="AA" * 32,
            certificate_serial="1000",
            identity_version=2,
        )
        database.add(agent)
        database.flush()
        database.add_all(
            [
                AgentIdentity(
                    agent_id=agent.id,
                    generation=1,
                    state=AgentIdentityState.active.value,
                    signing_public_key=agent.signing_public_key,
                    certificate_fingerprint=agent.certificate_fingerprint,
                    certificate_serial=agent.certificate_serial,
                    verified_at=now,
                    activated_at=now,
                ),
                AgentIdentity(
                    agent_id=agent.id,
                    generation=2,
                    state=AgentIdentityState.pending.value,
                    signing_public_key=public_key_base64(new_key),
                    certificate_fingerprint="BB" * 32,
                    certificate_serial="2000",
                    expires_at=now + timedelta(minutes=15),
                    verified_at=now if pending_verified else None,
                    successful_heartbeats=2 if pending_verified else 0,
                ),
            ]
        )
        database.flush()
        pending_id = database.scalar(
            select(AgentIdentity.id).where(
                AgentIdentity.agent_id == agent.id,
                AgentIdentity.state == AgentIdentityState.pending.value,
            )
        )
        assert pending_id
        database.commit()
        return agent.id, pending_id, old_key, new_key, owner


def heartbeat_payload() -> tuple[bytes, AgentHeartbeat]:
    body = json.dumps(
        {
            "collected_at": datetime.now(UTC).isoformat(),
            "version": "postgres-concurrency-test",
            "metrics": {"cpu_percent": 7.0},
            "services": [],
            "events": [],
        },
        separators=(",", ":"),
    ).encode()
    return body, AgentHeartbeat.model_validate_json(body)


def seed_active_only(
    sessions: sessionmaker[Session],
) -> tuple[str, User]:
    agent_id, pending_id, _, _, owner = seed_dual_identity(sessions, pending_verified=False)
    with sessions() as database:
        pending = database.get(AgentIdentity, pending_id)
        agent = database.get(Agent, agent_id)
        assert pending and agent
        database.delete(pending)
        agent.identity_version = 1
        database.commit()
    return agent_id, owner


def test_concurrent_enrollment_token_consumption_has_exactly_one_winner(
    postgres_sessions: sessionmaker[Session],
) -> None:
    with postgres_sessions() as database:
        owner = User(
            email=f"owner-{uuid.uuid4().hex}@example.test",
            password_hash="unused",
            role=Role.owner.value,
        )
        host = Host(name=f"bootstrap-{uuid.uuid4().hex}", address="192.0.2.120")
        database.add_all([owner, host])
        database.flush()
        issued = issue_enrollment_token(database, host=host, actor=owner)
        host_id = host.id
        database.commit()

    barrier = threading.Barrier(2)

    def consume() -> str:
        with postgres_sessions() as database:
            barrier.wait(timeout=10)
            try:
                consume_enrollment_token(
                    database,
                    value=issued.value,
                    expected_host_id=host_id,
                )
                database.commit()
                return "accepted"
            except EnrollmentTokenError:
                database.rollback()
                return "rejected"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _: consume(), range(2)))

    assert sorted(outcomes) == ["accepted", "rejected"]


def test_postgresql_partial_indexes_reject_second_live_identity(
    postgres_sessions: sessionmaker[Session],
) -> None:
    agent_id, _, _, _, _ = seed_dual_identity(postgres_sessions, pending_verified=False)
    with postgres_sessions() as database:
        duplicate = AgentIdentity(
            agent_id=agent_id,
            generation=3,
            state=AgentIdentityState.pending.value,
            signing_public_key=public_key_base64(Ed25519PrivateKey.generate()),
            certificate_fingerprint="CC" * 32,
            certificate_serial="3000",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )
        database.add(duplicate)
        with pytest.raises(IntegrityError):
            database.commit()


def test_concurrent_prepare_creates_exactly_one_pending_identity(
    postgres_sessions: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_id, owner = seed_active_only(postgres_sessions)
    settings = Settings.model_construct(
        environment="test",
        agent_pending_identity_ttl_minutes=15,
    )
    first_holds_lock = threading.Event()
    release_first = threading.Event()
    second_attempted_lock = threading.Event()
    thread_role = threading.local()
    real_lock = api.lock_active_agent

    def pause_first_lock(database: Session, locked_agent_id: str) -> Agent:
        if getattr(thread_role, "second", False):
            second_attempted_lock.set()
        locked = real_lock(database, locked_agent_id)
        if not getattr(thread_role, "second", False):
            first_holds_lock.set()
            if not release_first.wait(10):
                raise AssertionError("timed out waiting to release first prepare")
        return locked

    monkeypatch.setattr(api, "lock_active_agent", pause_first_lock)
    first_key = Ed25519PrivateKey.generate()
    second_key = Ed25519PrivateKey.generate()

    def prepare(*, second: bool) -> AgentIdentity:
        thread_role.second = second
        payload = AgentRotateRequest(
            rotation_id=str(uuid.uuid4()),
            expected_version=1,
            signing_public_key=public_key_base64(second_key if second else first_key),
            certificate_fingerprint=("DD" if second else "CC") * 32,
            certificate_serial="4000" if second else "3000",
        )
        with postgres_sessions() as database:
            return api.prepare_agent_identity(
                agent_id,
                payload,
                owner_request(),
                database,
                settings,
                owner,
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(prepare, second=False)
        assert first_holds_lock.wait(10)
        second_future = executor.submit(prepare, second=True)
        assert second_attempted_lock.wait(10)
        try:
            with pytest.raises(FutureTimeoutError):
                second_future.result(timeout=0.25)
        finally:
            release_first.set()
        assert first_future.result(timeout=10).state == AgentIdentityState.pending.value
        with pytest.raises(HTTPException) as conflict:
            second_future.result(timeout=10)
    assert conflict.value.status_code == 409
    assert conflict.value.detail == "agent already has a pending identity"

    with postgres_sessions() as database:
        pending_count = database.scalar(
            select(func.count())
            .select_from(AgentIdentity)
            .where(
                AgentIdentity.agent_id == agent_id,
                AgentIdentity.state == AgentIdentityState.pending.value,
            )
        )
        agent = database.get(Agent, agent_id)
        assert pending_count == 1
        assert agent and agent.identity_version == 2


def test_postgresql_rotation_id_replay_and_conflict_audit(
    postgres_sessions: sessionmaker[Session],
) -> None:
    agent_id, owner = seed_active_only(postgres_sessions)
    settings = Settings.model_construct(
        environment="test",
        agent_pending_identity_ttl_minutes=15,
    )
    rotation_id = str(uuid.uuid4())
    signing_key = Ed25519PrivateKey.generate()
    payload = AgentRotateRequest(
        rotation_id=rotation_id,
        expected_version=1,
        signing_public_key=public_key_base64(signing_key),
        certificate_fingerprint="CC" * 32,
        certificate_serial="3000",
    )
    with postgres_sessions() as database:
        winner = api.prepare_agent_identity(
            agent_id,
            payload,
            owner_request(),
            database,
            settings,
            owner,
        )
    with postgres_sessions() as database:
        replay = api.prepare_agent_identity(
            agent_id,
            payload,
            owner_request(),
            database,
            settings,
            owner,
        )
    assert replay.id == winner.id

    mismatched = AgentRotateRequest(
        rotation_id=rotation_id,
        expected_version=1,
        signing_public_key=public_key_base64(Ed25519PrivateKey.generate()),
        certificate_fingerprint="DD" * 32,
        certificate_serial="4000",
    )
    with postgres_sessions() as database, pytest.raises(HTTPException) as conflict:
        api.prepare_agent_identity(
            agent_id,
            mismatched,
            owner_request(),
            database,
            settings,
            owner,
        )
    assert conflict.value.status_code == 409
    assert conflict.value.detail == "rotation id payload conflict"

    with postgres_sessions() as database:
        agent = database.get(Agent, agent_id)
        audits = list(
            database.scalars(
                select(AuditLog).where(
                    AuditLog.action.in_(
                        [
                            "agent.identity_pending_created",
                            "agent.identity_rotation_replayed",
                            "agent.identity_rotation_conflict",
                        ]
                    )
                )
            )
        )
        assert agent and agent.identity_version == 2
        assert {entry.action for entry in audits} == {
            "agent.identity_pending_created",
            "agent.identity_rotation_replayed",
            "agent.identity_rotation_conflict",
        }
        assert all(entry.details.get("agent_id") == agent_id for entry in audits)


@pytest.mark.parametrize("transition", ["activate", "revoke"])
def test_active_heartbeat_is_linearized_before_identity_transition(
    postgres_sessions: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
    transition: str,
) -> None:
    agent_id, pending_id, old_key, _, owner = seed_dual_identity(
        postgres_sessions, pending_verified=True
    )
    now = datetime.now(UTC)
    with postgres_sessions() as database:
        database.add(
            AgentTask(
                agent_id=agent_id,
                action="local_health_check",
                parameters={},
                status="pending",
                nonce=secrets.token_urlsafe(24),
                expires_at=now + timedelta(minutes=5),
                signature="test-signature",
            )
        )
        database.commit()

    settings = Settings.model_construct(environment="test", nonce_ttl_seconds=300)
    heartbeat_holds_lock = threading.Event()
    release_heartbeat = threading.Event()
    transition_at_lock = threading.Event()
    thread_role = threading.local()
    real_verify = api.verify_agent_request
    real_lock = api.lock_active_agent

    def pause_verified_heartbeat(**kwargs: object) -> AgentIdentity:
        identity = real_verify(**kwargs)  # type: ignore[arg-type]
        heartbeat_holds_lock.set()
        if not release_heartbeat.wait(10):
            raise AssertionError("timed out waiting to release heartbeat transaction")
        return identity

    def observe_transition_lock(database: Session, locked_agent_id: str) -> Agent:
        if getattr(thread_role, "transition", False):
            transition_at_lock.set()
        return real_lock(database, locked_agent_id)

    monkeypatch.setattr(api, "verify_agent_request", pause_verified_heartbeat)
    monkeypatch.setattr(api, "lock_active_agent", observe_transition_lock)

    def send_heartbeat() -> dict[str, object]:
        body, payload = heartbeat_payload()
        with postgres_sessions() as database:
            return asyncio.run(
                api.agent_heartbeat(
                    agent_id,
                    payload,
                    signed_request(
                        agent_id=agent_id,
                        private_key=old_key,
                        fingerprint="AA" * 32,
                        body=body,
                    ),
                    Response(),
                    database,
                    settings,
                )
            )

    def change_identity() -> object:
        thread_role.transition = True
        with postgres_sessions() as database:
            if transition == "activate":
                return api.activate_agent_identity(
                    agent_id,
                    pending_id,
                    AgentIdentityActivateRequest(expected_version=2),
                    owner_request(),
                    database,
                    owner,
                )
            database.add(
                AuditLog(
                    actor_id=None,
                    action="gateway.crl_publication",
                    resource_type="agent_ca_crl",
                    resource_id="6102",
                    outcome="success",
                    details={
                        "crl_number": "6102",
                        "sha256": "ef" * 32,
                        "certificate_serial": "1000",
                    },
                )
            )
            database.flush()
            return api.revoke_agent(
                agent_id,
                AgentIdentityRevokeRequest(
                    expected_version=2,
                    crl_number=6102,
                    crl_sha256="ef" * 32,
                ),
                owner_request(),
                database,
                owner,
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        heartbeat_future = executor.submit(send_heartbeat)
        assert heartbeat_holds_lock.wait(10)
        transition_future = executor.submit(change_identity)
        assert transition_at_lock.wait(10)
        try:
            with pytest.raises(FutureTimeoutError):
                transition_future.result(timeout=0.25)
        finally:
            release_heartbeat.set()
        heartbeat_result = heartbeat_future.result(timeout=10)
        transition_future.result(timeout=10)

    assert heartbeat_result["accepted"] is True
    assert len(heartbeat_result["tasks"]) == 1  # type: ignore[arg-type]
    with postgres_sessions() as database:
        assert database.scalar(select(func.count()).select_from(MetricSnapshot)) == 1
        task = database.scalar(select(AgentTask).where(AgentTask.agent_id == agent_id))
        agent = database.get(Agent, agent_id)
        assert task and task.status == "delivered"
        assert agent
        if transition == "activate":
            assert agent.certificate_fingerprint == "BB" * 32
            assert agent.revoked_at is None
        else:
            assert agent.revoked_at is not None

    body, payload = heartbeat_payload()
    if transition == "activate":
        with postgres_sessions() as database:
            retiring_result = asyncio.run(
                api.agent_heartbeat(
                    agent_id,
                    payload,
                    signed_request(
                        agent_id=agent_id,
                        private_key=old_key,
                        fingerprint="AA" * 32,
                        body=body,
                    ),
                    Response(),
                    database,
                    settings,
                )
            )
        assert retiring_result["accepted"] is True
        assert retiring_result["identity_state"] == AgentIdentityState.retiring.value
    else:
        with postgres_sessions() as database, pytest.raises(HTTPException) as rejected:
            asyncio.run(
                api.agent_heartbeat(
                    agent_id,
                    payload,
                    signed_request(
                        agent_id=agent_id,
                        private_key=old_key,
                        fingerprint="AA" * 32,
                        body=body,
                    ),
                    Response(),
                    database,
                    settings,
                )
            )
        assert rejected.value.status_code == 404


def test_pending_validation_is_linearized_before_concurrent_retirement(
    postgres_sessions: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_id, pending_id, _, pending_key, owner = seed_dual_identity(
        postgres_sessions, pending_verified=False
    )
    settings = Settings.model_construct(environment="test", nonce_ttl_seconds=300)
    validation_holds_lock = threading.Event()
    release_validation = threading.Event()
    retirement_at_lock = threading.Event()
    thread_role = threading.local()
    real_verify = api.verify_agent_request
    real_lock = api.lock_active_agent

    def pause_validated_identity(**kwargs: object) -> AgentIdentity:
        identity = real_verify(**kwargs)  # type: ignore[arg-type]
        validation_holds_lock.set()
        if not release_validation.wait(10):
            raise AssertionError("timed out waiting to release validation transaction")
        return identity

    def observe_retirement_lock(database: Session, locked_agent_id: str) -> Agent:
        if getattr(thread_role, "retirement", False):
            retirement_at_lock.set()
        return real_lock(database, locked_agent_id)

    monkeypatch.setattr(api, "verify_agent_request", pause_validated_identity)
    monkeypatch.setattr(api, "lock_active_agent", observe_retirement_lock)
    body = b'{"expected_version":2}'

    def validate() -> AgentIdentity:
        with postgres_sessions() as database:
            return asyncio.run(
                api.validate_pending_agent_identity(
                    agent_id,
                    pending_id,
                    AgentIdentityValidateRequest(expected_version=2),
                    signed_request(
                        agent_id=agent_id,
                        private_key=pending_key,
                        fingerprint="BB" * 32,
                        body=body,
                    ),
                    database,
                    settings,
                )
            )

    def retire() -> AgentIdentity:
        thread_role.retirement = True
        with postgres_sessions() as database:
            return api.retire_pending_agent_identity(
                agent_id,
                pending_id,
                AgentIdentityRetireRequest(
                    expected_version=2,
                    reason_code="rotation.cancelled",
                ),
                owner_request(),
                database,
                owner,
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        validation_future = executor.submit(validate)
        assert validation_holds_lock.wait(10)
        retirement_future = executor.submit(retire)
        assert retirement_at_lock.wait(10)
        try:
            with pytest.raises(FutureTimeoutError):
                retirement_future.result(timeout=0.25)
        finally:
            release_validation.set()
        assert validation_future.result(timeout=10).verified_at is not None
        assert retirement_future.result(timeout=10).state == AgentIdentityState.retired.value

    with postgres_sessions() as database:
        identity = database.get(AgentIdentity, pending_id)
        agent = database.get(Agent, agent_id)
        possession_audits = database.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.action == "agent.identity_possession_verified")
        )
        assert identity and identity.state == AgentIdentityState.retired.value
        assert identity.verified_at is not None
        assert agent and agent.identity_version == 3
        assert possession_audits == 1

    with postgres_sessions() as database, pytest.raises(HTTPException) as rejected:
        asyncio.run(
            api.validate_pending_agent_identity(
                agent_id,
                pending_id,
                AgentIdentityValidateRequest(expected_version=3),
                signed_request(
                    agent_id=agent_id,
                    private_key=pending_key,
                    fingerprint="BB" * 32,
                    body=b'{"expected_version":3}',
                ),
                database,
                settings,
            )
        )
    assert rejected.value.status_code == 409
    assert rejected.value.detail == "identity is not pending"
