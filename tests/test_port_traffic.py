from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from guardian.config import get_settings
from guardian.database import SessionLocal
from guardian.models import (
    Agent,
    AgentTask,
    AlertInstance,
    AlertRule,
    Approval,
    Host,
    Incident,
    PortTrafficDailyRollup,
    PortTrafficHourlyRollup,
    PortTrafficPolicy,
    PortTrafficRuntimeState,
    PortTrafficSample,
    User,
)
from guardian.port_traffic import (
    PortTrafficError,
    dispatch_due_port_traffic_resets,
    ensure_policy_capacity_and_no_overlap,
    ensure_quota_alert_rules,
    ingest_observations,
    next_reset_at,
    prune_port_traffic,
    query_history,
    quota_alert_source_id,
    validate_reset_policy,
)
from guardian.schemas import PortTrafficObservation
from guardian.security import hash_password
from sqlalchemy import select


def test_helper_install_and_agent_config_preserve_fail_closed_host_binding() -> None:
    helper_installer = Path("scripts/install-port-traffic-helper.sh").read_text(
        encoding="utf-8"
    )
    agent_installer = Path("scripts/install-agent.sh").read_text(encoding="utf-8")
    assert "set -eu" in helper_installer
    assert "previous_socket_enabled=false" in helper_installer
    assert "previous_socket_active=false" in helper_installer
    assert 'if ! "$completed"; then' in helper_installer
    assert "rollback" in helper_installer
    assert "--arg host_id" in agent_installer
    assert "host_id:$host_id" in agent_installer


def test_helper_fresh_install_places_executable_before_systemd_verify() -> None:
    helper_installer = Path("scripts/install-port-traffic-helper.sh").read_text(
        encoding="utf-8"
    )
    binary_install = (
        'install -o root -g root -m 0755 "$binary" '
        "/usr/local/libexec/vps-guardian-net-helper"
    )

    assert helper_installer.index(binary_install) < helper_installer.index(
        "systemd-analyze verify"
    )


def seed_host(owner: User) -> tuple[str, str]:
    with SessionLocal() as database:
        host = Host(name="traffic-node", address="192.0.2.90")
        database.add(host)
        database.flush()
        agent = Agent(
            host_id=host.id,
            signing_public_key="A" * 44,
            certificate_fingerprint="AB" * 32,
        )
        database.add(agent)
        database.commit()
        return host.id, agent.id


def create_policy(owner: User) -> tuple[str, str]:
    host_id, _ = seed_host(owner)
    with SessionLocal() as database:
        policy = PortTrafficPolicy(
            host_id=host_id,
            name="web",
            protocol="tcp",
            direction="both",
            port_start=443,
            port_end=443,
            mode="monitor_only",
            quota_bytes=1_000,
            reset_policy={"type": "manual", "timezone": "UTC"},
            status="active",
            created_by=owner.id,
        )
        database.add(policy)
        database.flush()
        database.add(PortTrafficRuntimeState(policy_id=policy.id))
        ensure_quota_alert_rules(database, policy)
        database.commit()
        return host_id, policy.id


def test_quota_alert_source_ids_fit_the_database_column(owner: User) -> None:
    _, policy_id = create_policy(owner)

    with SessionLocal() as database:
        source_ids = database.scalars(
            select(AlertRule.source_id).where(
                AlertRule.source_type == "port_traffic_quota"
            )
        ).all()

    assert len(source_ids) == 4
    assert all(len(source_id) <= 36 for source_id in source_ids)
    assert {source_id.rsplit(":", 1)[1] for source_id in source_ids} == {
        "70",
        "85",
        "95",
        "100",
    }
    assert all(source_id.startswith(policy_id.replace("-", "")) for source_id in source_ids)


def observation(policy_id: str, *, rx: int, tx: int, generation: int = 1) -> PortTrafficObservation:
    return PortTrafficObservation(
        policy_id=policy_id,
        rx_bytes_total=rx,
        tx_bytes_total=tx,
        current_period_rx=rx,
        current_period_tx=tx,
        quota_bytes=1_000,
        counter_generation=generation,
        runtime_rule_state="active",
        shaping_state="disabled",
    )


def test_reset_policy_clamps_month_end_and_uses_timezone() -> None:
    policy = validate_reset_policy(
        {"type": "monthly", "day": 31, "timezone": "Asia/Hong_Kong"}
    )
    result = next_reset_at(policy, after=datetime(2026, 2, 1, tzinfo=UTC))

    assert result == datetime(2026, 2, 27, 16, 0, tzinfo=UTC)
    dst_boundary = next_reset_at(
        {"type": "monthly", "day": 8, "timezone": "America/New_York"},
        after=datetime(2026, 3, 7, 12, 0, tzinfo=UTC),
    )
    assert dst_boundary == datetime(2026, 3, 8, 5, 0, tzinfo=UTC)


def test_overlap_is_rejected_per_protocol(owner: User) -> None:
    host_id, _ = create_policy(owner)
    with SessionLocal() as database:
        with pytest.raises(PortTrafficError, match="overlaps"):
            ensure_policy_capacity_and_no_overlap(
                database,
                host_id=host_id,
                protocol="both",
                port_start=440,
                port_end=450,
            )
        ensure_policy_capacity_and_no_overlap(
            database,
            host_id=host_id,
            protocol="udp",
            port_start=443,
            port_end=443,
        )


def test_cumulative_samples_are_aggregated_without_weighting_and_baseline_is_omitted(
    owner: User,
) -> None:
    host_id, policy_id = create_policy(owner)
    starts_at = datetime(2026, 7, 29, 0, 0, tzinfo=UTC)
    with SessionLocal() as database:
        ingest_observations(
            database,
            host_id=host_id,
            collected_at=starts_at,
            observations=[observation(policy_id, rx=100, tx=200)],
        )
        ingest_observations(
            database,
            host_id=host_id,
            collected_at=starts_at + timedelta(minutes=1),
            observations=[observation(policy_id, rx=160, tx=290)],
        )
        database.commit()

        resolution, points = query_history(
            database,
            policy_id=policy_id,
            starts_at=starts_at,
            ends_at=starts_at + timedelta(minutes=2),
            limit=100,
        )

        assert resolution == "raw"
        assert len(database.query(PortTrafficSample).all()) == 2
        assert [(point.rx_bytes, point.tx_bytes, point.combined_bytes) for point in points] == [
            (60, 90, 150)
        ]


def test_duplicate_and_out_of_order_samples_are_idempotently_ignored(owner: User) -> None:
    host_id, policy_id = create_policy(owner)
    collected_at = datetime(2026, 7, 29, 0, 1, tzinfo=UTC)
    with SessionLocal() as database:
        latest = observation(policy_id, rx=160, tx=290)
        ingest_observations(
            database,
            host_id=host_id,
            collected_at=collected_at,
            observations=[latest],
        )
        ingest_observations(
            database,
            host_id=host_id,
            collected_at=collected_at,
            observations=[latest],
        )
        ingest_observations(
            database,
            host_id=host_id,
            collected_at=collected_at - timedelta(minutes=1),
            observations=[observation(policy_id, rx=100, tx=200)],
        )
        database.commit()
        samples = database.scalars(
            select(PortTrafficSample).where(PortTrafficSample.policy_id == policy_id)
        ).all()
        assert len(samples) == 1
        assert samples[0].rx_bytes_total == 160
        assert samples[0].tx_bytes_total == 290


def test_generation_change_is_a_discontinuity_not_zero_traffic(owner: User) -> None:
    host_id, policy_id = create_policy(owner)
    starts_at = datetime(2026, 7, 29, 0, 0, tzinfo=UTC)
    with SessionLocal() as database:
        ingest_observations(
            database,
            host_id=host_id,
            collected_at=starts_at,
            observations=[observation(policy_id, rx=500, tx=700)],
        )
        ingest_observations(
            database,
            host_id=host_id,
            collected_at=starts_at + timedelta(minutes=1),
            observations=[observation(policy_id, rx=0, tx=0, generation=2)],
        )
        database.commit()
        samples = (
            database.query(PortTrafficSample)
            .order_by(PortTrafficSample.collected_at)
            .all()
        )
        assert samples[1].discontinuity_reason == "counter_reset"
        _, points = query_history(
            database,
            policy_id=policy_id,
            starts_at=starts_at,
            ends_at=starts_at + timedelta(minutes=2),
            limit=100,
        )
        assert points[0].rx_bytes is None
        assert points[0].tx_bytes is None
        assert points[0].combined_bytes is None
        assert points[0].discontinuity_reason == "counter_reset"


def test_counter_decrease_and_missing_intervals_are_explicit(owner: User) -> None:
    host_id, policy_id = create_policy(owner)
    starts_at = datetime(2026, 7, 29, 0, 0, tzinfo=UTC)
    with SessionLocal() as database:
        ingest_observations(
            database,
            host_id=host_id,
            collected_at=starts_at,
            observations=[observation(policy_id, rx=500, tx=700)],
        )
        ingest_observations(
            database,
            host_id=host_id,
            collected_at=starts_at + timedelta(minutes=4),
            observations=[observation(policy_id, rx=10, tx=20)],
        )
        database.commit()
        _, points = query_history(
            database,
            policy_id=policy_id,
            starts_at=starts_at,
            ends_at=starts_at + timedelta(minutes=5),
            limit=100,
        )
        assert points[0].rx_bytes is None
        assert points[0].tx_bytes is None
        assert points[0].discontinuity_reason == "counter_wrap"
        assert points[0].missing_intervals == 3


def test_quota_alert_uses_hysteresis_and_existing_recovery_state_machine(
    owner: User,
) -> None:
    host_id, policy_id = create_policy(owner)
    starts_at = datetime(2026, 7, 29, 0, 0, tzinfo=UTC)
    with SessionLocal() as database:
        ingest_observations(
            database,
            host_id=host_id,
            collected_at=starts_at,
            observations=[observation(policy_id, rx=500, tx=300)],
        )
        database.flush()
        rule = database.scalar(
            select(AlertRule).where(
                AlertRule.source_id == quota_alert_source_id(policy_id, 70)
            )
        )
        assert rule is not None
        alert = database.query(AlertInstance).filter_by(rule_id=rule.id).one()
        assert alert.state == "firing"

        for offset in (1, 2):
            recovered = observation(policy_id, rx=500 + offset, tx=300 + offset)
            recovered.current_period_rx = 330
            recovered.current_period_tx = 330
            ingest_observations(
                database,
                host_id=host_id,
                collected_at=starts_at + timedelta(minutes=offset),
                observations=[recovered],
            )
        database.flush()
        assert alert.state == "resolved"


def test_api_starts_monitor_only_and_risky_change_only_creates_approval(
    client: TestClient,
    owner_token: str,
    owner: User,
) -> None:
    host_id, _ = seed_host(owner)
    headers = {"Authorization": f"Bearer {owner_token}"}
    unsafe_create = client.post(
        f"/api/v1/hosts/{host_id}/port-traffic/policies",
        headers=headers,
        json={
            "name": "unsafe-scheduled-create",
            "protocol": "tcp",
            "direction": "both",
            "port_start": 8443,
            "port_end": 8443,
            "reset_policy": {"type": "monthly", "day": 1, "timezone": "UTC"},
        },
    )
    assert unsafe_create.status_code == 409
    assert "independently approved" in unsafe_create.json()["detail"]

    created = client.post(
        f"/api/v1/hosts/{host_id}/port-traffic/policies",
        headers=headers,
        json={
            "name": "https",
            "protocol": "tcp",
            "direction": "both",
            "port_start": 443,
            "port_end": 443,
            "quota_bytes": 10_000,
        },
    )
    assert created.status_code == 201, created.text
    policy_id = created.json()["id"]
    with SessionLocal() as database:
        tasks_before = database.query(AgentTask).count()
        task = database.query(AgentTask).one()
        assert task.action == "port_traffic_apply"
        assert task.approval_id is None
        assert task.parameters["mode"] == "monitor_only"

    requested = client.post(
        f"/api/v1/hosts/{host_id}/port-traffic/policies/{policy_id}/change-requests",
        headers=headers,
        json={
            "mode": "enforcing",
            "egress_rate_bps": 1_000_000,
            "reason": "approved test of quota enforcement",
        },
    )
    assert requested.status_code == 202, requested.text
    assert requested.json()["status"] == "pending"
    assert requested.json()["risk_level"] == 3
    with SessionLocal() as database:
        assert database.query(AgentTask).count() == tasks_before

    scheduled = client.post(
        f"/api/v1/hosts/{host_id}/port-traffic/policies/{policy_id}/change-requests",
        headers=headers,
        json={
            "mode": "monitor_only",
            "egress_rate_bps": None,
            "reset_policy": {"type": "monthly", "day": 31, "timezone": "UTC"},
            "reason": "approved monthly billing boundary",
        },
    )
    assert scheduled.status_code == 202
    assert scheduled.json()["action_name"] == "port_traffic_reset_schedule_change"
    with SessionLocal() as database:
        assert database.query(AgentTask).count() == tasks_before


def test_host_group_scope_is_enforced(
    client: TestClient,
    owner_token: str,
    owner: User,
) -> None:
    host_id, _ = seed_host(owner)
    with SessionLocal() as database:
        host = database.get(Host, host_id)
        scoped_owner = database.get(User, owner.id)
        assert host and scoped_owner
        host.group_name = "edge"
        scoped_owner.scopes = ["hosts:read", "hosts:group:database"]
        database.commit()

    response = client.get(
        f"/api/v1/hosts/{host_id}/port-traffic/policies",
        headers={"Authorization": f"Bearer {owner_token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "host group scope denied"


def test_policy_update_revalidates_overlap_and_history_query_bounds(
    client: TestClient,
    owner_token: str,
    owner: User,
) -> None:
    host_id, _ = seed_host(owner)
    headers = {"Authorization": f"Bearer {owner_token}"}
    first = client.post(
        f"/api/v1/hosts/{host_id}/port-traffic/policies",
        headers=headers,
        json={
            "name": "tcp-443",
            "protocol": "tcp",
            "direction": "both",
            "port_start": 443,
            "port_end": 443,
        },
    )
    second = client.post(
        f"/api/v1/hosts/{host_id}/port-traffic/policies",
        headers=headers,
        json={
            "name": "udp-443",
            "protocol": "udp",
            "direction": "both",
            "port_start": 443,
            "port_end": 443,
        },
    )
    assert first.status_code == second.status_code == 201

    overlap = client.patch(
        f"/api/v1/hosts/{host_id}/port-traffic/policies/{second.json()['id']}",
        headers=headers,
        json={"protocol": "both"},
    )
    assert overlap.status_code == 409
    assert "overlaps" in overlap.json()["detail"]

    now = datetime.now(UTC)
    too_wide = client.get(
        f"/api/v1/hosts/{host_id}/port-traffic/policies/{first.json()['id']}/history",
        headers=headers,
        params={
            "starts_at": (now - timedelta(days=401)).isoformat(),
            "ends_at": now.isoformat(),
        },
    )
    assert too_wide.status_code == 422

    excessive_page = client.get(
        f"/api/v1/hosts/{host_id}/port-traffic/policies/{first.json()['id']}/history",
        headers=headers,
        params={
            "starts_at": (now - timedelta(hours=1)).isoformat(),
            "ends_at": now.isoformat(),
            "limit": 10_001,
        },
    )
    assert excessive_page.status_code == 422
    excessive_policy_page = client.get(
        f"/api/v1/hosts/{host_id}/port-traffic/policies",
        headers=headers,
        params={"limit": 65},
    )
    assert excessive_policy_page.status_code == 422


def test_due_reset_schedule_reuses_independently_approved_provenance_once(
    owner: User,
) -> None:
    host_id, policy_id = create_policy(owner)
    due = datetime(2026, 7, 1, tzinfo=UTC)
    with SessionLocal() as database:
        approver = User(
            email="schedule-approver@example.test",
            password_hash="not-used-in-this-test",
            role="owner",
        )
        incident = Incident(
            title="Approved recurring traffic reset",
            fault_type="planned_port_traffic_change",
            severity=2,
        )
        database.add_all([approver, incident])
        database.flush()
        approval = Approval(
            incident_id=incident.id,
            action_name="port_traffic_reset_schedule_change",
            risk_level=3,
            status="executed",
            requested_by=owner.id,
            decided_by=approver.id,
        )
        database.add(approval)
        database.flush()
        policy = database.get(PortTrafficPolicy, policy_id)
        runtime = database.get(PortTrafficRuntimeState, policy_id)
        assert policy and runtime
        policy.reset_policy = {
            "type": "monthly",
            "day": 1,
            "timezone": "UTC",
        }
        policy.reset_approval_id = approval.id
        policy.reset_requested_by = owner.id
        policy.reset_approved_by = approver.id
        runtime.next_reset_at = due
        database.commit()

        queued = dispatch_due_port_traffic_resets(
            database,
            settings=get_settings(),
            now=due + timedelta(minutes=1),
        )
        database.commit()
        assert queued == 1
        task = database.scalar(
            select(AgentTask).where(AgentTask.action == "port_traffic_reset")
        )
        assert task is not None
        assert task.approval_id == approval.id
        assert task.requester_id == owner.id
        assert task.approver_id == approver.id
        assert task.parameters["second_confirmation"] == "confirmed"
        assert task.parameters["scheduled_for"] == due.isoformat()

        assert (
            dispatch_due_port_traffic_resets(
                database,
                settings=get_settings(),
                now=due + timedelta(minutes=2),
            )
            == 0
        )


def test_reset_schedule_approval_requires_independent_exact_confirmation(
    client: TestClient,
    owner_token: str,
    owner: User,
) -> None:
    host_id, _ = seed_host(owner)
    requester_headers = {"Authorization": f"Bearer {owner_token}"}
    created = client.post(
        f"/api/v1/hosts/{host_id}/port-traffic/policies",
        headers=requester_headers,
        json={
            "name": "billing",
            "protocol": "tcp",
            "direction": "both",
            "port_start": 9443,
            "port_end": 9443,
        },
    )
    assert created.status_code == 201
    policy_id = created.json()["id"]
    requested = client.post(
        f"/api/v1/hosts/{host_id}/port-traffic/policies/{policy_id}/change-requests",
        headers=requester_headers,
        json={
            "mode": "monitor_only",
            "reset_policy": {"type": "monthly", "day": 1, "timezone": "UTC"},
            "reason": "monthly billing boundary",
        },
    )
    assert requested.status_code == 202
    approval_id = requested.json()["id"]

    approver_password = "independent-schedule-approver-password"
    with SessionLocal() as database:
        database.add(
            User(
                email="independent-approver@example.test",
                password_hash=hash_password(approver_password),
                role="owner",
            )
        )
        database.commit()
    login = client.post(
        "/api/v1/auth/login",
        json={
            "email": "independent-approver@example.test",
            "password": approver_password,
        },
    )
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    presentation = client.get(
        f"/api/v1/approvals/{approval_id}/presentation",
        headers=headers,
    )
    assert presentation.status_code == 200
    assert {
        "key": "policy_id",
        "value": policy_id,
        "tone": "neutral",
    } in presentation.json()["impact_facts"]
    decision = {
        "decision": "approved",
        "confirmation": "wrong",
        "current_password": approver_password,
        "rollback_confirmed": True,
    }
    wrong = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        headers=headers,
        json=decision,
    )
    assert wrong.status_code == 409
    decision["confirmation"] = f"SCHEDULE {policy_id}"
    approved = client.post(
        f"/api/v1/approvals/{approval_id}/decision",
        headers=headers,
        json=decision,
    )
    assert approved.status_code == 200
    with SessionLocal() as database:
        task = database.scalar(
            select(AgentTask).where(AgentTask.approval_id == approval_id)
        )
        assert task is not None
        assert task.requester_id != task.approver_id


def test_raw_hourly_and_daily_retention_are_independently_bounded(owner: User) -> None:
    host_id, policy_id = create_policy(owner)
    now = datetime(2026, 7, 29, tzinfo=UTC)
    with SessionLocal() as database:
        database.add_all(
            [
                PortTrafficSample(
                    policy_id=policy_id,
                    host_id=host_id,
                    collected_at=now - timedelta(days=8),
                    rx_bytes_total=1,
                    tx_bytes_total=1,
                    current_period_rx=1,
                    current_period_tx=1,
                    counter_generation=1,
                    runtime_rule_state="active",
                    shaping_state="disabled",
                ),
                PortTrafficHourlyRollup(
                    policy_id=policy_id,
                    host_id=host_id,
                    bucket_start=now - timedelta(days=91),
                ),
                PortTrafficDailyRollup(
                    policy_id=policy_id,
                    host_id=host_id,
                    bucket_start=now - timedelta(days=401),
                ),
            ]
        )
        database.commit()
        assert prune_port_traffic(database, now=now) == {
            "raw": 1,
            "hourly": 1,
            "daily": 1,
        }
