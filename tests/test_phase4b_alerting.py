from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from guardian.alerting import acknowledge_alert, observe_alert, silence_alert
from guardian.database import SessionLocal
from guardian.enrollment import (
    EnrollmentTokenError,
    consume_enrollment_token,
    issue_enrollment_token,
)
from guardian.models import (
    AlertInstance,
    AlertRule,
    AlertState,
    AlertTransition,
    EnrollmentToken,
    Host,
    NotificationChannel,
    NotificationDelivery,
    Role,
    User,
)
from sqlalchemy import func, select


def create_owner() -> User:
    return User(email="phase4b-owner@example.test", password_hash="unused", role=Role.owner.value)


def test_enrollment_token_is_hashed_single_use_and_bound_to_host() -> None:
    now = datetime(2026, 7, 22, 0, 0, tzinfo=UTC)
    with SessionLocal() as db:
        owner = create_owner()
        host = Host(name="pending-node", address="192.0.2.44")
        db.add_all([owner, host])
        db.flush()
        issued = issue_enrollment_token(db, host=host, actor=owner, now=now)
        db.commit()

        stored_hash = db.scalar(select(func.max(EnrollmentToken.token_hash)))
        assert stored_hash is not None
        assert issued.value not in stored_hash

        _, consumed_host = consume_enrollment_token(db, value=issued.value, now=now)
        assert consumed_host.id == host.id
        db.commit()
        with pytest.raises(EnrollmentTokenError, match="already used"):
            consume_enrollment_token(db, value=issued.value, now=now)


def test_expired_or_disabled_enrollment_target_is_rejected() -> None:
    now = datetime(2026, 7, 22, 0, 0, tzinfo=UTC)
    with SessionLocal() as db:
        owner = create_owner()
        host = Host(name="disabled-node", address="192.0.2.45")
        db.add_all([owner, host])
        db.flush()
        issued = issue_enrollment_token(
            db, host=host, actor=owner, ttl=timedelta(minutes=1), now=now
        )
        db.commit()
        with pytest.raises(EnrollmentTokenError, match="expired"):
            consume_enrollment_token(db, value=issued.value, now=now + timedelta(minutes=2))

        issued = issue_enrollment_token(db, host=host, actor=owner, now=now)
        host.enabled = False
        db.commit()
        with pytest.raises(EnrollmentTokenError, match="unavailable"):
            consume_enrollment_token(db, value=issued.value, now=now)


def test_alert_state_hysteresis_deduplication_and_restart_persistence() -> None:
    started = datetime(2026, 7, 22, 0, 0, tzinfo=UTC)
    with SessionLocal() as db:
        rule = AlertRule(
            name="api-health",
            source_type="service_check",
            source_id="check-1",
            failure_threshold=2,
            recovery_threshold=2,
            repeat_interval_seconds=3600,
        )
        channel = NotificationChannel(
            name="mock-webhook",
            kind="webhook",
            configuration={"endpoint_env": "GUARDIAN_TEST_WEBHOOK_URL"},
        )
        db.add_all([rule, channel])
        db.flush()

        pending = observe_alert(
            db, rule=rule, success=False, summary="timeout", now=started
        )
        assert pending.alert.state == AlertState.pending.value
        assert pending.notification_scheduled is False
        firing = observe_alert(
            db,
            rule=rule,
            success=False,
            summary="timeout",
            now=started + timedelta(seconds=30),
        )
        assert firing.alert.state == AlertState.firing.value
        assert firing.notification_scheduled is True
        duplicate = observe_alert(
            db,
            rule=rule,
            success=False,
            summary="timeout",
            now=started + timedelta(minutes=1),
        )
        assert duplicate.changed is False
        assert duplicate.notification_scheduled is False
        alert_id = firing.alert.id
        rule_id = rule.id
        db.commit()

    with SessionLocal() as restarted:
        rule = restarted.get(AlertRule, rule_id)
        alert = restarted.get(AlertInstance, alert_id)
        assert rule is not None and alert is not None
        assert alert.state == AlertState.firing.value
        assert restarted.scalar(select(func.count(NotificationDelivery.id))) == 1
        first_recovery = observe_alert(
            restarted,
            rule=rule,
            success=True,
            summary="healthy",
            now=started + timedelta(minutes=2),
        )
        assert first_recovery.alert.state == AlertState.firing.value
        recovered = observe_alert(
            restarted,
            rule=rule,
            success=True,
            summary="healthy",
            now=started + timedelta(minutes=3),
        )
        assert recovered.alert.state == AlertState.resolved.value
        assert recovered.notification_scheduled is True
        assert restarted.scalar(select(func.count(NotificationDelivery.id))) == 2
        assert restarted.scalar(select(func.count(AlertTransition.id))) == 3


def test_acknowledge_and_silence_are_explicit_persistent_states() -> None:
    now = datetime(2026, 7, 22, 0, 0, tzinfo=UTC)
    with SessionLocal() as db:
        owner = create_owner()
        rule = AlertRule(
            name="host-offline",
            source_type="host_liveness",
            source_id="host-1",
            failure_threshold=1,
            recovery_threshold=2,
        )
        db.add_all([owner, rule])
        db.flush()
        observed = observe_alert(db, rule=rule, success=False, summary="offline", now=now)
        assert acknowledge_alert(db, alert=observed.alert, actor=owner, now=now) is True
        assert observed.alert.state == AlertState.acknowledged.value
        silence_alert(
            db,
            alert=observed.alert,
            actor=owner,
            reason="planned work",
            until=now + timedelta(hours=1),
            now=now,
        )
        assert observed.alert.state == AlertState.silenced.value
