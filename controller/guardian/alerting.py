from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian.models import (
    AlertInstance,
    AlertRule,
    AlertSilence,
    AlertState,
    AlertTransition,
    MaintenanceWindow,
    NotificationChannel,
    NotificationDelivery,
    User,
)


@dataclass(frozen=True, slots=True)
class AlertObservation:
    alert: AlertInstance
    changed: bool
    notification_scheduled: bool


def alert_fingerprint(rule: AlertRule) -> str:
    value = f"{rule.id}\n{rule.source_type}\n{rule.source_id}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _matches(matchers: dict[str, object], rule: AlertRule) -> bool:
    supported = {
        "rule_id": rule.id,
        "source_type": rule.source_type,
        "source_id": rule.source_id,
        "severity": rule.severity,
        "group_key": rule.group_key,
    }
    return all(supported.get(key) == value for key, value in matchers.items())


def _is_suppressed(db: Session, alert: AlertInstance, rule: AlertRule, now: datetime) -> bool:
    if alert.silenced_until and _aware(alert.silenced_until) > now:
        return True
    silences = db.scalars(
        select(AlertSilence).where(
            AlertSilence.starts_at <= now,
            AlertSilence.ends_at > now,
        )
    )
    if any(
        silence.alert_id == alert.id or _matches(silence.matchers, rule)
        for silence in silences
    ):
        return True
    windows = db.scalars(
        select(MaintenanceWindow).where(
            MaintenanceWindow.starts_at <= now,
            MaintenanceWindow.ends_at > now,
        )
    )
    return any(_matches(window.matchers, rule) for window in windows)


def _record_transition(
    db: Session,
    alert: AlertInstance,
    previous: str,
    current: str,
    reason: str,
    now: datetime,
) -> None:
    if previous == current:
        return
    db.add(
        AlertTransition(
            alert_id=alert.id,
            previous_state=previous,
            current_state=current,
            reason=reason[:255],
            observed_at=now,
        )
    )


def _schedule_notifications(
    db: Session, alert: AlertInstance, event_type: str, now: datetime
) -> bool:
    channels = db.scalars(
        select(NotificationChannel).where(NotificationChannel.enabled.is_(True))
    )
    scheduled = False
    for channel in channels:
        db.add(
            NotificationDelivery(
                channel_id=channel.id,
                alert_id=alert.id,
                event_type=event_type,
                status="pending",
                next_attempt_at=now,
                created_at=now,
            )
        )
        scheduled = True
    if scheduled:
        alert.last_notified_at = now
        alert.notification_count += 1
    return scheduled


def observe_alert(
    db: Session,
    *,
    rule: AlertRule,
    success: bool,
    summary: str,
    details: dict[str, object] | None = None,
    now: datetime | None = None,
) -> AlertObservation:
    now = now or datetime.now(UTC)
    fingerprint = alert_fingerprint(rule)
    alert = db.scalar(
        select(AlertInstance)
        .where(AlertInstance.fingerprint == fingerprint)
        .with_for_update()
    )
    if alert is None:
        alert = AlertInstance(
            rule_id=rule.id,
            fingerprint=fingerprint,
            state=AlertState.ok.value,
            first_observed_at=now,
            last_observed_at=now,
        )
        db.add(alert)
        db.flush()

    previous = alert.state
    alert.last_observed_at = now
    alert.summary = summary[:512]
    alert.details = details or {}
    reason = "observation unchanged"
    notification_event: str | None = None

    if success:
        alert.consecutive_successes += 1
        alert.consecutive_failures = 0
        if previous == AlertState.resolved.value:
            alert.state = AlertState.ok.value
            reason = "resolved alert returned to steady state"
        elif (
            previous != AlertState.ok.value
            and alert.consecutive_successes >= rule.recovery_threshold
        ):
            alert.state = AlertState.resolved.value
            alert.resolved_at = now
            reason = "recovery threshold met"
            if rule.recovery_notifications:
                notification_event = "resolved"
    else:
        alert.consecutive_failures += 1
        alert.consecutive_successes = 0
        suppressed = _is_suppressed(db, alert, rule, now)
        if suppressed:
            alert.state = AlertState.silenced.value
            reason = "active silence or maintenance window"
        elif previous in {AlertState.acknowledged.value, AlertState.firing.value}:
            alert.state = previous
        elif alert.consecutive_failures >= rule.failure_threshold:
            alert.state = AlertState.firing.value
            alert.fired_at = alert.fired_at or now
            alert.resolved_at = None
            reason = "failure threshold met"
            notification_event = "firing"
        else:
            alert.state = AlertState.pending.value
            reason = "failure threshold pending"

    changed = previous != alert.state
    _record_transition(db, alert, previous, alert.state, reason, now)
    scheduled = False
    if notification_event and changed:
        scheduled = _schedule_notifications(db, alert, notification_event, now)
    elif (
        not success
        and alert.state == AlertState.firing.value
        and alert.last_notified_at is not None
        and now - _aware(alert.last_notified_at)
        >= timedelta(seconds=rule.repeat_interval_seconds)
    ):
        scheduled = _schedule_notifications(db, alert, "reminder", now)
    return AlertObservation(alert=alert, changed=changed, notification_scheduled=scheduled)


def acknowledge_alert(
    db: Session, *, alert: AlertInstance, actor: User, now: datetime | None = None
) -> bool:
    now = now or datetime.now(UTC)
    if alert.state not in {AlertState.firing.value, AlertState.pending.value}:
        return False
    previous = alert.state
    alert.state = AlertState.acknowledged.value
    alert.acknowledged_at = now
    alert.acknowledged_by = actor.id
    _record_transition(db, alert, previous, alert.state, "acknowledged by operator", now)
    return True


def silence_alert(
    db: Session,
    *,
    alert: AlertInstance,
    actor: User,
    reason: str,
    until: datetime,
    now: datetime | None = None,
) -> AlertSilence:
    now = now or datetime.now(UTC)
    if _aware(until) <= now or _aware(until) > now + timedelta(days=30):
        raise ValueError("silence expiry is outside the allowed range")
    silence = AlertSilence(
        alert_id=alert.id,
        matchers={},
        reason=reason[:255],
        starts_at=now,
        ends_at=until,
        created_by=actor.id,
        created_at=now,
    )
    db.add(silence)
    previous = alert.state
    alert.state = AlertState.silenced.value
    alert.silenced_until = until
    _record_transition(db, alert, previous, alert.state, "silenced by operator", now)
    return silence
