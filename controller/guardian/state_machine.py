from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from guardian.probes import ProbeResult


class MonitorState(StrEnum):
    unknown = "unknown"
    healthy = "healthy"
    pending_failure = "pending_failure"
    failing = "failing"
    pending_recovery = "pending_recovery"


@dataclass(slots=True)
class Transition:
    previous: MonitorState
    current: MonitorState
    changed: bool
    incident_opened: bool = False
    incident_recovered: bool = False
    suppressed: bool = False


@dataclass(slots=True)
class MonitorStateMachine:
    failure_threshold: int = 3
    recovery_threshold: int = 2
    cooldown_seconds: int = 300
    state: MonitorState = MonitorState.unknown
    consecutive_successes: int = 0
    consecutive_failures: int = 0
    last_transition_at: datetime | None = None

    def observe(self, result: ProbeResult, now: datetime | None = None) -> Transition:
        now = now or datetime.now(UTC)
        previous = self.state
        incident_opened = False
        incident_recovered = False

        if result.success:
            self.consecutive_successes += 1
            self.consecutive_failures = 0
            if self.state in {MonitorState.unknown, MonitorState.healthy}:
                self.state = MonitorState.healthy
            elif self.consecutive_successes >= self.recovery_threshold:
                self.state = MonitorState.healthy
                incident_recovered = previous in {
                    MonitorState.failing,
                    MonitorState.pending_recovery,
                }
            else:
                self.state = MonitorState.pending_recovery
        else:
            self.consecutive_failures += 1
            self.consecutive_successes = 0
            if self.state == MonitorState.failing:
                pass
            elif self.consecutive_failures >= self.failure_threshold:
                self.state = MonitorState.failing
                incident_opened = True
            else:
                self.state = MonitorState.pending_failure

        changed = previous != self.state
        suppressed = False
        if changed and self.last_transition_at:
            cooldown_until = self.last_transition_at + timedelta(seconds=self.cooldown_seconds)
            if now < cooldown_until and incident_opened:
                self.state = previous
                changed = False
                incident_opened = False
                suppressed = True
        if changed:
            self.last_transition_at = now
        return Transition(
            previous=previous,
            current=self.state,
            changed=changed,
            incident_opened=incident_opened,
            incident_recovered=incident_recovered,
            suppressed=suppressed,
        )
