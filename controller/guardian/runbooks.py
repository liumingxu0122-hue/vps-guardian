from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian.config import Settings
from guardian.models import Agent, Approval, Incident, RepairAttempt
from guardian.tasking import REGISTERED_ACTIONS, create_agent_task

CONDITION_TYPES = {
    "fault_type",
    "agent_online",
    "verified_recovery_point",
    "changed_within",
    "service_level2_enabled",
}
CONTEXT_FIELDS = {
    "service",
    "container",
    "systemd_unit",
    "config_path",
    "health_url",
    "recovery_point",
    "restore_target",
    "cache_path",
}
CONTEXT_VARIABLE = re.compile(
    r"^\$\{(service|container|systemd_unit|config_path|health_url|recovery_point|restore_target|cache_path)\}$"
)
APPROVAL_ONLY_ACTIONS = {"restore_database", "modify_dns", "modify_firewall", "rebuild_host"}
RUNBOOK_ACTIONS = REGISTERED_ACTIONS | APPROVAL_ONLY_ACTIONS

RUNBOOK_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "name",
        "version",
        "risk_level",
        "conditions",
        "prechecks",
        "actions",
        "postchecks",
        "rollback_on_failure",
        "cooldown",
        "max_attempts",
    ],
    "properties": {
        "name": {"type": "string", "pattern": "^[a-z][a-z0-9_]{2,79}$"},
        "version": {"type": "integer", "minimum": 1},
        "risk_level": {"type": "integer", "enum": [1, 2, 3]},
        "conditions": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["type"],
                "properties": {
                    "type": {"type": "string", "enum": sorted(CONDITION_TYPES)},
                    "value": {"type": ["string", "boolean", "number"]},
                },
            },
        },
        "prechecks": {"$ref": "#/$defs/actions"},
        "actions": {"$ref": "#/$defs/actions"},
        "postchecks": {"$ref": "#/$defs/actions"},
        "rollback_on_failure": {"type": "boolean"},
        "cooldown": {"type": "string", "pattern": "^[1-9][0-9]*(s|m|h)$"},
        "max_attempts": {"type": "integer", "minimum": 1, "maximum": 3},
    },
    "$defs": {
        "actions": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["type", "parameters"],
                "properties": {
                    "type": {"type": "string", "enum": sorted(RUNBOOK_ACTIONS)},
                    "parameters": {
                        "type": "object",
                        "maxProperties": 16,
                        "additionalProperties": {
                            "type": "string",
                            "pattern": (
                                r"^(?:[^$]|\$\{(?:service|container|systemd_unit|config_path|health_url|"
                                r"recovery_point|restore_target|cache_path)\})+$"
                            ),
                            "maxLength": 1024,
                        },
                    },
                },
            },
        }
    },
}


@dataclass(slots=True)
class Runbook:
    data: dict[str, Any]

    @property
    def name(self) -> str:
        return str(self.data["name"])

    @property
    def risk_level(self) -> int:
        return int(self.data["risk_level"])

    @property
    def cooldown(self) -> timedelta:
        return parse_duration(str(self.data["cooldown"]))

    @property
    def max_attempts(self) -> int:
        return int(self.data["max_attempts"])


def parse_duration(value: str) -> timedelta:
    amount = int(value[:-1])
    unit = {"s": "seconds", "m": "minutes", "h": "hours"}[value[-1]]
    return timedelta(**{unit: amount})


def load_runbook(path: Path) -> Runbook:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(RUNBOOK_SCHEMA).iter_errors(document), key=str)
    if errors:
        raise ValueError("invalid runbook: " + "; ".join(error.message for error in errors[:5]))
    if int(document["risk_level"]) < 3 and any(
        action["type"] in APPROVAL_ONLY_ACTIONS
        for section in ("prechecks", "actions", "postchecks")
        for action in document[section]
    ):
        raise ValueError("approval-only actions require risk level 3")
    return Runbook(document)


def interpolate_parameters(parameters: dict[str, str], context: dict[str, str]) -> dict[str, str]:
    output: dict[str, str] = {}
    for key, value in parameters.items():
        match = CONTEXT_VARIABLE.fullmatch(value)
        output[key] = context.get(match.group(1), "") if match else value
        if not output[key]:
            raise ValueError(f"runbook parameter {key} resolved to an empty value")
    return output


@dataclass(slots=True)
class RepairPlan:
    runbook: str
    risk_level: int
    dry_run: bool
    requires_approval: bool
    actions: list[dict[str, object]]
    reason: str
    task_ids: list[str]


class RepairOrchestrator:
    @staticmethod
    def conditions_match(
        runbook: Runbook,
        incident: Incident,
        context: dict[str, str],
        level2_enabled: bool,
    ) -> tuple[bool, str]:
        for condition in runbook.data["conditions"]:
            condition_type = condition["type"]
            expected = condition.get("value")
            if condition_type == "fault_type" and incident.fault_type != expected:
                return False, "fault type condition did not match"
            if condition_type == "agent_online" and (
                context.get("agent_online", "false").lower() == "true"
            ) != bool(expected):
                return False, "agent online condition did not match"
            if condition_type == "verified_recovery_point" and (
                context.get("verified_recovery_point", "false").lower() == "true"
            ) != bool(expected):
                return False, "verified recovery point is required"
            if condition_type == "service_level2_enabled" and level2_enabled != bool(expected):
                return False, "service Level 2 repair is disabled"
            if condition_type == "changed_within":
                changed_seconds = int(context.get("changed_seconds_ago", "999999999"))
                if changed_seconds > parse_duration(str(expected)).total_seconds():
                    return False, "recent change window did not match"
        return True, "conditions matched"

    def plan(
        self,
        db: Session,
        *,
        runbook: Runbook,
        incident: Incident,
        agent: Agent,
        context: dict[str, str],
        settings: Settings,
        dry_run: bool = True,
        level2_enabled: bool = False,
    ) -> RepairPlan:
        matched, reason = self.conditions_match(
            runbook,
            incident,
            context,
            level2_enabled or dry_run,
        )
        if not matched:
            return RepairPlan(runbook.name, runbook.risk_level, True, True, [], reason, [])
        cooldown = parse_duration(str(runbook.data["cooldown"]))
        actual_attempts = list(
            db.scalars(
                select(RepairAttempt)
                .where(
                    RepairAttempt.incident_id == incident.id,
                    RepairAttempt.action == runbook.name,
                    RepairAttempt.dry_run.is_(False),
                )
                .order_by(RepairAttempt.created_at.desc())
            ).all()
        )
        max_attempts = int(runbook.data["max_attempts"])
        if len(actual_attempts) >= max_attempts:
            return RepairPlan(
                runbook.name,
                runbook.risk_level,
                True,
                True,
                [],
                "maximum repair attempts reached; incident must be escalated",
                [],
            )
        if actual_attempts and not dry_run:
            last_created = actual_attempts[0].created_at
            if last_created.tzinfo is None:
                last_created = last_created.replace(tzinfo=UTC)
            if datetime.now(UTC) < last_created + cooldown:
                return RepairPlan(
                    runbook.name,
                    runbook.risk_level,
                    True,
                    True,
                    [],
                    "repair cooldown is active; incident remains escalated",
                    [],
                )
        requires_approval = not dry_run and (
            runbook.risk_level == 3
            or (runbook.risk_level == 2 and not level2_enabled)
        )
        actions: list[dict[str, object]] = []
        for action in runbook.data["actions"]:
            parameters = interpolate_parameters(action["parameters"], context)
            parameters["dry_run"] = "true" if dry_run or requires_approval else "false"
            actions.append({"type": action["type"], "parameters": parameters})
        task_ids: list[str] = []
        if requires_approval:
            requested_at = datetime.now(UTC)
            approval = Approval(
                incident_id=incident.id,
                action_name=runbook.name,
                risk_level=runbook.risk_level,
                parameters={"agent_id": agent.id, "actions": actions},
                impact={"service": context.get("service"), "dry_run_available": True},
                rollback_plan=["stop remaining actions", "execute runbook rollback metadata"],
                requested_at=requested_at,
                expires_at=requested_at + timedelta(minutes=settings.approval_ttl_minutes),
            )
            db.add(approval)
            db.flush()
        else:
            dispatch_actions = actions
            if not dry_run:
                for postcheck in runbook.data["postchecks"]:
                    parameters = interpolate_parameters(postcheck["parameters"], context)
                    parameters["dry_run"] = "false"
                    dispatch_actions.append(
                        {"type": postcheck["type"], "parameters": parameters}
                    )
            for action in dispatch_actions:
                if str(action["type"]) in APPROVAL_ONLY_ACTIONS:
                    if not dry_run:
                        raise RuntimeError("approval-only action cannot be dispatched to an agent")
                    continue
                task = create_agent_task(
                    db,
                    agent_id=agent.id,
                    action=str(action["type"]),
                    parameters=action["parameters"],  # type: ignore[arg-type]
                    settings=settings,
                )
                task_ids.append(task.id)
        db.add(
            RepairAttempt(
                incident_id=incident.id,
                action=runbook.name,
                dry_run=dry_run or requires_approval,
                before_state={"context": context},
                after_state={"task_ids": task_ids},
            )
        )
        db.flush()
        return RepairPlan(
            runbook.name,
            runbook.risk_level,
            dry_run or requires_approval,
            requires_approval,
            actions,
            "approval required" if requires_approval else "plan accepted",
            task_ids,
        )
