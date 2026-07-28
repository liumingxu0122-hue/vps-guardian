from __future__ import annotations

import json
import re
from collections import Counter

EXECUTION_FAILURE_MARKERS = (
    "command not found",
    "permission denied",
    "operation not permitted",
    "timed out",
    "timeout",
    "failed to execute",
)


def classify_service_observation(kind: str, summary: str) -> dict[str, object]:
    normalized_kind = kind.strip().lower()
    content = summary.strip()
    lowered = content.lower()
    if not content:
        return {
            "status": "no_data",
            "reason": "the observation contains no data",
            "counts": {},
            "parsed": False,
        }
    if any(marker in lowered for marker in EXECUTION_FAILURE_MARKERS):
        return {
            "status": "execution_failed",
            "reason": "the observation command could not complete",
            "counts": {},
            "parsed": False,
        }

    if normalized_kind == "systemd_failed":
        if re.search(r"\b0\s+loaded units listed\b", lowered):
            return {
                "status": "healthy",
                "reason": "no failed systemd units found",
                "counts": {"failed": 0},
                "parsed": True,
            }
        unit_lines = [
            line
            for line in content.splitlines()
            if line.strip() and not line.lstrip().startswith(("UNIT ", "●", "LOAD "))
        ]
        return {
            "status": "critical" if unit_lines else "parse_failed",
            "reason": (
                f"{len(unit_lines)} failed systemd unit(s) found"
                if unit_lines
                else "the systemd observation could not be parsed"
            ),
            "counts": {"failed": len(unit_lines)},
            "parsed": bool(unit_lines),
        }

    if normalized_kind == "docker":
        records: list[dict[str, object]] = []
        for line in content.splitlines()[:500]:
            try:
                record = json.loads(line)
            except (TypeError, ValueError):
                continue
            if isinstance(record, dict):
                records.append(record)
        if not records:
            return {
                "status": "parse_failed",
                "reason": "the Docker observation could not be parsed",
                "counts": {},
                "parsed": False,
            }
        states = Counter(str(record.get("State", "unknown")).lower() for record in records)
        health = Counter(str(record.get("Health", "")).lower() for record in records)
        unhealthy = states["exited"] + states["restarting"] + health["unhealthy"]
        return {
            "status": "critical" if unhealthy else "healthy",
            "reason": (
                f"{unhealthy} unhealthy Docker container(s)"
                if unhealthy
                else f"{states['running']} Docker container(s) running"
            ),
            "counts": {
                "running": states["running"],
                "exited": states["exited"],
                "restarting": states["restarting"],
                "healthy": health["healthy"],
                "unhealthy": health["unhealthy"],
            },
            "parsed": True,
        }

    if normalized_kind in {
        "compose",
        "listening_ports",
        "journal_errors",
        "container_logs",
    }:
        return {
            "status": "healthy",
            "reason": "observation collected",
            "counts": {},
            "parsed": True,
        }

    return {
        "status": "unsupported",
        "reason": "observation type is not supported",
        "counts": {},
        "parsed": False,
    }
