from __future__ import annotations

from sqlalchemy.orm import Session

from guardian.models import AuditLog, User
from guardian.redaction import redact_structure


def write_audit(
    db: Session,
    *,
    actor: User | None,
    action: str,
    resource_type: str,
    resource_id: str | None,
    outcome: str,
    details: dict[str, object] | None = None,
    source_ip: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        actor_id=actor.id if actor else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        details=redact_structure(details or {}),
        source_ip=source_ip,
    )
    db.add(entry)
    db.flush()
    return entry
