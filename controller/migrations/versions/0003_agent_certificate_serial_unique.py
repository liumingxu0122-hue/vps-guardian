"""Require unique Agent certificate serials."""

import re

import sqlalchemy as sa
from alembic import op

revision = "0003_agent_cert_serial_unique"
down_revision = "0002_approval_audit_guards"
branch_labels = None
depends_on = None


def _unique_serial_constraint_exists(bind: sa.engine.Connection) -> bool:
    inspector = sa.inspect(bind)
    constraints = inspector.get_unique_constraints("agents")
    indexes = inspector.get_indexes("agents")
    return any(
        entry.get("column_names") == ["certificate_serial"]
        for entry in [*constraints, *indexes]
        if entry.get("unique", True)
    )


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(
        sa.text("SELECT id, certificate_serial FROM agents WHERE certificate_serial IS NOT NULL")
    ).mappings()
    normalized_by_serial: dict[str, str] = {}
    normalized_by_agent: dict[str, str] = {}
    for row in rows:
        serial = str(row["certificate_serial"])
        if not re.fullmatch(r"[A-Fa-f0-9]{1,128}", serial):
            raise RuntimeError("existing Agent certificate serial is invalid")
        normalized = format(int(serial, 16), "X")
        previous_agent = normalized_by_serial.get(normalized)
        if previous_agent and previous_agent != row["id"]:
            raise RuntimeError("existing Agent certificate serials collide after normalization")
        normalized_by_serial[normalized] = row["id"]
        normalized_by_agent[row["id"]] = normalized
    for agent_id, normalized in normalized_by_agent.items():
        bind.execute(
            sa.text("UPDATE agents SET certificate_serial = :serial WHERE id = :agent_id"),
            {"serial": normalized, "agent_id": agent_id},
        )
    if not _unique_serial_constraint_exists(bind):
        with op.batch_alter_table("agents") as batch:
            batch.create_unique_constraint(
                "uq_agents_certificate_serial",
                ["certificate_serial"],
            )


def downgrade() -> None:
    bind = op.get_bind()
    named_constraints = {
        constraint.get("name") for constraint in sa.inspect(bind).get_unique_constraints("agents")
    }
    if "uq_agents_certificate_serial" in named_constraints:
        with op.batch_alter_table("agents") as batch:
            batch.drop_constraint("uq_agents_certificate_serial", type_="unique")
