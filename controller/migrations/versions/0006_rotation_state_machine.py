"""Add idempotent, heartbeat-gated Agent rotation state."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_rotation_state_machine"
down_revision = "0005_recovery_attestation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("agent_identities")}
    additions = (
        sa.Column("rotation_id", sa.String(length=36), nullable=True),
        sa.Column(
            "successful_heartbeats",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("last_pending_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retiring_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    for column in additions:
        if column.name not in columns:
            op.add_column("agent_identities", column)

    inspector = sa.inspect(bind)
    checks = {
        constraint["name"]: str(constraint.get("sqltext", ""))
        for constraint in inspector.get_check_constraints("agent_identities")
    }
    state_is_current = "retiring" in checks.get("ck_agent_identity_state", "")
    has_heartbeat_check = "ck_agent_identity_successful_heartbeats" in checks
    if not state_is_current or not has_heartbeat_check:
        with op.batch_alter_table("agent_identities") as batch:
            if "ck_agent_identity_state" in checks and not state_is_current:
                batch.drop_constraint("ck_agent_identity_state", type_="check")
            if not state_is_current:
                batch.create_check_constraint(
                    "ck_agent_identity_state",
                    "state IN ('pending', 'active', 'retiring', 'revoked', 'retired')",
                )
            if not has_heartbeat_check:
                batch.create_check_constraint(
                    "ck_agent_identity_successful_heartbeats",
                    "successful_heartbeats >= 0",
                )

    unique_constraints = {
        constraint["name"]
        for constraint in sa.inspect(bind).get_unique_constraints("agent_identities")
    }
    if "uq_agent_identity_rotation_id" not in unique_constraints:
        with op.batch_alter_table("agent_identities") as batch:
            batch.create_unique_constraint(
                "uq_agent_identity_rotation_id",
                ["agent_id", "rotation_id"],
            )


def downgrade() -> None:
    with op.batch_alter_table("agent_identities") as batch:
        batch.drop_constraint("uq_agent_identity_rotation_id", type_="unique")
        batch.drop_constraint("ck_agent_identity_successful_heartbeats", type_="check")
        batch.drop_constraint("ck_agent_identity_state", type_="check")
        batch.create_check_constraint(
            "ck_agent_identity_state",
            "state IN ('pending', 'active', 'retired')",
        )
    with op.batch_alter_table("agent_identities") as batch:
        batch.drop_column("revoked_at")
        batch.drop_column("retiring_at")
        batch.drop_column("last_pending_heartbeat_at")
        batch.drop_column("successful_heartbeats")
        batch.drop_column("rotation_id")
