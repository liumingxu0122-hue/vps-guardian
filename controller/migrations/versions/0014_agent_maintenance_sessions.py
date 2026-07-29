"""Add isolated repair and decommission sessions.

Revision ID: 0014_agent_maintenance
Revises: 0013_agent_enrollment
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision = "0014_agent_maintenance"
down_revision = "0013_agent_enrollment"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "agent_maintenance_sessions" not in tables:
        op.create_table(
            "agent_maintenance_sessions",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("host_id", sa.String(36), nullable=False),
            sa.Column("agent_id", sa.String(36), nullable=False),
            sa.Column("kind", sa.String(24), nullable=False),
            sa.Column("token_hash", sa.String(64), nullable=False),
            sa.Column("progress_token_hash", sa.String(64), nullable=True),
            sa.Column("status", sa.String(32), server_default="waiting", nullable=False),
            sa.Column("status_sequence", sa.Integer(), server_default="0", nullable=False),
            sa.Column("source_cidr", sa.String(64), nullable=True),
            sa.Column("purge_local_state", sa.Boolean(), server_default=sa.false(), nullable=False),
            sa.Column("expected_identity_version", sa.Integer(), nullable=False),
            sa.Column("old_identity_id", sa.String(36), nullable=True),
            sa.Column("new_identity_id", sa.String(36), nullable=True),
            sa.Column("approval_id", sa.String(36), nullable=True),
            sa.Column("created_by", sa.String(36), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("error_code", sa.String(64), nullable=True),
            sa.Column("error_summary", sa.String(240), nullable=True),
            sa.Column("rolled_back", sa.Boolean(), server_default=sa.false(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("status_updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.CheckConstraint(
                "kind IN ('repair', 'reinstall', 'rotate_identity', 'decommission')",
                name="ck_agent_maintenance_kind",
            ),
            sa.CheckConstraint(
                "status IN ('waiting', 'started', 'artifact_verified', 'service_stopped', "
                "'identity_rotated', 'service_started', 'heartbeat_verified', "
                "'confirmation_pending', 'completed', 'failed', 'rolled_back', "
                "'expired', 'revoked')",
                name="ck_agent_maintenance_status",
            ),
            sa.CheckConstraint("length(token_hash) = 64", name="ck_agent_maintenance_token_hash"),
            sa.CheckConstraint(
                "progress_token_hash IS NULL OR length(progress_token_hash) = 64",
                name="ck_agent_maintenance_progress_hash",
            ),
            sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(
                ["old_identity_id"], ["agent_identities.id"], ondelete="SET NULL"
            ),
            sa.ForeignKeyConstraint(
                ["new_identity_id"], ["agent_identities.id"], ondelete="SET NULL"
            ),
            sa.ForeignKeyConstraint(["approval_id"], ["approvals.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
            sa.UniqueConstraint("token_hash", name="uq_agent_maintenance_token_hash"),
            sa.UniqueConstraint("progress_token_hash", name="uq_agent_maintenance_progress_hash"),
        )
        op.create_index(
            "ix_agent_maintenance_host_created",
            "agent_maintenance_sessions",
            ["host_id", "created_at"],
        )
        op.create_index("ix_agent_maintenance_agent_id", "agent_maintenance_sessions", ["agent_id"])
        op.create_index("ix_agent_maintenance_kind", "agent_maintenance_sessions", ["kind"])
        op.create_index("ix_agent_maintenance_status", "agent_maintenance_sessions", ["status"])
        op.create_index(
            "ix_agent_maintenance_expires_at",
            "agent_maintenance_sessions",
            ["expires_at"],
        )
    if "agent_maintenance_events" in tables:
        return
    op.create_table(
        "agent_maintenance_events",
        sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True),
        sa.Column("session_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("status_sequence", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_summary", sa.String(240), nullable=True),
        sa.Column("rolled_back", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.ForeignKeyConstraint(
            ["session_id"], ["agent_maintenance_sessions.id"], ondelete="CASCADE"
        ),
        sa.UniqueConstraint("session_id", "status", name="uq_agent_maintenance_event_status"),
    )
    op.create_index(
        "ix_agent_maintenance_events_session_id",
        "agent_maintenance_events",
        ["session_id"],
    )


def downgrade() -> None:
    if "agent_maintenance_sessions" not in sa.inspect(op.get_bind()).get_table_names():
        return
    if "agent_maintenance_events" in sa.inspect(op.get_bind()).get_table_names():
        op.drop_table("agent_maintenance_events")
    op.drop_table("agent_maintenance_sessions")
