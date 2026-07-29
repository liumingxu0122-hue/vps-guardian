"""Add bounded port traffic accounting and rollups.

Revision ID: 0013_port_traffic
Revises: 0012_persistent_sessions
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision = "0013_port_traffic"
down_revision = "0012_persistent_sessions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _create_reset_guards(bind: sa.engine.Connection) -> None:
    if bind.dialect.name == "postgresql":
        op.execute(
            """
            CREATE OR REPLACE FUNCTION guardian_reject_traffic_reset_mutation()
            RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'traffic reset records are append-only';
            END;
            $$
            """
        )
        op.execute(
            "DROP TRIGGER IF EXISTS guardian_traffic_reset_append_only "
            "ON port_traffic_reset_events"
        )
        op.execute(
            """
            CREATE TRIGGER guardian_traffic_reset_append_only
            BEFORE UPDATE OR DELETE ON port_traffic_reset_events
            FOR EACH ROW EXECUTE FUNCTION guardian_reject_traffic_reset_mutation()
            """
        )
    elif bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS guardian_traffic_reset_no_update")
        op.execute("DROP TRIGGER IF EXISTS guardian_traffic_reset_no_delete")
        op.execute(
            """
            CREATE TRIGGER guardian_traffic_reset_no_update
            BEFORE UPDATE ON port_traffic_reset_events
            BEGIN
                SELECT RAISE(ABORT, 'traffic reset records are append-only');
            END
            """
        )
        op.execute(
            """
            CREATE TRIGGER guardian_traffic_reset_no_delete
            BEFORE DELETE ON port_traffic_reset_events
            BEGIN
                SELECT RAISE(ABORT, 'traffic reset records are append-only');
            END
            """
        )


def _drop_reset_guards(bind: sa.engine.Connection) -> None:
    if bind.dialect.name == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS guardian_traffic_reset_append_only "
            "ON port_traffic_reset_events"
        )
        op.execute("DROP FUNCTION IF EXISTS guardian_reject_traffic_reset_mutation()")
    elif bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS guardian_traffic_reset_no_update")
        op.execute("DROP TRIGGER IF EXISTS guardian_traffic_reset_no_delete")


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    required_tables = {
        "port_traffic_policies",
        "port_traffic_samples",
        "port_traffic_hourly_rollups",
        "port_traffic_daily_rollups",
        "port_traffic_reset_events",
        "port_traffic_runtime_states",
    }
    existing = tables & required_tables
    if existing == required_tables:
        _create_reset_guards(bind)
        return
    if existing:
        raise RuntimeError("partial port traffic schema detected; refusing unsafe upgrade")
    op.create_table(
        "port_traffic_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("host_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("protocol", sa.String(8), nullable=False),
        sa.Column("direction", sa.String(8), nullable=False),
        sa.Column("port_start", sa.Integer(), nullable=False),
        sa.Column("port_end", sa.Integer(), nullable=False),
        sa.Column("interface_name", sa.String(32), nullable=True),
        sa.Column("mode", sa.String(16), server_default="monitor_only", nullable=False),
        sa.Column("quota_bytes", sa.BigInteger(), nullable=True),
        sa.Column("reset_policy", sa.JSON(), server_default="{}", nullable=False),
        sa.Column("egress_rate_bps", sa.BigInteger(), nullable=True),
        sa.Column("status", sa.String(16), server_default="pending", nullable=False),
        sa.Column("generation", sa.Integer(), server_default="1", nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("approved_by", sa.String(36), nullable=True),
        sa.Column("reset_approval_id", sa.String(36), nullable=True),
        sa.Column("reset_requested_by", sa.String(36), nullable=True),
        sa.Column("reset_approved_by", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "port_start >= 1 AND port_start <= 65535", name="ck_port_traffic_start"
        ),
        sa.CheckConstraint(
            "port_end >= port_start AND port_end <= 65535", name="ck_port_traffic_end"
        ),
        sa.CheckConstraint(
            "protocol IN ('tcp', 'udp', 'both')", name="ck_port_traffic_protocol"
        ),
        sa.CheckConstraint(
            "direction IN ('rx', 'tx', 'both')", name="ck_port_traffic_direction"
        ),
        sa.CheckConstraint(
            "mode IN ('monitor_only', 'enforcing')", name="ck_port_traffic_mode"
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'active', 'disabled', 'error')",
            name="ck_port_traffic_status",
        ),
        sa.CheckConstraint("generation >= 1", name="ck_port_traffic_generation"),
        sa.CheckConstraint(
            "quota_bytes IS NULL OR quota_bytes > 0", name="ck_port_traffic_quota"
        ),
        sa.CheckConstraint(
            "egress_rate_bps IS NULL OR egress_rate_bps >= 8000",
            name="ck_port_traffic_egress_rate",
        ),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
        sa.ForeignKeyConstraint(
            ["reset_approval_id"], ["approvals.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["reset_requested_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["reset_approved_by"], ["users.id"]),
    )
    op.create_index("ix_port_traffic_policies_host_id", "port_traffic_policies", ["host_id"])
    op.create_index("ix_port_traffic_policies_status", "port_traffic_policies", ["status"])
    op.create_index(
        "ix_port_traffic_host_status", "port_traffic_policies", ["host_id", "status"]
    )
    op.create_table(
        "port_traffic_samples",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("policy_id", sa.String(36), nullable=False),
        sa.Column("host_id", sa.String(36), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rx_bytes_total", sa.BigInteger(), nullable=False),
        sa.Column("tx_bytes_total", sa.BigInteger(), nullable=False),
        sa.Column("current_period_rx", sa.BigInteger(), nullable=False),
        sa.Column("current_period_tx", sa.BigInteger(), nullable=False),
        sa.Column("quota_bytes", sa.BigInteger(), nullable=True),
        sa.Column("counter_generation", sa.Integer(), nullable=False),
        sa.Column("runtime_rule_state", sa.String(32), nullable=False),
        sa.Column("shaping_state", sa.String(32), nullable=False),
        sa.Column("current_egress_rate_bps", sa.BigInteger(), nullable=True),
        sa.Column("discontinuity_reason", sa.String(64), nullable=True),
        sa.CheckConstraint("rx_bytes_total >= 0", name="ck_port_traffic_sample_rx"),
        sa.CheckConstraint("tx_bytes_total >= 0", name="ck_port_traffic_sample_tx"),
        sa.CheckConstraint("current_period_rx >= 0", name="ck_port_traffic_period_rx"),
        sa.CheckConstraint("current_period_tx >= 0", name="ck_port_traffic_period_tx"),
        sa.ForeignKeyConstraint(
            ["policy_id"], ["port_traffic_policies.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.UniqueConstraint(
            "policy_id", "collected_at", name="uq_port_traffic_sample_policy_time"
        ),
    )
    op.create_index("ix_port_traffic_samples_policy_id", "port_traffic_samples", ["policy_id"])
    op.create_index("ix_port_traffic_samples_host_id", "port_traffic_samples", ["host_id"])
    op.create_index(
        "ix_port_traffic_samples_collected_at", "port_traffic_samples", ["collected_at"]
    )
    op.create_index(
        "ix_port_traffic_sample_host_time",
        "port_traffic_samples",
        ["host_id", "collected_at"],
    )
    for table, unique_name, host_index in (
        (
            "port_traffic_hourly_rollups",
            "uq_port_traffic_hourly_policy_bucket",
            "ix_port_traffic_hourly_host_bucket",
        ),
        (
            "port_traffic_daily_rollups",
            "uq_port_traffic_daily_policy_bucket",
            "ix_port_traffic_daily_host_bucket",
        ),
    ):
        op.create_table(
            table,
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("policy_id", sa.String(36), nullable=False),
            sa.Column("host_id", sa.String(36), nullable=False),
            sa.Column("bucket_start", sa.DateTime(timezone=True), nullable=False),
            sa.Column("rx_bytes", sa.BigInteger(), server_default="0", nullable=False),
            sa.Column("tx_bytes", sa.BigInteger(), server_default="0", nullable=False),
            sa.Column("sample_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("missing_intervals", sa.Integer(), server_default="0", nullable=False),
            sa.Column("discontinuity_count", sa.Integer(), server_default="0", nullable=False),
            sa.ForeignKeyConstraint(
                ["policy_id"], ["port_traffic_policies.id"], ondelete="CASCADE"
            ),
            sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
            sa.UniqueConstraint("policy_id", "bucket_start", name=unique_name),
        )
        op.create_index(f"ix_{table}_policy_id", table, ["policy_id"])
        op.create_index(f"ix_{table}_host_id", table, ["host_id"])
        op.create_index(f"ix_{table}_bucket_start", table, ["bucket_start"])
        op.create_index(host_index, table, ["host_id", "bucket_start"])
    op.create_table(
        "port_traffic_reset_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("policy_id", sa.String(36), nullable=False),
        sa.Column("host_id", sa.String(36), nullable=False),
        sa.Column("reason", sa.String(64), nullable=False),
        sa.Column("previous_generation", sa.Integer(), nullable=False),
        sa.Column("new_generation", sa.Integer(), nullable=False),
        sa.Column("previous_rx_bytes", sa.BigInteger(), nullable=False),
        sa.Column("previous_tx_bytes", sa.BigInteger(), nullable=False),
        sa.Column("requested_by", sa.String(36), nullable=True),
        sa.Column("approval_id", sa.String(36), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["policy_id"], ["port_traffic_policies.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["approval_id"], ["approvals.id"], ondelete="SET NULL"),
    )
    op.create_index(
        "ix_port_traffic_reset_events_policy_id",
        "port_traffic_reset_events",
        ["policy_id"],
    )
    op.create_index(
        "ix_port_traffic_reset_events_host_id", "port_traffic_reset_events", ["host_id"]
    )
    op.create_index(
        "ix_port_traffic_reset_events_occurred_at",
        "port_traffic_reset_events",
        ["occurred_at"],
    )
    op.create_table(
        "port_traffic_runtime_states",
        sa.Column("policy_id", sa.String(36), primary_key=True),
        sa.Column("runtime_rule_state", sa.String(32), server_default="unknown", nullable=False),
        sa.Column("shaping_state", sa.String(32), server_default="disabled", nullable=False),
        sa.Column("counter_generation", sa.Integer(), server_default="1", nullable=False),
        sa.Column("last_sample_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_reset_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_reset_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("restore_error", sa.String(240), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["policy_id"], ["port_traffic_policies.id"], ondelete="CASCADE"
        ),
    )
    _create_reset_guards(bind)


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "port_traffic_reset_events" in tables:
        _drop_reset_guards(bind)
    for table in (
        "port_traffic_runtime_states",
        "port_traffic_reset_events",
        "port_traffic_daily_rollups",
        "port_traffic_hourly_rollups",
        "port_traffic_samples",
        "port_traffic_policies",
    ):
        if table in tables:
            op.drop_table(table)
