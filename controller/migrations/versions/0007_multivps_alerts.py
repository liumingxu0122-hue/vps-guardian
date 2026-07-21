"""Add multi-host lifecycle, service checks, alerts, and notification delivery."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007_multivps_alerts"
down_revision = "0006_rotation_state_machine"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    phase4b_tables = {
        "enrollment_tokens",
        "service_checks",
        "service_check_results",
        "alert_rules",
        "alert_instances",
        "alert_transitions",
        "maintenance_windows",
        "alert_silences",
        "notification_channels",
        "notification_deliveries",
    }
    host_columns = {column["name"] for column in inspector.get_columns("hosts")}
    approval_columns = {column["name"] for column in inspector.get_columns("approvals")}
    task_columns = {column["name"] for column in inspector.get_columns("agent_tasks")}
    if (
        phase4b_tables <= set(inspector.get_table_names())
        and {"data_state", "enabled", "group_name", "tags", "enrolled_at", "disabled_at"}
        <= host_columns
        and {"requested_by", "target_host_id"} <= approval_columns
        and {
            "approval_id",
            "requester_id",
            "approver_id",
            "target_host_id",
            "verification_result",
            "started_at",
            "completed_at",
        }
        <= task_columns
    ):
        return

    with op.batch_alter_table("hosts") as batch:
        batch.add_column(
            sa.Column("data_state", sa.String(length=32), server_default="no_data", nullable=False)
        )
        batch.add_column(
            sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False)
        )
        batch.add_column(sa.Column("group_name", sa.String(length=120), nullable=True))
        batch.add_column(
            sa.Column("tags", sa.JSON(), server_default=sa.text("'[]'"), nullable=False)
        )
        batch.add_column(sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_index("ix_hosts_group_name", ["group_name"])

    op.create_table(
        "enrollment_tokens",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("host_id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_enrollment_token_hash_length"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_enrollment_tokens_host_id", "enrollment_tokens", ["host_id"])
    op.create_index("ix_enrollment_tokens_expires_at", "enrollment_tokens", ["expires_at"])

    op.create_table(
        "service_checks",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("kind", sa.String(length=24), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("host_id", sa.String(length=36), nullable=True),
        sa.Column("runner_agent_id", sa.String(length=36), nullable=True),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column("group_name", sa.String(length=120), nullable=True),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("failure_threshold", sa.Integer(), nullable=False),
        sa.Column("recovery_threshold", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("interval_seconds >= 15", name="ck_service_check_interval"),
        sa.CheckConstraint("timeout_seconds >= 1", name="ck_service_check_timeout"),
        sa.CheckConstraint("failure_threshold >= 1", name="ck_service_check_failure_threshold"),
        sa.CheckConstraint("recovery_threshold >= 1", name="ck_service_check_recovery_threshold"),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["runner_agent_id"], ["agents.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    for column in ("kind", "host_id", "runner_agent_id", "group_name", "last_checked_at"):
        op.create_index(f"ix_service_checks_{column}", "service_checks", [column])

    op.create_table(
        "service_check_results",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("check_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("message", sa.String(length=512), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["check_id"], ["service_checks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_service_check_results_check_id", "service_check_results", ["check_id"])
    op.create_index("ix_service_check_results_status", "service_check_results", ["status"])
    op.create_index("ix_service_check_results_checked_at", "service_check_results", ["checked_at"])

    op.create_table(
        "alert_rules",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("source_id", sa.String(length=36), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("group_key", sa.String(length=120), nullable=False),
        sa.Column("failure_threshold", sa.Integer(), nullable=False),
        sa.Column("recovery_threshold", sa.Integer(), nullable=False),
        sa.Column("repeat_interval_seconds", sa.Integer(), nullable=False),
        sa.Column("escalation_after_seconds", sa.Integer(), nullable=True),
        sa.Column("recovery_notifications", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("failure_threshold >= 1", name="ck_alert_rule_failure_threshold"),
        sa.CheckConstraint("recovery_threshold >= 1", name="ck_alert_rule_recovery_threshold"),
        sa.CheckConstraint("repeat_interval_seconds >= 60", name="ck_alert_rule_repeat_interval"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_alert_rules_source_type", "alert_rules", ["source_type"])
    op.create_index("ix_alert_rules_source_id", "alert_rules", ["source_id"])

    op.create_table(
        "alert_instances",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("rule_id", sa.String(length=36), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("consecutive_successes", sa.Integer(), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.String(length=36), nullable=True),
        sa.Column("silenced_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_notified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notification_count", sa.Integer(), nullable=False),
        sa.Column("summary", sa.String(length=512), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.CheckConstraint("consecutive_failures >= 0", name="ck_alert_failures"),
        sa.CheckConstraint("consecutive_successes >= 0", name="ck_alert_successes"),
        sa.ForeignKeyConstraint(["acknowledged_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["rule_id"], ["alert_rules.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("fingerprint"),
    )
    op.create_index("ix_alert_instances_rule_id", "alert_instances", ["rule_id"])
    op.create_index("ix_alert_instances_state", "alert_instances", ["state"])

    op.create_table(
        "alert_transitions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=False),
        sa.Column("previous_state", sa.String(length=24), nullable=False),
        sa.Column("current_state", sa.String(length=24), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alert_instances.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alert_transitions_alert_id", "alert_transitions", ["alert_id"])
    op.create_index("ix_alert_transitions_current_state", "alert_transitions", ["current_state"])
    op.create_index("ix_alert_transitions_observed_at", "alert_transitions", ["observed_at"])

    op.create_table(
        "maintenance_windows",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("matchers", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_maintenance_windows_starts_at", "maintenance_windows", ["starts_at"])
    op.create_index("ix_maintenance_windows_ends_at", "maintenance_windows", ["ends_at"])

    op.create_table(
        "alert_silences",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=True),
        sa.Column("matchers", sa.JSON(), nullable=False),
        sa.Column("reason", sa.String(length=255), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alert_instances.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alert_silences_alert_id", "alert_silences", ["alert_id"])
    op.create_index("ix_alert_silences_starts_at", "alert_silences", ["starts_at"])
    op.create_index("ix_alert_silences_ends_at", "alert_silences", ["ends_at"])

    op.create_table(
        "notification_channels",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("kind", sa.String(length=24), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("configuration", sa.JSON(), nullable=False),
        sa.Column("rate_limit_per_minute", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_notification_channels_kind", "notification_channels", ["kind"])

    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("channel_id", sa.String(length=36), nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=False),
        sa.Column("event_type", sa.String(length=24), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("response_code", sa.Integer(), nullable=True),
        sa.Column("error_summary", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["alert_id"], ["alert_instances.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["channel_id"], ["notification_channels.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("channel_id", "alert_id", "status", "next_attempt_at"):
        op.create_index(
            f"ix_notification_deliveries_{column}", "notification_deliveries", [column]
        )

    with op.batch_alter_table("approvals") as batch:
        batch.add_column(sa.Column("requested_by", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("target_host_id", sa.String(length=36), nullable=True))
        batch.create_foreign_key("fk_approvals_requested_by", "users", ["requested_by"], ["id"])
        batch.create_foreign_key(
            "fk_approvals_target_host_id",
            "hosts",
            ["target_host_id"],
            ["id"],
            ondelete="SET NULL",
        )
    with op.batch_alter_table("agent_tasks") as batch:
        batch.add_column(sa.Column("approval_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("requester_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("approver_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("target_host_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("verification_result", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_foreign_key(
            "fk_agent_tasks_approval_id", "approvals", ["approval_id"], ["id"], ondelete="SET NULL"
        )
        batch.create_foreign_key("fk_agent_tasks_requester_id", "users", ["requester_id"], ["id"])
        batch.create_foreign_key("fk_agent_tasks_approver_id", "users", ["approver_id"], ["id"])
        batch.create_foreign_key(
            "fk_agent_tasks_target_host_id", "hosts", ["target_host_id"], ["id"], ondelete="SET NULL"
        )
        batch.create_index("ix_agent_tasks_approval_id", ["approval_id"])


def downgrade() -> None:
    with op.batch_alter_table("agent_tasks") as batch:
        batch.drop_index("ix_agent_tasks_approval_id")
        for name in (
            "fk_agent_tasks_target_host_id",
            "fk_agent_tasks_approver_id",
            "fk_agent_tasks_requester_id",
            "fk_agent_tasks_approval_id",
        ):
            batch.drop_constraint(name, type_="foreignkey")
        for column in (
            "completed_at",
            "started_at",
            "verification_result",
            "target_host_id",
            "approver_id",
            "requester_id",
            "approval_id",
        ):
            batch.drop_column(column)
    with op.batch_alter_table("approvals") as batch:
        batch.drop_constraint("fk_approvals_target_host_id", type_="foreignkey")
        batch.drop_constraint("fk_approvals_requested_by", type_="foreignkey")
        batch.drop_column("target_host_id")
        batch.drop_column("requested_by")
    for table in (
        "notification_deliveries",
        "notification_channels",
        "alert_silences",
        "maintenance_windows",
        "alert_transitions",
        "alert_instances",
        "alert_rules",
        "service_check_results",
        "service_checks",
        "enrollment_tokens",
    ):
        op.drop_table(table)
    with op.batch_alter_table("hosts") as batch:
        batch.drop_index("ix_hosts_group_name")
        batch.drop_column("disabled_at")
        batch.drop_column("enrolled_at")
        batch.drop_column("tags")
        batch.drop_column("group_name")
        batch.drop_column("enabled")
        batch.drop_column("data_state")
