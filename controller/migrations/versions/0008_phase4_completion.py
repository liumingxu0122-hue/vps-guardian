"""Add Phase 4 user, alert, incident, and notification lifecycle fields."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008_phase4_completion"
down_revision = "0007_multivps_alerts"
branch_labels = None
depends_on = None


def _columns(table: str) -> set[str]:
    return {str(column["name"]) for column in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    user_columns = _columns("users")
    with op.batch_alter_table("users") as batch:
        if "scopes" not in user_columns:
            batch.add_column(
                sa.Column("scopes", sa.JSON(), server_default=sa.text("'[]'"), nullable=False)
            )
        if "session_version" not in user_columns:
            batch.add_column(
                sa.Column("session_version", sa.Integer(), server_default="1", nullable=False)
            )
        if "last_login_at" not in user_columns:
            batch.add_column(sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
        if "disabled_at" not in user_columns:
            batch.add_column(sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True))

    alert_columns = _columns("alert_instances")
    with op.batch_alter_table("alert_instances") as batch:
        if "assigned_to" not in alert_columns:
            batch.add_column(sa.Column("assigned_to", sa.String(length=36), nullable=True))
            batch.create_foreign_key(
                "fk_alert_instances_assigned_to",
                "users",
                ["assigned_to"],
                ["id"],
            )
        if "closed_at" not in alert_columns:
            batch.add_column(sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True))

    channel_columns = _columns("notification_channels")
    with op.batch_alter_table("notification_channels") as batch:
        if "event_scope" not in channel_columns:
            batch.add_column(
                sa.Column(
                    "event_scope", sa.JSON(), server_default=sa.text("'[]'"), nullable=False
                )
            )
        if "severity_filter" not in channel_columns:
            batch.add_column(
                sa.Column(
                    "severity_filter", sa.JSON(), server_default=sa.text("'[]'"), nullable=False
                )
            )
        if "retry_policy" not in channel_columns:
            batch.add_column(
                sa.Column(
                    "retry_policy", sa.JSON(), server_default=sa.text("'{}'"), nullable=False
                )
            )

    incident_columns = _columns("incidents")
    with op.batch_alter_table("incidents") as batch:
        if "assigned_to" not in incident_columns:
            batch.add_column(sa.Column("assigned_to", sa.String(length=36), nullable=True))
            batch.create_foreign_key(
                "fk_incidents_assigned_to",
                "users",
                ["assigned_to"],
                ["id"],
            )
        if "acknowledged_at" not in incident_columns:
            batch.add_column(sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True))
        if "updated_at" not in incident_columns:
            batch.add_column(
                sa.Column(
                    "updated_at",
                    sa.DateTime(timezone=True),
                    server_default=sa.func.now(),
                    nullable=False,
                )
            )
        if "resolution_summary" not in incident_columns:
            batch.add_column(sa.Column("resolution_summary", sa.Text(), nullable=True))
        if "postmortem" not in incident_columns:
            batch.add_column(sa.Column("postmortem", sa.Text(), nullable=True))
    op.execute(
        sa.text("UPDATE incidents SET status = 'mitigating' WHERE status = 'mitigated'")
    )


def downgrade() -> None:
    op.execute(
        sa.text("UPDATE incidents SET status = 'mitigated' WHERE status = 'mitigating'")
    )
    with op.batch_alter_table("incidents") as batch:
        for column in (
            "postmortem",
            "resolution_summary",
            "updated_at",
            "acknowledged_at",
            "assigned_to",
        ):
            batch.drop_column(column)
    with op.batch_alter_table("notification_channels") as batch:
        for column in ("retry_policy", "severity_filter", "event_scope"):
            batch.drop_column(column)
    with op.batch_alter_table("alert_instances") as batch:
        batch.drop_column("closed_at")
        batch.drop_column("assigned_to")
    with op.batch_alter_table("users") as batch:
        for column in ("disabled_at", "last_login_at", "session_version", "scopes"):
            batch.drop_column(column)
