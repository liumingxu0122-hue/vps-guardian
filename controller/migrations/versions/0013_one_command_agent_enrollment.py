"""Add one-command Agent enrollment sessions and progress events.

Revision ID: 0013_agent_enrollment
Revises: 0012_persistent_sessions
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision = "0013_agent_enrollment"
down_revision = "0012_persistent_sessions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

STATUSES = (
    "waiting",
    "installer_downloaded",
    "installer_verified",
    "prerequisites_checked",
    "agent_downloaded",
    "agent_verified",
    "local_key_generated",
    "csr_submitted",
    "certificate_issued",
    "service_installed",
    "service_started",
    "heartbeat_received",
    "completed",
    "failed",
    "expired",
    "revoked",
)


def _status_check(column: str) -> str:
    values = ", ".join(f"'{value}'" for value in STATUSES)
    return f"{column} IN ({values})"


def _columns(table: str) -> set[str]:
    return {str(column["name"]) for column in sa.inspect(op.get_bind()).get_columns(table)}


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _checks(table: str) -> set[str]:
    return {
        str(constraint["name"])
        for constraint in sa.inspect(op.get_bind()).get_check_constraints(table)
        if constraint.get("name")
    }


def _indexes(table: str) -> set[str]:
    return {
        str(index["name"])
        for index in sa.inspect(op.get_bind()).get_indexes(table)
        if index.get("name")
    }


def _has_unique(table: str, columns: list[str]) -> bool:
    expected = set(columns)
    return any(
        set(constraint.get("column_names") or []) == expected
        for constraint in sa.inspect(op.get_bind()).get_unique_constraints(table)
    )


def upgrade() -> None:
    host_columns = _columns("hosts")
    if "notes" not in host_columns:
        op.add_column("hosts", sa.Column("notes", sa.String(length=500), nullable=True))
    if "desired_os_family" not in host_columns:
        op.add_column(
            "hosts",
            sa.Column(
                "desired_os_family",
                sa.String(length=32),
                server_default="auto",
                nullable=False,
            ),
        )
    if "ck_hosts_desired_os_family" not in _checks("hosts"):
        with op.batch_alter_table("hosts") as batch:
            batch.create_check_constraint(
                "ck_hosts_desired_os_family",
                "desired_os_family IN ('auto', 'debian', 'rhel', 'fedora', 'alpine', 'generic')",
            )

    token_columns = _columns("enrollment_tokens")
    added_status = "status" not in token_columns
    additions = (
        ("status", sa.Column("status", sa.String(length=32), server_default="waiting", nullable=False)),
        ("progress_token_hash", sa.Column("progress_token_hash", sa.String(length=64), nullable=True)),
        ("status_sequence", sa.Column("status_sequence", sa.Integer(), server_default="0", nullable=False)),
        ("status_updated_at", sa.Column("status_updated_at", sa.DateTime(timezone=True), nullable=True)),
        ("source_cidr", sa.Column("source_cidr", sa.String(length=64), nullable=True)),
        ("os_family", sa.Column("os_family", sa.String(length=32), server_default="auto", nullable=False)),
        ("installer_version", sa.Column("installer_version", sa.String(length=64), nullable=True)),
        ("agent_version", sa.Column("agent_version", sa.String(length=64), nullable=True)),
        ("error_code", sa.Column("error_code", sa.String(length=64), nullable=True)),
        ("error_step", sa.Column("error_step", sa.String(length=32), nullable=True)),
        ("error_summary", sa.Column("error_summary", sa.String(length=240), nullable=True)),
        ("rolled_back", sa.Column("rolled_back", sa.Boolean(), server_default=sa.false(), nullable=False)),
        ("completed_at", sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True)),
    )
    for name, column in additions:
        if name not in token_columns:
            op.add_column("enrollment_tokens", column)
    if added_status:
        op.execute(
            sa.text(
                "UPDATE enrollment_tokens "
                "SET status_updated_at = created_at, "
                "status = CASE "
                "WHEN revoked_at IS NOT NULL THEN 'revoked' "
                "WHEN used_at IS NOT NULL THEN 'certificate_issued' "
                "ELSE 'waiting' END, "
                "status_sequence = CASE WHEN used_at IS NOT NULL THEN 8 ELSE 0 END"
            )
        )
    token_checks = _checks("enrollment_tokens")
    with op.batch_alter_table("enrollment_tokens") as batch:
        if "status_updated_at" not in token_columns:
            batch.alter_column(
                "status_updated_at",
                existing_type=sa.DateTime(timezone=True),
                nullable=False,
            )
        if "ck_enrollment_token_status" not in token_checks:
            batch.create_check_constraint(
                "ck_enrollment_token_status", _status_check("status")
            )
        if "ck_enrollment_token_status_sequence" not in token_checks:
            batch.create_check_constraint(
                "ck_enrollment_token_status_sequence",
                "status_sequence >= 0 AND status_sequence <= 12",
            )
        if "ck_enrollment_progress_token_hash_length" not in token_checks:
            batch.create_check_constraint(
                "ck_enrollment_progress_token_hash_length",
                "progress_token_hash IS NULL OR length(progress_token_hash) = 64",
            )
        if not _has_unique("enrollment_tokens", ["progress_token_hash"]):
            batch.create_unique_constraint(
                "uq_enrollment_tokens_progress_token_hash",
                ["progress_token_hash"],
            )
    token_indexes = _indexes("enrollment_tokens")
    if "ix_enrollment_tokens_status" not in token_indexes:
        op.create_index(
            "ix_enrollment_tokens_status", "enrollment_tokens", ["status"]
        )
    if "ix_enrollment_tokens_host_created" not in token_indexes:
        op.create_index(
            "ix_enrollment_tokens_host_created",
            "enrollment_tokens",
            ["host_id", "created_at"],
        )

    if "enrollment_events" in _tables():
        return
    op.create_table(
        "enrollment_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("enrollment_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("status_sequence", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_summary", sa.String(length=240), nullable=True),
        sa.Column("rolled_back", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.CheckConstraint(
            _status_check("status"), name="ck_enrollment_event_status"
        ),
        sa.CheckConstraint(
            "status_sequence >= 0 AND status_sequence <= 12",
            name="ck_enrollment_event_status_sequence",
        ),
        sa.ForeignKeyConstraint(
            ["enrollment_id"], ["enrollment_tokens.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "enrollment_id", "status", name="uq_enrollment_event_status"
        ),
    )
    op.create_index(
        "ix_enrollment_events_enrollment_id",
        "enrollment_events",
        ["enrollment_id"],
    )
    op.execute(
        sa.text(
            "INSERT INTO enrollment_events "
            "(enrollment_id, status, status_sequence, occurred_at, rolled_back) "
            "SELECT id, status, status_sequence, status_updated_at, false "
            "FROM enrollment_tokens"
        )
    )


def downgrade() -> None:
    op.drop_index(
        "ix_enrollment_events_enrollment_id", table_name="enrollment_events"
    )
    op.drop_table("enrollment_events")
    op.drop_index(
        "ix_enrollment_tokens_host_created", table_name="enrollment_tokens"
    )
    op.drop_index("ix_enrollment_tokens_status", table_name="enrollment_tokens")
    with op.batch_alter_table("enrollment_tokens") as batch:
        batch.drop_constraint(
            "uq_enrollment_tokens_progress_token_hash", type_="unique"
        )
        batch.drop_constraint(
            "ck_enrollment_progress_token_hash_length", type_="check"
        )
        batch.drop_constraint(
            "ck_enrollment_token_status_sequence", type_="check"
        )
        batch.drop_constraint("ck_enrollment_token_status", type_="check")
        for column in (
            "completed_at",
            "rolled_back",
            "error_summary",
            "error_step",
            "error_code",
            "agent_version",
            "installer_version",
            "os_family",
            "source_cidr",
            "status_updated_at",
            "status_sequence",
            "status",
            "progress_token_hash",
        ):
            batch.drop_column(column)
    with op.batch_alter_table("hosts") as batch:
        batch.drop_constraint("ck_hosts_desired_os_family", type_="check")
        batch.drop_column("desired_os_family")
        batch.drop_column("notes")
