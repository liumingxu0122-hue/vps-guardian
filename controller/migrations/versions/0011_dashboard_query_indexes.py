"""Add reversible indexes for the UI V3 dashboard read paths."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0011_dashboard_query_indexes"
down_revision = "0010_identity_recovery"
branch_labels = None
depends_on = None

INDEXES = (
    (
        "ix_metric_snapshots_host_collected",
        "metric_snapshots",
        ["host_id", "collected_at"],
    ),
    (
        "ix_incidents_status_severity_updated",
        "incidents",
        ["status", "severity", "updated_at"],
    ),
    (
        "ix_recovery_points_verified_verified_at",
        "recovery_points",
        ["verified", "verified_at"],
    ),
)


def _index_names(table: str) -> set[str]:
    return {
        str(index["name"])
        for index in sa.inspect(op.get_bind()).get_indexes(table)
        if index.get("name")
    }


def upgrade() -> None:
    for name, table, columns in INDEXES:
        if name not in _index_names(table):
            op.create_index(name, table, columns, unique=False)


def downgrade() -> None:
    for name, table, _columns in reversed(INDEXES):
        if name in _index_names(table):
            op.drop_index(name, table_name=table)
