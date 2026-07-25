"""Add immutable Agent build provenance reported by authenticated heartbeats."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009_agent_provenance"
down_revision = "0008_phase4_completion"
branch_labels = None
depends_on = None


def _columns(table: str) -> set[str]:
    return {str(column["name"]) for column in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    columns = _columns("agents")
    with op.batch_alter_table("agents") as batch:
        if "build_git_sha" not in columns:
            batch.add_column(sa.Column("build_git_sha", sa.String(length=40), nullable=True))
        if "build_id" not in columns:
            batch.add_column(sa.Column("build_id", sa.String(length=128), nullable=True))
        if "build_time" not in columns:
            batch.add_column(sa.Column("build_time", sa.String(length=64), nullable=True))
        if "go_version" not in columns:
            batch.add_column(sa.Column("go_version", sa.String(length=64), nullable=True))
        if "platform_os" not in columns:
            batch.add_column(sa.Column("platform_os", sa.String(length=32), nullable=True))
        if "platform_arch" not in columns:
            batch.add_column(sa.Column("platform_arch", sa.String(length=32), nullable=True))
        if "build_dirty" not in columns:
            batch.add_column(sa.Column("build_dirty", sa.Boolean(), nullable=True))
        if "binary_sha256" not in columns:
            batch.add_column(sa.Column("binary_sha256", sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("agents") as batch:
        for column in (
            "binary_sha256",
            "build_dirty",
            "platform_arch",
            "platform_os",
            "go_version",
            "build_time",
            "build_id",
            "build_git_sha",
        ):
            batch.drop_column(column)
