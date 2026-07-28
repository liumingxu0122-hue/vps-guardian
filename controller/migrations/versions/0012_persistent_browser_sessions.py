"""Add persistent opaque browser sessions and step-up state.

Revision ID: 0012_persistent_browser_sessions
Revises: 0011_dashboard_query_indexes
"""

import hashlib
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision = "0012_persistent_sessions"
down_revision = "0011_dashboard_query_indexes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("user_sessions", sa.Column("token_hash", sa.String(length=64), nullable=True))
    op.add_column(
        "user_sessions", sa.Column("csrf_secret_hash", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "user_sessions", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "user_sessions", sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "user_sessions", sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "user_sessions",
        sa.Column("remember_me", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column(
        "user_sessions", sa.Column("step_up_until", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "user_sessions", sa.Column("user_agent_summary", sa.String(length=160), nullable=True)
    )
    op.add_column("user_sessions", sa.Column("ip_summary", sa.String(length=80), nullable=True))
    op.add_column(
        "user_sessions",
        sa.Column("created_via", sa.String(length=32), server_default="legacy", nullable=False),
    )
    op.add_column(
        "user_sessions",
        sa.Column(
            "last_activity_type",
            sa.String(length=64),
            server_default="legacy",
            nullable=False,
        ),
    )
    op.add_column("user_sessions", sa.Column("device_name", sa.String(length=120), nullable=True))
    op.add_column(
        "user_sessions",
        sa.Column("rotated_from_session_id", sa.String(length=36), nullable=True),
    )
    sessions = sa.table(
        "user_sessions",
        sa.column("id", sa.String(length=36)),
        sa.column("token_hash", sa.String(length=64)),
    )
    bind = op.get_bind()
    legacy_session_ids = bind.execute(
        sa.select(sessions.c.id).where(sessions.c.token_hash.is_(None))
    ).scalars()
    for session_id in legacy_session_ids:
        bind.execute(
            sessions.update()
            .where(sessions.c.id == session_id)
            .values(token_hash=hashlib.sha256(f"legacy:{session_id}".encode()).hexdigest())
        )
    op.execute(
        sa.text(
            """
            UPDATE user_sessions
               SET last_seen_at = issued_at,
                   idle_expires_at = expires_at,
                   absolute_expires_at = expires_at,
                   user_agent_summary = 'unknown:unknown',
                   ip_summary = 'protected'
             WHERE last_seen_at IS NULL
            """
        )
    )
    with op.batch_alter_table("user_sessions") as batch:
        batch.alter_column("token_hash", existing_type=sa.String(length=64), nullable=False)
        batch.alter_column(
            "last_seen_at", existing_type=sa.DateTime(timezone=True), nullable=False
        )
        batch.alter_column(
            "idle_expires_at", existing_type=sa.DateTime(timezone=True), nullable=False
        )
        batch.alter_column(
            "absolute_expires_at", existing_type=sa.DateTime(timezone=True), nullable=False
        )
        batch.alter_column(
            "user_agent_summary", existing_type=sa.String(length=160), nullable=False
        )
        batch.alter_column("ip_summary", existing_type=sa.String(length=80), nullable=False)
        batch.create_check_constraint(
            "ck_user_session_idle_absolute", "idle_expires_at <= absolute_expires_at"
        )
    op.create_index(
        "ix_user_sessions_token_hash", "user_sessions", ["token_hash"], unique=True
    )
    op.create_index(
        "ix_user_sessions_idle_expires_at", "user_sessions", ["idle_expires_at"]
    )
    op.create_index(
        "ix_user_sessions_absolute_expires_at", "user_sessions", ["absolute_expires_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_user_sessions_absolute_expires_at", table_name="user_sessions")
    op.drop_index("ix_user_sessions_idle_expires_at", table_name="user_sessions")
    op.drop_index("ix_user_sessions_token_hash", table_name="user_sessions")
    with op.batch_alter_table("user_sessions") as batch:
        batch.drop_constraint("ck_user_session_idle_absolute", type_="check")
    for column in (
        "rotated_from_session_id",
        "device_name",
        "last_activity_type",
        "created_via",
        "ip_summary",
        "user_agent_summary",
        "step_up_until",
        "remember_me",
        "absolute_expires_at",
        "idle_expires_at",
        "last_seen_at",
        "csrf_secret_hash",
        "token_hash",
    ):
        op.drop_column("user_sessions", column)
