"""Add reversible identity recovery, server sessions, and recovery-code lifecycle."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010_identity_recovery"
down_revision = "0009_agent_provenance"
branch_labels = None
depends_on = None


def _columns(table: str) -> set[str]:
    return {str(column["name"]) for column in sa.inspect(op.get_bind()).get_columns(table)}


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    user_columns = _columns("users")
    with op.batch_alter_table("users") as batch:
        if "must_change_password" not in user_columns:
            batch.add_column(
                sa.Column(
                    "must_change_password",
                    sa.Boolean(),
                    server_default=sa.false(),
                    nullable=False,
                )
            )
        if "identity_setup_enforced" not in user_columns:
            batch.add_column(
                sa.Column(
                    "identity_setup_enforced",
                    sa.Boolean(),
                    server_default=sa.false(),
                    nullable=False,
                )
            )
        if "password_changed_at" not in user_columns:
            batch.add_column(
                sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True)
            )
        if "totp_enabled_at" not in user_columns:
            batch.add_column(
                sa.Column("totp_enabled_at", sa.DateTime(timezone=True), nullable=True)
            )
        if "totp_pending_secret_encrypted" not in user_columns:
            batch.add_column(
                sa.Column("totp_pending_secret_encrypted", sa.Text(), nullable=True)
            )
        if "totp_pending_created_at" not in user_columns:
            batch.add_column(
                sa.Column("totp_pending_created_at", sa.DateTime(timezone=True), nullable=True)
            )
        if "last_totp_counter" not in user_columns:
            batch.add_column(sa.Column("last_totp_counter", sa.Integer(), nullable=True))
        if "recovery_codes_confirmed_at" not in user_columns:
            batch.add_column(
                sa.Column(
                    "recovery_codes_confirmed_at",
                    sa.DateTime(timezone=True),
                    nullable=True,
                )
            )
        if "disabled_by" not in user_columns:
            batch.add_column(sa.Column("disabled_by", sa.String(length=36), nullable=True))
            batch.create_foreign_key(
                "fk_users_disabled_by_users", "users", ["disabled_by"], ["id"], ondelete="SET NULL"
            )
        if "created_by" not in user_columns:
            batch.add_column(sa.Column("created_by", sa.String(length=36), nullable=True))
            batch.create_foreign_key(
                "fk_users_created_by_users", "users", ["created_by"], ["id"], ondelete="SET NULL"
            )

    op.execute(
        sa.text(
            "UPDATE users SET totp_enabled_at = created_at "
            "WHERE totp_enabled = true AND totp_enabled_at IS NULL"
        )
    )

    tables = _tables()
    if "user_sessions" not in tables:
        op.create_table(
            "user_sessions",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column(
                "user_id",
                sa.String(length=36),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "revoked_by",
                sa.String(length=36),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("revoke_reason", sa.String(length=160), nullable=True),
            sa.Column("user_agent_digest", sa.String(length=64), nullable=False),
            sa.Column("ip_digest", sa.String(length=64), nullable=False),
            sa.Column("session_version", sa.Integer(), nullable=False),
            sa.CheckConstraint("session_version >= 1", name="ck_user_session_version"),
            sa.CheckConstraint("expires_at > issued_at", name="ck_user_session_expiry"),
        )
        op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
        op.create_index("ix_user_sessions_expires_at", "user_sessions", ["expires_at"])

    if "recovery_codes" not in tables:
        op.create_table(
            "recovery_codes",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column(
                "user_id",
                sa.String(length=36),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("code_hash", sa.String(length=64), nullable=False),
            sa.Column("batch_id", sa.String(length=36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint(
                "user_id", "code_hash", name="uq_recovery_code_user_hash"
            ),
        )
        op.create_index("ix_recovery_codes_user_id", "recovery_codes", ["user_id"])
        op.create_index(
            "ix_recovery_codes_user_batch", "recovery_codes", ["user_id", "batch_id"]
        )


def downgrade() -> None:
    op.drop_index("ix_recovery_codes_user_batch", table_name="recovery_codes")
    op.drop_index("ix_recovery_codes_user_id", table_name="recovery_codes")
    op.drop_table("recovery_codes")
    op.drop_index("ix_user_sessions_expires_at", table_name="user_sessions")
    op.drop_index("ix_user_sessions_user_id", table_name="user_sessions")
    op.drop_table("user_sessions")
    with op.batch_alter_table("users") as batch:
        for column in (
            "created_by",
            "disabled_by",
            "recovery_codes_confirmed_at",
            "last_totp_counter",
            "totp_pending_created_at",
            "totp_pending_secret_encrypted",
            "totp_enabled_at",
            "password_changed_at",
            "must_change_password",
            "identity_setup_enforced",
        ):
            batch.drop_column(column)
