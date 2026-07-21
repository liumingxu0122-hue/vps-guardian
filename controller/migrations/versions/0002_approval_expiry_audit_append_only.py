"""Add approval expiry and enforce append-only audit rows."""

import sqlalchemy as sa
from alembic import op

revision = "0002_approval_audit_guards"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def _has_approval_expiry(bind: sa.engine.Connection) -> bool:
    columns = sa.inspect(bind).get_columns("approvals")
    return any(column["name"] == "expires_at" for column in columns)


def _create_audit_guards(bind: sa.engine.Connection) -> None:
    if bind.dialect.name == "postgresql":
        op.execute(
            """
            CREATE OR REPLACE FUNCTION guardian_reject_audit_mutation()
            RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'audit records are append-only';
            END;
            $$
            """
        )
        op.execute("DROP TRIGGER IF EXISTS guardian_audit_append_only ON audit_logs")
        op.execute(
            """
            CREATE TRIGGER guardian_audit_append_only
            BEFORE UPDATE OR DELETE ON audit_logs
            FOR EACH ROW EXECUTE FUNCTION guardian_reject_audit_mutation()
            """
        )
    elif bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS guardian_audit_no_update")
        op.execute("DROP TRIGGER IF EXISTS guardian_audit_no_delete")
        op.execute(
            """
            CREATE TRIGGER guardian_audit_no_update
            BEFORE UPDATE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'audit records are append-only');
            END
            """
        )
        op.execute(
            """
            CREATE TRIGGER guardian_audit_no_delete
            BEFORE DELETE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'audit records are append-only');
            END
            """
        )


def _drop_audit_guards(bind: sa.engine.Connection) -> None:
    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS guardian_audit_append_only ON audit_logs")
        op.execute("DROP FUNCTION IF EXISTS guardian_reject_audit_mutation()")
    elif bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS guardian_audit_no_update")
        op.execute("DROP TRIGGER IF EXISTS guardian_audit_no_delete")


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_approval_expiry(bind):
        op.add_column(
            "approvals",
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        )
        if bind.dialect.name == "postgresql":
            op.execute(
                "UPDATE approvals SET expires_at = requested_at + INTERVAL '30 minutes'"
            )
        elif bind.dialect.name == "sqlite":
            op.execute(
                "UPDATE approvals SET expires_at = datetime(requested_at, '+30 minutes')"
            )
        else:
            op.execute("UPDATE approvals SET expires_at = requested_at")
        with op.batch_alter_table("approvals") as batch:
            batch.alter_column("expires_at", nullable=False)
            batch.create_index("ix_approvals_expires_at", ["expires_at"], unique=False)
    _create_audit_guards(bind)


def downgrade() -> None:
    bind = op.get_bind()
    _drop_audit_guards(bind)
    if _has_approval_expiry(bind):
        with op.batch_alter_table("approvals") as batch:
            batch.drop_index("ix_approvals_expires_at")
            batch.drop_column("expires_at")
