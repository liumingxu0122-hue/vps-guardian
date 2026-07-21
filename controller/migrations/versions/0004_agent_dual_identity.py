"""Add make-before-break Agent identities and a CAS version."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0004_agent_dual_identity"
down_revision = "0003_agent_cert_serial_unique"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    active_agents_without_serial = bind.scalar(
        sa.text(
            """
            SELECT COUNT(*)
            FROM agents
            WHERE certificate_serial IS NULL AND revoked_at IS NULL
            """
        )
    )
    if active_agents_without_serial:
        raise RuntimeError(
            "active legacy Agents require a normalized certificate serial before dual-identity migration"
        )
    inspector = sa.inspect(bind)
    if not any(column["name"] == "identity_version" for column in inspector.get_columns("agents")):
        op.add_column(
            "agents",
            sa.Column(
                "identity_version", sa.Integer(), nullable=False, server_default=sa.text("1")
            ),
        )

    inspector = sa.inspect(bind)
    if "agent_identities" not in inspector.get_table_names():
        op.create_table(
            "agent_identities",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("agent_id", sa.String(length=36), nullable=False),
            sa.Column("generation", sa.Integer(), nullable=False),
            sa.Column("state", sa.String(length=16), nullable=False),
            sa.Column("signing_public_key", sa.Text(), nullable=False),
            sa.Column("certificate_fingerprint", sa.String(length=128), nullable=False),
            sa.Column("certificate_serial", sa.String(length=128), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.CheckConstraint(
                "state IN ('pending', 'active', 'retired')",
                name="ck_agent_identity_state",
            ),
            sa.CheckConstraint("generation >= 1", name="ck_agent_identity_generation"),
            sa.UniqueConstraint(
                "agent_id",
                "generation",
                name="uq_agent_identity_generation",
            ),
            sa.UniqueConstraint("certificate_fingerprint"),
            sa.UniqueConstraint("certificate_serial"),
        )

    index_names = {
        index["name"] for index in sa.inspect(bind).get_indexes("agent_identities")
    }
    if "ix_agent_identities_agent_id" not in index_names:
        op.create_index(
            "ix_agent_identities_agent_id",
            "agent_identities",
            ["agent_id"],
            unique=False,
        )
    if "ix_agent_identities_state" not in index_names:
        op.create_index(
            "ix_agent_identities_state",
            "agent_identities",
            ["state"],
            unique=False,
        )
    if "uq_agent_identity_one_active" not in index_names:
        op.create_index(
            "uq_agent_identity_one_active",
            "agent_identities",
            ["agent_id"],
            unique=True,
            sqlite_where=sa.text("state = 'active'"),
            postgresql_where=sa.text("state = 'active'"),
        )
    if "uq_agent_identity_one_pending" not in index_names:
        op.create_index(
            "uq_agent_identity_one_pending",
            "agent_identities",
            ["agent_id"],
            unique=True,
            sqlite_where=sa.text("state = 'pending'"),
            postgresql_where=sa.text("state = 'pending'"),
        )

    agents = bind.execute(
        sa.text(
            """
            SELECT id, signing_public_key, certificate_fingerprint, certificate_serial
            FROM agents
            WHERE NOT EXISTS (
                SELECT 1 FROM agent_identities WHERE agent_identities.agent_id = agents.id
            )
            """
        )
    ).mappings()
    now = datetime.now(UTC)
    for agent in agents:
        bind.execute(
            sa.text(
                """
                INSERT INTO agent_identities
                    (id, agent_id, generation, state, signing_public_key,
                     certificate_fingerprint, certificate_serial, expires_at,
                     verified_at, activated_at, retired_at, created_at)
                VALUES
                    (:id, :agent_id, 1, 'active', :signing_public_key,
                     :certificate_fingerprint, :certificate_serial, NULL,
                     :verified_at, :activated_at, NULL, :created_at)
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "agent_id": agent["id"],
                "signing_public_key": agent["signing_public_key"],
                "certificate_fingerprint": agent["certificate_fingerprint"],
                "certificate_serial": agent["certificate_serial"],
                "verified_at": now,
                "activated_at": now,
                "created_at": now,
            },
        )


def downgrade() -> None:
    op.drop_index("uq_agent_identity_one_pending", table_name="agent_identities")
    op.drop_index("uq_agent_identity_one_active", table_name="agent_identities")
    op.drop_index("ix_agent_identities_state", table_name="agent_identities")
    op.drop_index("ix_agent_identities_agent_id", table_name="agent_identities")
    op.drop_table("agent_identities")
    with op.batch_alter_table("agents") as batch:
        batch.drop_column("identity_version")
