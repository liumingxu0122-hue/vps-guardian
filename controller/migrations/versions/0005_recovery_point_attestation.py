"""Add evidence-bound CAS verification to RecoveryPoints."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0005_recovery_attestation"
down_revision = "0004_agent_dual_identity"
branch_labels = None
depends_on = None


def _legacy_timestamp(value: object) -> str:
    if isinstance(value, datetime):
        timestamp = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return timestamp.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    return str(value)


def _legacy_attestation_digest(row: sa.RowMapping) -> str:
    payload: dict[str, Any] = {
        "schema": "vps-guardian/recovery-verification-legacy-import/v1",
        "recovery_point": {
            "id": str(row["id"]),
            "snapshot_id": str(row["snapshot_id"]).lower(),
            "manifest_checksum": str(row["checksum"]).lower(),
        },
        "verification": {
            "verifier": "guardian-migration",
            "method": "legacy-inline-isolated-restore",
            "completed_at": _legacy_timestamp(row["effective_verified_at"]),
        },
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _hex_digest_constraint() -> str:
    remainder = "lower(attestation_digest)"
    for character in "0123456789abcdef":
        remainder = f"replace({remainder}, '{character}', '')"
    return (
        "attestation_digest IS NULL OR "
        "(length(attestation_digest) = 64 "
        "AND lower(attestation_digest) = attestation_digest "
        f"AND {remainder} = '')"
    )


def upgrade() -> None:
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("recovery_points")}
    if "verification_version" not in columns:
        op.add_column(
            "recovery_points",
            sa.Column(
                "verification_version",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("0"),
            ),
        )
    if "attestation_digest" not in columns:
        op.add_column(
            "recovery_points",
            sa.Column("attestation_digest", sa.String(length=64), nullable=True),
        )

    rows = bind.execute(
        sa.text(
            """
            SELECT id, snapshot_id, checksum, verified,
                   COALESCE(verified_at, created_at) AS effective_verified_at,
                   attestation_digest
            FROM recovery_points
            """
        )
    ).mappings()
    for row in rows:
        if bool(row["verified"]):
            existing_digest = row["attestation_digest"]
            digest = (
                str(existing_digest).lower()
                if existing_digest and re.fullmatch(r"[A-Fa-f0-9]{64}", str(existing_digest))
                else _legacy_attestation_digest(row)
            )
            bind.execute(
                sa.text(
                    """
                    UPDATE recovery_points
                    SET verified_at = :verified_at,
                        verification_version = CASE
                            WHEN COALESCE(verification_version, 0) < 1 THEN 1
                            ELSE verification_version
                        END,
                        attestation_digest = :attestation_digest
                    WHERE id = :id
                    """
                ),
                {
                    "id": row["id"],
                    "verified_at": row["effective_verified_at"],
                    "attestation_digest": digest,
                },
            )
        else:
            bind.execute(
                sa.text(
                    """
                    UPDATE recovery_points
                    SET verified_at = NULL,
                        verification_version = 0,
                        attestation_digest = NULL
                    WHERE id = :id
                    """
                ),
                {"id": row["id"]},
            )

    check_names = {
        constraint["name"]
        for constraint in sa.inspect(bind).get_check_constraints("recovery_points")
    }
    with op.batch_alter_table("recovery_points") as batch:
        if "ck_recovery_point_verification_version" not in check_names:
            batch.create_check_constraint(
                "ck_recovery_point_verification_version",
                "verification_version >= 0",
            )
        if "ck_recovery_point_verification_state" not in check_names:
            batch.create_check_constraint(
                "ck_recovery_point_verification_state",
                "(verified = false AND verified_at IS NULL "
                "AND attestation_digest IS NULL AND verification_version = 0) OR "
                "(verified = true AND verified_at IS NOT NULL "
                "AND attestation_digest IS NOT NULL AND verification_version >= 1)",
            )
        if "ck_recovery_point_attestation_digest" not in check_names:
            batch.create_check_constraint(
                "ck_recovery_point_attestation_digest",
                _hex_digest_constraint(),
            )


def downgrade() -> None:
    bind = op.get_bind()
    check_names = {
        constraint["name"]
        for constraint in sa.inspect(bind).get_check_constraints("recovery_points")
    }
    columns = {column["name"] for column in sa.inspect(bind).get_columns("recovery_points")}
    with op.batch_alter_table("recovery_points") as batch:
        for name in (
            "ck_recovery_point_attestation_digest",
            "ck_recovery_point_verification_state",
            "ck_recovery_point_verification_version",
        ):
            if name in check_names:
                batch.drop_constraint(name, type_="check")
        if "attestation_digest" in columns:
            batch.drop_column("attestation_digest")
        if "verification_version" in columns:
            batch.drop_column("verification_version")
