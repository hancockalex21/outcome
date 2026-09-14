"""add evidence lineage tracking

Revision ID: 20260914_0009
Revises: 20260914_0008
Create Date: 2026-09-14 00:00:04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260914_0009"
down_revision: str | None = "20260914_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_lineages",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "account_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("accounts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "evidence_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("evidence_items.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "verification_request_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("verification_requests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("provider_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("source_reference", sa.String(length=1024), nullable=True),
        sa.Column("source_class", sa.String(length=64), nullable=False),
        sa.Column("lineage_type", sa.String(length=64), nullable=False),
        sa.Column("publisher_identity", sa.String(length=255), nullable=True),
        sa.Column("canonical_source_identity", sa.String(length=255), nullable=True),
        sa.Column("origin_reference", sa.String(length=1024), nullable=True),
        sa.Column("origin_identity_hash", sa.String(length=128), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lineage_version", sa.String(length=128), nullable=False),
        sa.Column("lineage_metadata", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "account_id",
            "evidence_id",
            "lineage_version",
            name="uq_evidence_lineages_version",
        ),
    )
    op.create_table(
        "evidence_lineage_relationships",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "account_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("accounts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "verification_request_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("verification_requests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "parent_evidence_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("evidence_items.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "child_evidence_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("evidence_items.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("relationship_type", sa.String(length=64), nullable=False),
        sa.Column("lineage_version", sa.String(length=128), nullable=False),
        sa.Column("reason_code", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "account_id",
            "parent_evidence_id",
            "child_evidence_id",
            "relationship_type",
            "lineage_version",
            name="uq_evidence_lineage_relationships_edge",
        ),
    )
    op.create_index(
        "ix_evidence_lineages_account_created_at",
        "evidence_lineages",
        ["account_id", "created_at"],
    )
    op.create_index(
        "ix_evidence_lineages_request",
        "evidence_lineages",
        ["account_id", "verification_request_id"],
    )
    op.create_index(
        "ix_evidence_lineage_relationships_account_created_at",
        "evidence_lineage_relationships",
        ["account_id", "created_at"],
    )
    op.create_index(
        "ix_evidence_lineage_relationships_request",
        "evidence_lineage_relationships",
        ["account_id", "verification_request_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_evidence_lineage_relationships_request",
        table_name="evidence_lineage_relationships",
    )
    op.drop_index(
        "ix_evidence_lineage_relationships_account_created_at",
        table_name="evidence_lineage_relationships",
    )
    op.drop_index("ix_evidence_lineages_request", table_name="evidence_lineages")
    op.drop_index(
        "ix_evidence_lineages_account_created_at",
        table_name="evidence_lineages",
    )
    op.drop_table("evidence_lineage_relationships")
    op.drop_table("evidence_lineages")
