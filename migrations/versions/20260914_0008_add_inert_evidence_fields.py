"""add inert evidence fields

Revision ID: 20260914_0008
Revises: 20260914_0007
Create Date: 2026-09-14 00:00:03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260914_0008"
down_revision: str | None = "20260914_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("evidence_items") as batch_op:
        batch_op.add_column(sa.Column("provider_id", sa.Uuid(as_uuid=True), nullable=True))
        batch_op.add_column(sa.Column("provider_alias", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("source_uri", sa.String(length=1024), nullable=True))
        batch_op.add_column(sa.Column("source_class", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("content_type", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("normalized_text", sa.String(length=4096), nullable=True))
        batch_op.add_column(sa.Column("extraction_method", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("extraction_version", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("extraction_quality", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("authority_metadata", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("lineage_metadata", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("size_metadata", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("safety_flags", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("truncated", sa.Boolean(), nullable=True))

        batch_op.alter_column("source_class", nullable=False)
        batch_op.alter_column("content_type", nullable=False)
        batch_op.alter_column("normalized_text", nullable=False)
        batch_op.alter_column("extraction_method", nullable=False)
        batch_op.alter_column("extraction_version", nullable=False)
        batch_op.alter_column("extraction_quality", nullable=False)
        batch_op.alter_column("authority_metadata", nullable=False)
        batch_op.alter_column("lineage_metadata", nullable=False)
        batch_op.alter_column("size_metadata", nullable=False)
        batch_op.alter_column("safety_flags", nullable=False)
        batch_op.alter_column("observed_at", nullable=False)
        batch_op.alter_column("truncated", nullable=False)


def downgrade() -> None:
    with op.batch_alter_table("evidence_items") as batch_op:
        batch_op.drop_column("truncated")
        batch_op.drop_column("observed_at")
        batch_op.drop_column("safety_flags")
        batch_op.drop_column("size_metadata")
        batch_op.drop_column("lineage_metadata")
        batch_op.drop_column("authority_metadata")
        batch_op.drop_column("extraction_quality")
        batch_op.drop_column("extraction_version")
        batch_op.drop_column("extraction_method")
        batch_op.drop_column("normalized_text")
        batch_op.drop_column("content_type")
        batch_op.drop_column("source_class")
        batch_op.drop_column("source_uri")
        batch_op.drop_column("provider_alias")
        batch_op.drop_column("provider_id")
