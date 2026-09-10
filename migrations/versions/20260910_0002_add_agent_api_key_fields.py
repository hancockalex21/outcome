"""add agent api key fields

Revision ID: 20260910_0002
Revises: 20260910_0001
Create Date: 2026-09-10 00:00:01
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260910_0002"
down_revision: str | None = "20260910_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("agent_credentials", sa.Column("key_prefix", sa.String(length=32), nullable=True))
    op.add_column("agent_credentials", sa.Column("key_hash", sa.String(length=256), nullable=True))
    op.add_column("agent_credentials", sa.Column("scopes", sa.JSON(), nullable=True))
    op.add_column(
        "agent_credentials",
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "agent_credentials",
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.execute("UPDATE agent_credentials SET scopes = '[]' WHERE scopes IS NULL")

    op.alter_column("agent_credentials", "key_prefix", nullable=False)
    op.alter_column("agent_credentials", "key_hash", nullable=False)
    op.alter_column("agent_credentials", "scopes", nullable=False)
    op.create_index(
        "ix_agent_credentials_key_prefix",
        "agent_credentials",
        ["key_prefix"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_agent_credentials_key_prefix", table_name="agent_credentials")
    op.drop_column("agent_credentials", "last_used_at")
    op.drop_column("agent_credentials", "revoked_at")
    op.drop_column("agent_credentials", "scopes")
    op.drop_column("agent_credentials", "key_hash")
    op.drop_column("agent_credentials", "key_prefix")
