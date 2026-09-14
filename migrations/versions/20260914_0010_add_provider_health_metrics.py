"""add provider health metrics

Revision ID: 20260914_0010
Revises: 20260914_0009
Create Date: 2026-09-14 00:00:05
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260914_0010"
down_revision: str | None = "20260914_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("provider_metrics") as batch_op:
        batch_op.add_column(sa.Column("capability", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("metrics_version", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("window_start", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("window_end", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("request_count", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("success_count", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("failure_count", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("timeout_count", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("rate_limited_count", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("system_failure_count", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("consecutive_failures", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("latency_count", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("latency_total_ms", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("latency_max_ms", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("current_health", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("circuit_state", sa.String(length=64), nullable=True))
        batch_op.add_column(
            sa.Column("circuit_opened_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column("circuit_retry_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(sa.Column("manually_disabled", sa.Boolean(), nullable=True))

        batch_op.alter_column("capability", nullable=False)
        batch_op.alter_column("metrics_version", nullable=False)
        batch_op.alter_column("window_start", nullable=False)
        batch_op.alter_column("window_end", nullable=False)
        batch_op.alter_column("request_count", nullable=False)
        batch_op.alter_column("success_count", nullable=False)
        batch_op.alter_column("failure_count", nullable=False)
        batch_op.alter_column("timeout_count", nullable=False)
        batch_op.alter_column("rate_limited_count", nullable=False)
        batch_op.alter_column("system_failure_count", nullable=False)
        batch_op.alter_column("consecutive_failures", nullable=False)
        batch_op.alter_column("latency_count", nullable=False)
        batch_op.alter_column("latency_total_ms", nullable=False)
        batch_op.alter_column("latency_max_ms", nullable=False)
        batch_op.alter_column("current_health", nullable=False)
        batch_op.alter_column("circuit_state", nullable=False)
        batch_op.alter_column("manually_disabled", nullable=False)
        batch_op.create_unique_constraint(
            "uq_provider_metrics_capability",
            ["account_id", "provider_id", "capability"],
        )

    op.create_index(
        "ix_provider_metrics_provider_capability",
        "provider_metrics",
        ["provider_id", "capability"],
    )


def downgrade() -> None:
    op.drop_index("ix_provider_metrics_provider_capability", table_name="provider_metrics")
    with op.batch_alter_table("provider_metrics") as batch_op:
        batch_op.drop_constraint("uq_provider_metrics_capability", type_="unique")
        batch_op.drop_column("manually_disabled")
        batch_op.drop_column("circuit_retry_at")
        batch_op.drop_column("circuit_opened_at")
        batch_op.drop_column("circuit_state")
        batch_op.drop_column("current_health")
        batch_op.drop_column("latency_max_ms")
        batch_op.drop_column("latency_total_ms")
        batch_op.drop_column("latency_count")
        batch_op.drop_column("consecutive_failures")
        batch_op.drop_column("system_failure_count")
        batch_op.drop_column("rate_limited_count")
        batch_op.drop_column("timeout_count")
        batch_op.drop_column("failure_count")
        batch_op.drop_column("success_count")
        batch_op.drop_column("request_count")
        batch_op.drop_column("window_end")
        batch_op.drop_column("window_start")
        batch_op.drop_column("metrics_version")
        batch_op.drop_column("capability")
