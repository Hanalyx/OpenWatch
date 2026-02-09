"""Add posture_snapshots table for temporal compliance

Revision ID: 019_posture_snapshots
Revises: 20260209_1200_018_add_framework_mappings_table
Create Date: 2026-02-09

Part of Phase 2: Temporal Compliance (Aegis Integration Plan)
Enables point-in-time compliance posture queries per NIST SP 800-137.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers
revision = "019_posture_snapshots"
down_revision = "20260209_1200_018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create posture_snapshots table (idempotent)."""
    # Check if table already exists (idempotent migration)
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'posture_snapshots')")
    )
    if result.scalar():
        # Table exists, just create indexes if not present
        op.execute(
            "CREATE INDEX IF NOT EXISTS ix_posture_snapshots_host_date_desc "
            "ON posture_snapshots (host_id, snapshot_date DESC)"
        )
        return

    op.create_table(
        "posture_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, index=True),
        sa.Column(
            "host_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("hosts.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("snapshot_date", sa.DateTime, nullable=False, index=True),
        # Aggregated compliance state
        sa.Column("total_rules", sa.Integer, nullable=False),
        sa.Column("passed", sa.Integer, nullable=False),
        sa.Column("failed", sa.Integer, nullable=False),
        sa.Column("error_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("not_applicable", sa.Integer, nullable=False, server_default="0"),
        sa.Column("compliance_score", sa.Float, nullable=False),
        # Per-severity breakdown
        sa.Column("severity_critical_passed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("severity_critical_failed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("severity_high_passed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("severity_high_failed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("severity_medium_passed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("severity_medium_failed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("severity_low_passed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("severity_low_failed", sa.Integer, nullable=False, server_default="0"),
        # JSONB for per-rule state
        sa.Column("rule_states", postgresql.JSONB, nullable=False, server_default="{}"),
        # Source scan reference
        sa.Column(
            "source_scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id"),
            nullable=True,
        ),
        # Metadata
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        # Constraints
        sa.UniqueConstraint("host_id", "snapshot_date", name="uq_host_snapshot_date"),
    )

    # Create indexes for common query patterns
    op.create_index(
        "ix_posture_snapshots_host_date_desc",
        "posture_snapshots",
        ["host_id", sa.text("snapshot_date DESC")],
    )


def downgrade() -> None:
    """Drop posture_snapshots table."""
    op.drop_index("ix_posture_snapshots_host_date_desc")
    op.drop_table("posture_snapshots")
