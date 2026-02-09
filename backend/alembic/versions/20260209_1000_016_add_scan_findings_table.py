"""Add scan_findings table for per-rule scan results

Revision ID: 20260209_1000_016
Revises: 20260128_merge_heads
Create Date: 2026-02-09

This migration creates the scan_findings table to store individual rule
results from compliance scans. This enables:
- Tracking rule failures over time
- Querying failed rules across scans
- Filtering findings by severity
- Compliance trend analysis
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic
revision = "20260209_1000_016"
down_revision = "20260128_merge_heads"
branch_labels = None
depends_on = None


def upgrade():
    """Create scan_findings table with indexes."""
    op.create_table(
        "scan_findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_id", sa.String(255), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("framework_section", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
    )

    # Create indexes for common query patterns
    op.create_index("idx_scan_findings_scan_id", "scan_findings", ["scan_id"])
    op.create_index("idx_scan_findings_rule_id", "scan_findings", ["rule_id"])
    op.create_index("idx_scan_findings_severity_status", "scan_findings", ["severity", "status"])
    op.create_index("idx_scan_findings_status", "scan_findings", ["status"])


def downgrade():
    """Drop scan_findings table and indexes."""
    op.drop_index("idx_scan_findings_status", "scan_findings")
    op.drop_index("idx_scan_findings_severity_status", "scan_findings")
    op.drop_index("idx_scan_findings_rule_id", "scan_findings")
    op.drop_index("idx_scan_findings_scan_id", "scan_findings")
    op.drop_table("scan_findings")
