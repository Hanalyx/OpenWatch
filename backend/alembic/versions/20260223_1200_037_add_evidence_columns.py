"""Add evidence, framework_refs, skip_reason columns to scan_findings

Revision ID: 037_add_evidence_columns
Revises: 036_rename_aegis_to_kensa
Create Date: 2026-02-23

Adds three nullable columns to scan_findings for full Kensa evidence storage:
  - evidence (JSONB): List of evidence dicts from Kensa checks
  - framework_refs (JSONB): Multi-framework reference dict
  - skip_reason (TEXT): Why a rule was skipped

GIN indexes on JSONB columns for containment and key-existence queries.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers
revision = "037_add_evidence_columns"
down_revision = "036_rename_aegis_to_kensa"
branch_labels = None
depends_on = None


def upgrade():
    """Add evidence columns and GIN indexes."""
    op.add_column(
        "scan_findings",
        sa.Column("evidence", postgresql.JSONB, nullable=True),
    )
    op.add_column(
        "scan_findings",
        sa.Column("framework_refs", postgresql.JSONB, nullable=True),
    )
    op.add_column(
        "scan_findings",
        sa.Column("skip_reason", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_scan_findings_evidence",
        "scan_findings",
        ["evidence"],
        postgresql_using="gin",
    )
    op.create_index(
        "ix_scan_findings_framework_refs",
        "scan_findings",
        ["framework_refs"],
        postgresql_using="gin",
    )


def downgrade():
    """Remove evidence columns and GIN indexes."""
    op.drop_index("ix_scan_findings_framework_refs")
    op.drop_index("ix_scan_findings_evidence")
    op.drop_column("scan_findings", "skip_reason")
    op.drop_column("scan_findings", "framework_refs")
    op.drop_column("scan_findings", "evidence")
