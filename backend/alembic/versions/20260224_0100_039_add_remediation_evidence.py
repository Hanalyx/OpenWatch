"""Add evidence and framework_refs columns to remediation_results

Revision ID: 039_add_remediation_evidence
Revises: 038_add_remediation_steps
Create Date: 2026-02-24

Adds two nullable JSONB columns to remediation_results for full Kensa
evidence storage from remediate_rule() results:
  - evidence (JSONB): List of evidence dicts (command, stdout, exit_code, etc.)
  - framework_refs (JSONB): Multi-framework reference dict (e.g. nist_800_53)

GIN indexes on both JSONB columns for containment and key-existence queries.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers
revision = "039_add_remediation_evidence"
down_revision = "038_add_remediation_steps"
branch_labels = None
depends_on = None


def upgrade():
    """Add evidence and framework_refs JSONB columns with GIN indexes."""
    op.add_column(
        "remediation_results",
        sa.Column("evidence", postgresql.JSONB, nullable=True),
    )
    op.add_column(
        "remediation_results",
        sa.Column("framework_refs", postgresql.JSONB, nullable=True),
    )
    op.create_index(
        "ix_remediation_results_evidence",
        "remediation_results",
        ["evidence"],
        postgresql_using="gin",
    )
    op.create_index(
        "ix_remediation_results_framework_refs",
        "remediation_results",
        ["framework_refs"],
        postgresql_using="gin",
    )


def downgrade():
    """Remove evidence and framework_refs columns and GIN indexes."""
    op.drop_index("ix_remediation_results_framework_refs")
    op.drop_index("ix_remediation_results_evidence")
    op.drop_column("remediation_results", "framework_refs")
    op.drop_column("remediation_results", "evidence")
