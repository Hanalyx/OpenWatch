"""Add remediation_steps table and extend remediation_results

Revision ID: 038_add_remediation_steps
Revises: 037_add_evidence_columns
Create Date: 2026-02-23

Adds remediation_steps child table for per-step tracking of Kensa remediation
results. Each step records mechanism, success, pre-state data for rollback,
and risk classification.

Also extends remediation_results with Kensa-specific columns:
  - remediated (BOOLEAN): Whether Kensa successfully applied changes
  - remediation_detail (TEXT): Kensa remediation summary
  - rolled_back (BOOLEAN): Whether auto-rolled-back on failure
  - step_count (INTEGER): Number of steps in this rule
  - risk_level (VARCHAR): Max risk across all steps (high/medium/low/na)
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers
revision = "038_add_remediation_steps"
down_revision = "037_add_evidence_columns"
branch_labels = None
depends_on = None


def upgrade():
    """Add remediation_steps table and extend remediation_results."""
    # Create remediation_steps table
    op.create_table(
        "remediation_steps",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "result_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("remediation_results.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("step_index", sa.Integer(), nullable=False),
        sa.Column("mechanism", sa.String(100), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("pre_state_data", postgresql.JSONB, nullable=True),
        sa.Column("pre_state_capturable", sa.Boolean(), nullable=True),
        sa.Column("verified", sa.Boolean(), nullable=True),
        sa.Column("verify_detail", sa.Text(), nullable=True),
        sa.Column("risk_level", sa.String(20), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )

    op.create_index(
        "ix_remediation_steps_result_id",
        "remediation_steps",
        ["result_id"],
    )

    # Extend remediation_results with Kensa fields
    op.add_column(
        "remediation_results",
        sa.Column("remediated", sa.Boolean(), nullable=True),
    )
    op.add_column(
        "remediation_results",
        sa.Column("remediation_detail", sa.Text(), nullable=True),
    )
    op.add_column(
        "remediation_results",
        sa.Column("rolled_back", sa.Boolean(), nullable=True),
    )
    op.add_column(
        "remediation_results",
        sa.Column("step_count", sa.Integer(), nullable=True),
    )
    op.add_column(
        "remediation_results",
        sa.Column("risk_level", sa.String(20), nullable=True),
    )


def downgrade():
    """Remove remediation_steps table and extra columns from remediation_results."""
    op.drop_column("remediation_results", "risk_level")
    op.drop_column("remediation_results", "step_count")
    op.drop_column("remediation_results", "rolled_back")
    op.drop_column("remediation_results", "remediation_detail")
    op.drop_column("remediation_results", "remediated")

    op.drop_index("ix_remediation_steps_result_id")
    op.drop_table("remediation_steps")
