"""
Add risk score fields to scan_results table

Adds severity-weighted risk score columns to support Phase 2 of the
XCCDF Scoring Implementation Plan.

Fields added:
- risk_score: Weighted risk score based on severity distribution
- risk_level: Risk level categorization (low, medium, high, critical)

Risk score calculation:
    risk_score = (critical_count * 10.0) + (high_count * 5.0) +
                 (medium_count * 2.0) + (low_count * 0.5) + (info_count * 0.0)

Risk levels:
    0-20:    low
    21-50:   medium
    51-100:  high
    100+:    critical

Revision ID: 20251107_add_risk_scores
Revises: 20251107_add_xccdf_scores
Create Date: 2025-11-07 14:30:00

Reference: XCCDF_SCORING_IMPLEMENTATION_PLAN_REVISED.md Phase 2.3
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "20251107_add_risk_scores"
down_revision = "20251107_add_xccdf_scores"
branch_labels = None
depends_on = None


def upgrade():
    """Add risk score columns to scan_results table"""

    # Add risk_score column
    op.add_column(
        "scan_results",
        sa.Column(
            "risk_score", sa.Float, nullable=True, comment="Severity-weighted risk score (0.0+, typically 0-200)"
        ),
    )

    # Add risk_level column
    op.add_column(
        "scan_results",
        sa.Column(
            "risk_level", sa.String(20), nullable=True, comment="Risk level categorization: low, medium, high, critical"
        ),
    )

    print("Added risk_score and risk_level columns to scan_results table")


def downgrade():
    """Remove risk score columns from scan_results table"""

    op.drop_column("scan_results", "risk_level")
    op.drop_column("scan_results", "risk_score")

    print("Removed risk score columns from scan_results table")
