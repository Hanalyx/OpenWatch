"""
Add severity_critical column for NIST risk scoring

Adds severity_critical column to scan_results table to support
NIST SP 800-30 Risk Management Guide requirements for separate
tracking of critical severity findings (CVSS >= 9.0).

This enables severity-weighted risk scoring by distinguishing
critical findings from high severity findings.

Revision ID: 20251115_add_severity_critical
Revises: 20251109_add_readiness
Create Date: 2025-11-15 14:30:00

Reference: NIST SP 800-30 Rev. 1 Risk Management Guide for IT Systems
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "20251115_add_severity_critical"
down_revision = "20251109_add_readiness"
branch_labels = None
depends_on = None


def upgrade():
    """Add severity_critical column to scan_results table"""

    # Add severity_critical column
    # NIST SP 800-30 requires separate tracking of critical severity findings (CVSS >= 9.0)
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_critical",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of critical severity findings (CVSS >= 9.0) - NIST SP 800-30 requirement",
        ),
    )

    print("Added severity_critical column to scan_results table")


def downgrade():
    """Remove severity_critical column from scan_results table"""

    op.drop_column("scan_results", "severity_critical")

    print("Removed severity_critical column from scan_results table")
