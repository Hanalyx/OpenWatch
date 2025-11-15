"""
Add per-severity pass/fail columns for accurate compliance visualization

Revision ID: 20251115_add_per_severity_pass_fail
Revises: 20251115_add_severity_critical
Create Date: 2025-11-15 15:00:00

NIST SP 800-137 Continuous Monitoring requires granular severity-level tracking
to enable accurate risk visualization and drift detection.

This migration adds 8 columns to track passed and failed rules by severity:
- severity_critical_passed, severity_critical_failed (CVSS >= 9.0)
- severity_high_passed, severity_high_failed (CVSS 7.0-8.9)
- severity_medium_passed, severity_medium_failed (CVSS 4.0-6.9)
- severity_low_passed, severity_low_failed (CVSS 0.1-3.9)

WHY NEEDED:
Frontend ComplianceRing component was displaying fake data because backend
only provided total failure counts by severity. To calculate accurate per-severity
pass rates, we need both passed and failed counts.

BEFORE: criticalPassRate = 100 - (criticalIssues / totalIssues) * 100  # WRONG!
AFTER:  criticalPassRate = (critical_passed / (critical_passed + critical_failed)) * 100  # CORRECT!

See: COMPLIANCE_ENHANCEMENT_MASTER_PLAN.md for complete architecture details
"""

import sqlalchemy as sa
from alembic import op

revision = "20251115_per_sev_pass_fail"
down_revision = "20251115_add_severity_critical"
branch_labels = None
depends_on = None


def upgrade():
    """
    Add per-severity pass/fail columns to scan_results table.

    Each severity level gets two columns: passed and failed counts.
    This enables accurate calculation of per-severity pass rates for
    compliance visualization (ComplianceRing component).
    """
    # Critical severity (CVSS >= 9.0)
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_critical_passed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of passed critical severity rules (CVSS >= 9.0)",
        ),
    )
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_critical_failed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of failed critical severity rules (CVSS >= 9.0)",
        ),
    )

    # High severity (CVSS 7.0-8.9)
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_high_passed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of passed high severity rules (CVSS 7.0-8.9)",
        ),
    )
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_high_failed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of failed high severity rules (CVSS 7.0-8.9)",
        ),
    )

    # Medium severity (CVSS 4.0-6.9)
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_medium_passed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of passed medium severity rules (CVSS 4.0-6.9)",
        ),
    )
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_medium_failed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of failed medium severity rules (CVSS 4.0-6.9)",
        ),
    )

    # Low severity (CVSS 0.1-3.9)
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_low_passed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of passed low severity rules (CVSS 0.1-3.9)",
        ),
    )
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_low_failed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of failed low severity rules (CVSS 0.1-3.9)",
        ),
    )

    print("Added 8 per-severity pass/fail columns to scan_results table")
    print("  - severity_critical_passed, severity_critical_failed")
    print("  - severity_high_passed, severity_high_failed")
    print("  - severity_medium_passed, severity_medium_failed")
    print("  - severity_low_passed, severity_low_failed")


def downgrade():
    """
    Remove per-severity pass/fail columns from scan_results table.

    WARNING: This will result in loss of granular severity data.
    ComplianceRing will fall back to displaying only overall score.
    """
    op.drop_column("scan_results", "severity_low_failed")
    op.drop_column("scan_results", "severity_low_passed")
    op.drop_column("scan_results", "severity_medium_failed")
    op.drop_column("scan_results", "severity_medium_passed")
    op.drop_column("scan_results", "severity_high_failed")
    op.drop_column("scan_results", "severity_high_passed")
    op.drop_column("scan_results", "severity_critical_failed")
    op.drop_column("scan_results", "severity_critical_passed")

    print("Removed 8 per-severity pass/fail columns from scan_results table")
