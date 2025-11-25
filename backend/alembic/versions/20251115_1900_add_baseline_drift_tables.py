"""
Add baseline and drift detection tables for compliance monitoring

Revision ID: 20251115_baseline_drift
Revises: 20251115_per_sev_pass_fail
Create Date: 2025-11-15 19:00:00

NIST SP 800-137 Continuous Monitoring requires establishing baselines
and detecting significant changes in compliance posture for risk assessment.

This migration adds two tables:
1. scan_baselines: Store compliance baseline snapshots
2. scan_drift_events: Record significant deviations from baseline

WHY NEEDED:
Enable compliance trend tracking to identify hosts improving or degrading
over time, with automated alerts for significant drift from baseline.

Uses existing AlertSettings table for notifications (no duplicate alert system).
Integrates with existing webhook infrastructure for drift alerts.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20251115_baseline_drift"
down_revision = "20251115_per_sev_pass_fail"
branch_labels = None
depends_on = None


def upgrade():
    """
    Add scan_baselines and scan_drift_events tables.

    scan_baselines: Stores compliance baseline snapshots for drift comparison
    scan_drift_events: Records significant compliance changes for alerting
    """

    # Create scan_baselines table
    op.create_table(
        "scan_baselines",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False
        ),
        # Baseline metadata
        sa.Column(
            "baseline_type", sa.String(20), nullable=False, comment="Baseline type: initial, manual, or rolling_avg"
        ),
        sa.Column(
            "established_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("NOW()"),
            comment="When baseline was established",
        ),
        sa.Column(
            "established_by",
            sa.Integer,
            sa.ForeignKey("users.id"),
            nullable=True,
            comment="User who established baseline (NULL for auto)",
        ),
        # Baseline compliance metrics
        sa.Column("baseline_score", sa.Float, nullable=False, comment="Baseline compliance score (0-100)"),
        sa.Column("baseline_passed_rules", sa.Integer, nullable=False, comment="Number of passed rules at baseline"),
        sa.Column("baseline_failed_rules", sa.Integer, nullable=False, comment="Number of failed rules at baseline"),
        sa.Column("baseline_total_rules", sa.Integer, nullable=False, comment="Total number of rules at baseline"),
        # Per-severity baseline pass/fail counts
        sa.Column(
            "baseline_critical_passed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Passed critical rules (CVSS >= 9.0)",
        ),
        sa.Column(
            "baseline_critical_failed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Failed critical rules (CVSS >= 9.0)",
        ),
        sa.Column(
            "baseline_high_passed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Passed high rules (CVSS 7.0-8.9)",
        ),
        sa.Column(
            "baseline_high_failed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Failed high rules (CVSS 7.0-8.9)",
        ),
        sa.Column(
            "baseline_medium_passed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Passed medium rules (CVSS 4.0-6.9)",
        ),
        sa.Column(
            "baseline_medium_failed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Failed medium rules (CVSS 4.0-6.9)",
        ),
        sa.Column(
            "baseline_low_passed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Passed low rules (CVSS 0.1-3.9)",
        ),
        sa.Column(
            "baseline_low_failed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Failed low rules (CVSS 0.1-3.9)",
        ),
        # Drift thresholds (percentage points)
        sa.Column(
            "drift_threshold_major",
            sa.Float,
            nullable=False,
            server_default="10.0",
            comment="Alert if score drops >10pp",
        ),
        sa.Column(
            "drift_threshold_minor", sa.Float, nullable=False, server_default="5.0", comment="Warn if score drops >5pp"
        ),
        # Active/superseded tracking
        sa.Column(
            "is_active", sa.Boolean, nullable=False, server_default="true", comment="Whether this baseline is active"
        ),
        sa.Column("superseded_at", sa.DateTime, nullable=True, comment="When this baseline was superseded"),
        sa.Column(
            "superseded_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_baselines.id"),
            nullable=True,
            comment="Baseline that superseded this one",
        ),
        # Audit
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.text("NOW()")),
    )

    # Create indexes for scan_baselines
    op.create_index("idx_scan_baselines_host_active", "scan_baselines", ["host_id", "is_active"])
    op.create_index("idx_scan_baselines_type", "scan_baselines", ["baseline_type"])

    # Create exclusion constraint to ensure one active baseline per host
    # Note: ExcludeConstraint requires btree_gist extension
    op.execute("CREATE EXTENSION IF NOT EXISTS btree_gist")
    op.execute(
        """
        ALTER TABLE scan_baselines
        ADD CONSTRAINT unique_active_baseline
        EXCLUDE USING gist (host_id WITH =, is_active WITH =)
        WHERE (is_active = true)
    """
    )

    # Create scan_drift_events table
    op.create_table(
        "scan_drift_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("baseline_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_baselines.id"), nullable=False),
        # Drift metrics
        sa.Column(
            "drift_type", sa.String(20), nullable=False, comment="Drift type: major, minor, improvement, or stable"
        ),
        sa.Column("drift_magnitude", sa.Float, nullable=False, comment="Absolute percentage point change"),
        # Scores
        sa.Column("baseline_score", sa.Float, nullable=False, comment="Baseline compliance score"),
        sa.Column("current_score", sa.Float, nullable=False, comment="Current scan score"),
        sa.Column("score_delta", sa.Float, nullable=False, comment="Score change (current - baseline)"),
        # Per-severity pass/fail deltas
        sa.Column("critical_passed_delta", sa.Integer, nullable=True, comment="Change in passed critical rules"),
        sa.Column("critical_failed_delta", sa.Integer, nullable=True, comment="Change in failed critical rules"),
        sa.Column("high_passed_delta", sa.Integer, nullable=True, comment="Change in passed high rules"),
        sa.Column("high_failed_delta", sa.Integer, nullable=True, comment="Change in failed high rules"),
        sa.Column("medium_passed_delta", sa.Integer, nullable=True, comment="Change in passed medium rules"),
        sa.Column("medium_failed_delta", sa.Integer, nullable=True, comment="Change in failed medium rules"),
        sa.Column("low_passed_delta", sa.Integer, nullable=True, comment="Change in passed low rules"),
        sa.Column("low_failed_delta", sa.Integer, nullable=True, comment="Change in failed low rules"),
        # Audit
        sa.Column(
            "detected_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("NOW()"),
            comment="When drift was detected",
        ),
        # Constraint
        sa.CheckConstraint("drift_type IN ('major', 'minor', 'improvement', 'stable')", name="valid_drift_type"),
    )

    # Create indexes for scan_drift_events
    op.create_index("idx_scan_drift_events_host", "scan_drift_events", ["host_id", "detected_at"])
    op.create_index("idx_scan_drift_events_type", "scan_drift_events", ["drift_type"])
    op.create_index("idx_scan_drift_events_scan", "scan_drift_events", ["scan_id"])

    print("[OK] Created scan_baselines table with 8 per-severity pass/fail columns")
    print("[OK] Created scan_drift_events table with per-severity delta tracking")
    print("[OK] Added indexes for efficient baseline and drift queries")
    print("[OK] Configured unique active baseline constraint per host")


def downgrade():
    """
    Remove scan_baselines and scan_drift_events tables.

    WARNING: This will result in loss of all baseline and drift data.
    Compliance trend tracking will be disabled.
    """
    op.drop_index("idx_scan_drift_events_scan", table_name="scan_drift_events")
    op.drop_index("idx_scan_drift_events_type", table_name="scan_drift_events")
    op.drop_index("idx_scan_drift_events_host", table_name="scan_drift_events")
    op.drop_table("scan_drift_events")

    op.execute("ALTER TABLE scan_baselines DROP CONSTRAINT IF EXISTS unique_active_baseline")
    op.drop_index("idx_scan_baselines_type", table_name="scan_baselines")
    op.drop_index("idx_scan_baselines_host_active", table_name="scan_baselines")
    op.drop_table("scan_baselines")

    print("[OK] Removed scan_drift_events table")
    print("[OK] Removed scan_baselines table")
    print("WARNING: All baseline and drift tracking data has been deleted")
