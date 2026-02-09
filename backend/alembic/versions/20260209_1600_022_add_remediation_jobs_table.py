"""Add remediation_jobs table for Phase 4

Revision ID: 022_remediation_jobs
Revises: 021_host_monitoring_config
Create Date: 2026-02-09

Part of Phase 4: Remediation + Subscription (Aegis Integration Plan)
Creates tables for tracking remediation jobs, individual rule remediations,
and rollback snapshots for OpenWatch+ licensed remediation.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers
revision = "022_remediation_jobs"
down_revision = "021_host_monitoring_config"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create remediation tables."""
    # Create remediation_status enum
    op.execute(
        """
        DO $$ BEGIN
            CREATE TYPE remediation_status AS ENUM (
                'pending',
                'running',
                'completed',
                'failed',
                'rolled_back',
                'cancelled'
            );
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
        """
    )

    # Main remediation jobs table
    op.create_table(
        "remediation_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, index=True),
        sa.Column(
            "host_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("hosts.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
        # Job configuration
        sa.Column("rule_ids", postgresql.JSONB, nullable=False, comment="List of rule IDs to remediate"),
        sa.Column("dry_run", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("framework", sa.String(50), nullable=True, comment="Optional framework filter"),
        # Status tracking
        sa.Column(
            "status",
            postgresql.ENUM(
                "pending",
                "running",
                "completed",
                "failed",
                "rolled_back",
                "cancelled",
                name="remediation_status",
                create_type=False,
            ),
            nullable=False,
            server_default="pending",
            index=True,
        ),
        sa.Column("progress", sa.Integer, nullable=False, server_default="0", comment="Percentage complete"),
        sa.Column("total_rules", sa.Integer, nullable=False, server_default="0"),
        sa.Column("completed_rules", sa.Integer, nullable=False, server_default="0"),
        sa.Column("failed_rules", sa.Integer, nullable=False, server_default="0"),
        sa.Column("skipped_rules", sa.Integer, nullable=False, server_default="0"),
        # Error handling
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("error_details", postgresql.JSONB, nullable=True),
        # Rollback support
        sa.Column("rollback_available", sa.Boolean, nullable=False, server_default="false"),
        sa.Column(
            "rollback_job_id", postgresql.UUID(as_uuid=True), nullable=True, comment="Parent job if this is a rollback"
        ),
        # Audit
        sa.Column("requested_by", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
    )

    # Individual rule remediation results
    op.create_table(
        "remediation_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, index=True),
        sa.Column(
            "job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("remediation_jobs.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("rule_id", sa.String(255), nullable=False, index=True),
        # Execution details
        sa.Column(
            "status",
            postgresql.ENUM(
                "pending",
                "running",
                "completed",
                "failed",
                "rolled_back",
                "cancelled",
                name="remediation_status",
                create_type=False,
            ),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("exit_code", sa.Integer, nullable=True),
        sa.Column("stdout", sa.Text, nullable=True),
        sa.Column("stderr", sa.Text, nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        # Error details
        sa.Column("error_message", sa.Text, nullable=True),
        # Rollback data
        sa.Column("pre_state", postgresql.JSONB, nullable=True, comment="State before remediation for rollback"),
        sa.Column("rollback_available", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("rollback_executed", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("rollback_result", postgresql.JSONB, nullable=True),
        # Timestamps
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
    )

    # Rollback snapshots for state preservation
    op.create_table(
        "rollback_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, index=True),
        sa.Column(
            "job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("remediation_jobs.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("rule_id", sa.String(255), nullable=False),
        # Snapshot data
        sa.Column("snapshot_type", sa.String(50), nullable=False, comment="file, config, service, package, etc."),
        sa.Column("resource_path", sa.String(500), nullable=True, comment="File path or resource identifier"),
        sa.Column("original_content", sa.Text, nullable=True, comment="Original file content"),
        sa.Column("original_state", postgresql.JSONB, nullable=True, comment="Original state as JSON"),
        sa.Column("original_permissions", sa.String(20), nullable=True),
        sa.Column("original_owner", sa.String(100), nullable=True),
        # Restoration tracking
        sa.Column("restored", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("restored_at", sa.DateTime, nullable=True),
        sa.Column("restore_error", sa.Text, nullable=True),
        # Timestamps
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )

    # Create indexes for common queries
    op.create_index("ix_remediation_jobs_status_created", "remediation_jobs", ["status", "created_at"])
    op.create_index("ix_remediation_jobs_host_status", "remediation_jobs", ["host_id", "status"])
    op.create_index("ix_remediation_results_job_status", "remediation_results", ["job_id", "status"])
    op.create_index("ix_rollback_snapshots_job_rule", "rollback_snapshots", ["job_id", "rule_id"])


def downgrade() -> None:
    """Drop remediation tables."""
    op.drop_index("ix_rollback_snapshots_job_rule")
    op.drop_index("ix_remediation_results_job_status")
    op.drop_index("ix_remediation_jobs_host_status")
    op.drop_index("ix_remediation_jobs_status_created")
    op.drop_table("rollback_snapshots")
    op.drop_table("remediation_results")
    op.drop_table("remediation_jobs")
    op.execute("DROP TYPE IF EXISTS remediation_status")
