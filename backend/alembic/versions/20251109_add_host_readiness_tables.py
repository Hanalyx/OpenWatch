"""
Add host readiness validation tables

Creates tables for storing host readiness check results with:
- Complete audit trail (FedRAMP, CMMC, ISO 27001 compliance)
- Smart caching (skip redundant checks within TTL)
- Historical trend analysis
- Remediation tracking

Tables added:
- host_readiness_validations: Overall validation runs per host
- host_readiness_checks: Individual check results per validation

Revision ID: 20251109_add_readiness
Revises: 20251107_add_risk_scores
Create Date: 2025-11-09 00:00:00

Reference: Host Readiness Validation Feature - Option B Implementation
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision = "20251109_add_readiness"
down_revision = "20251107_add_risk_scores"
branch_labels = None
depends_on = None


def upgrade():
    """Create host readiness validation tables"""

    # Create host_readiness_validations table
    op.create_table(
        "host_readiness_validations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("host_id", UUID(as_uuid=True), sa.ForeignKey("hosts.id"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("overall_passed", sa.Boolean, nullable=False),
        sa.Column("total_checks", sa.Integer, nullable=False),
        sa.Column("passed_checks", sa.Integer, nullable=False),
        sa.Column("failed_checks", sa.Integer, nullable=False),
        sa.Column("warnings_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("summary", JSON, nullable=True),
        sa.Column("validation_duration_ms", sa.Float, nullable=True),
        sa.Column("started_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", UUID(as_uuid=True), nullable=True),
    )

    # Create indexes for host_readiness_validations
    op.create_index("idx_readiness_validations_id", "host_readiness_validations", ["id"])
    op.create_index("idx_readiness_validations_host_id", "host_readiness_validations", ["host_id"])
    op.create_index("idx_readiness_validations_status", "host_readiness_validations", ["status"])
    op.create_index("idx_readiness_validations_overall_passed", "host_readiness_validations", ["overall_passed"])
    op.create_index("idx_readiness_validations_completed_at", "host_readiness_validations", ["completed_at"])
    # Composite indexes for common queries
    op.create_index("idx_host_completed", "host_readiness_validations", ["host_id", "completed_at"])
    op.create_index(
        "idx_host_status_completed",
        "host_readiness_validations",
        ["host_id", "status", "completed_at"],
    )

    # Create host_readiness_checks table
    op.create_table(
        "host_readiness_checks",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("host_id", UUID(as_uuid=True), sa.ForeignKey("hosts.id"), nullable=False),
        sa.Column(
            "validation_run_id",
            UUID(as_uuid=True),
            sa.ForeignKey("host_readiness_validations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("check_type", sa.String(50), nullable=False),
        sa.Column("check_name", sa.String(255), nullable=False),
        sa.Column("passed", sa.Boolean, nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("message", sa.Text, nullable=True),
        sa.Column("details", JSON, nullable=True),
        sa.Column("check_duration_ms", sa.Float, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", UUID(as_uuid=True), nullable=True),
    )

    # Create indexes for host_readiness_checks
    op.create_index("idx_readiness_checks_id", "host_readiness_checks", ["id"])
    op.create_index("idx_readiness_checks_host_id", "host_readiness_checks", ["host_id"])
    op.create_index("idx_readiness_checks_validation_run_id", "host_readiness_checks", ["validation_run_id"])
    op.create_index("idx_readiness_checks_check_type", "host_readiness_checks", ["check_type"])
    op.create_index("idx_readiness_checks_passed", "host_readiness_checks", ["passed"])
    op.create_index("idx_readiness_checks_created_at", "host_readiness_checks", ["created_at"])
    # Composite indexes for common queries
    op.create_index(
        "idx_host_check_type_created",
        "host_readiness_checks",
        ["host_id", "check_type", "created_at"],
    )
    op.create_index("idx_host_failed_checks", "host_readiness_checks", ["host_id", "passed", "created_at"])

    print("Created host_readiness_validations and host_readiness_checks tables")


def downgrade():
    """Drop host readiness validation tables"""

    # Drop indexes first
    op.drop_index("idx_host_failed_checks", table_name="host_readiness_checks")
    op.drop_index("idx_host_check_type_created", table_name="host_readiness_checks")
    op.drop_index("idx_readiness_checks_created_at", table_name="host_readiness_checks")
    op.drop_index("idx_readiness_checks_passed", table_name="host_readiness_checks")
    op.drop_index("idx_readiness_checks_check_type", table_name="host_readiness_checks")
    op.drop_index("idx_readiness_checks_validation_run_id", table_name="host_readiness_checks")
    op.drop_index("idx_readiness_checks_host_id", table_name="host_readiness_checks")
    op.drop_index("idx_readiness_checks_id", table_name="host_readiness_checks")

    op.drop_index("idx_host_status_completed", table_name="host_readiness_validations")
    op.drop_index("idx_host_completed", table_name="host_readiness_validations")
    op.drop_index("idx_readiness_validations_completed_at", table_name="host_readiness_validations")
    op.drop_index("idx_readiness_validations_overall_passed", table_name="host_readiness_validations")
    op.drop_index("idx_readiness_validations_status", table_name="host_readiness_validations")
    op.drop_index("idx_readiness_validations_host_id", table_name="host_readiness_validations")
    op.drop_index("idx_readiness_validations_id", table_name="host_readiness_validations")

    # Drop tables
    op.drop_table("host_readiness_checks")
    op.drop_table("host_readiness_validations")

    print("Removed host_readiness_validations and host_readiness_checks tables")
