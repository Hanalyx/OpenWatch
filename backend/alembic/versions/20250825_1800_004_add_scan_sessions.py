"""add scan sessions table for bulk scan orchestration

Revision ID: 004
Revises: 20250125_1200_add_security_config
Create Date: 2025-08-25 18:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "004"
down_revision = "20250125_1200_add_security_config"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create scan_sessions table for bulk scan orchestration
    op.create_table(
        "scan_sessions",
        sa.Column("id", sa.String(36), nullable=False, primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("total_hosts", sa.Integer, nullable=False, default=0),
        sa.Column("completed_hosts", sa.Integer, nullable=False, default=0),
        sa.Column("failed_hosts", sa.Integer, nullable=False, default=0),
        sa.Column("running_hosts", sa.Integer, nullable=False, default=0),
        sa.Column("status", sa.String(20), nullable=False, default="pending"),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("estimated_completion", sa.DateTime(), nullable=True),
        sa.Column("scan_ids", sa.Text, nullable=True),  # JSON array of scan IDs
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Index("idx_scan_sessions_status", "status"),
        sa.Index("idx_scan_sessions_created_by", "created_by"),
        sa.Index("idx_scan_sessions_created_at", "created_at"),
    )

    # Foreign key to users table - skipped because created_by is String(36)
    # but users.id is Integer (type mismatch). The original try/except
    # caught the Python error but left PostgreSQL's transaction in a
    # failed state, breaking subsequent migrations.

    # Add indexes for scan performance
    op.create_index("idx_scans_host_id_status", "scans", ["host_id", "status"])
    op.create_index("idx_scans_status_started_at", "scans", ["status", "started_at"])


def downgrade() -> None:
    # Drop indexes
    op.drop_index("idx_scans_status_started_at", table_name="scans")
    op.drop_index("idx_scans_host_id_status", table_name="scans")

    # Drop scan_sessions table
    op.drop_table("scan_sessions")
