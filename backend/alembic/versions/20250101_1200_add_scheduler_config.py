"""Add scheduler configuration table

Revision ID: 20250101_1200
Revises:
Create Date: 2025-01-01 12:00:00.000000

"""

import sqlalchemy as sa
from sqlalchemy import text

from alembic import op

# revision identifiers, used by Alembic.
revision = "20250101_1200"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add scheduler_config table for persisting scheduler state"""
    # Create scheduler_config table
    op.create_table(
        "scheduler_config",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("service_name", sa.String(50), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, default=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False, default=15),
        sa.Column("last_started", sa.DateTime(), nullable=True),
        sa.Column("last_stopped", sa.DateTime(), nullable=True),
        sa.Column("auto_start", sa.Boolean(), nullable=False, default=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("service_name"),
    )

    # Insert default configuration for host monitoring
    op.execute(
        text(
            """
        INSERT INTO scheduler_config (
            service_name, enabled, interval_minutes, auto_start
        ) VALUES (
            'host_monitoring', TRUE, 15, TRUE
        )
    """
        )
    )


def downgrade() -> None:
    """Remove scheduler_config table"""
    op.drop_table("scheduler_config")
