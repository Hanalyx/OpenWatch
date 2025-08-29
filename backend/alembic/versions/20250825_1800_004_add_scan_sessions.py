"""add scan sessions table for bulk scan orchestration

Revision ID: 20250825_1800_004
Revises: 20250818_1400_003
Create Date: 2025-08-25 18:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20250825_1800_004'
down_revision = '20250818_1400_003_compliance_framework_mapping'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create scan_sessions table for bulk scan orchestration
    op.create_table('scan_sessions',
        sa.Column('id', sa.String(36), nullable=False, primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('total_hosts', sa.Integer, nullable=False, default=0),
        sa.Column('completed_hosts', sa.Integer, nullable=False, default=0),
        sa.Column('failed_hosts', sa.Integer, nullable=False, default=0),
        sa.Column('running_hosts', sa.Integer, nullable=False, default=0),
        sa.Column('status', sa.String(20), nullable=False, default='pending'),
        sa.Column('created_by', sa.String(36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('estimated_completion', sa.DateTime(), nullable=True),
        sa.Column('scan_ids', sa.Text, nullable=True),  # JSON array of scan IDs
        sa.Column('error_message', sa.Text, nullable=True),
        sa.Index('idx_scan_sessions_status', 'status'),
        sa.Index('idx_scan_sessions_created_by', 'created_by'),
        sa.Index('idx_scan_sessions_created_at', 'created_at'),
    )

    # Add foreign key reference from scans to users (if not already exists)
    # Note: This assumes users table exists with id column
    try:
        op.create_foreign_key(
            'fk_scan_sessions_created_by', 
            'scan_sessions', 
            'users', 
            ['created_by'], 
            ['id'],
            ondelete='CASCADE'
        )
    except Exception:
        # Foreign key might already exist or users table might not exist
        pass

    # Add indexes for scan performance
    try:
        op.create_index('idx_scans_host_id_status', 'scans', ['host_id', 'status'])
        op.create_index('idx_scans_status_started_at', 'scans', ['status', 'started_at'])
    except Exception:
        # Indexes might already exist
        pass


def downgrade() -> None:
    # Drop indexes
    try:
        op.drop_index('idx_scans_status_started_at', table_name='scans')
        op.drop_index('idx_scans_host_id_status', table_name='scans')
    except Exception:
        pass

    # Drop foreign key
    try:
        op.drop_constraint('fk_scan_sessions_created_by', 'scan_sessions', type_='foreignkey')
    except Exception:
        pass

    # Drop scan_sessions table
    op.drop_table('scan_sessions')