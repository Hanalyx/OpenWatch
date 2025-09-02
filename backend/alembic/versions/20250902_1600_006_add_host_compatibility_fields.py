"""Add compatibility fields to Host and ScapContent models

Revision ID: 006
Revises: 005
Create Date: 2025-09-02 16:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add compatibility fields to Host and ScapContent models"""
    
    # Add compatibility fields to hosts table
    op.add_column('hosts', sa.Column('os_family', sa.String(50), nullable=True))
    op.add_column('hosts', sa.Column('os_version', sa.String(100), nullable=True))
    op.add_column('hosts', sa.Column('architecture', sa.String(50), nullable=True))
    op.add_column('hosts', sa.Column('last_os_detection', sa.DateTime(), nullable=True))
    
    # Add compatibility fields to scap_content table
    op.add_column('scap_content', sa.Column('os_family', sa.String(50), nullable=True))
    op.add_column('scap_content', sa.Column('compliance_framework', sa.String(100), nullable=True))


def downgrade() -> None:
    """Remove compatibility fields from Host and ScapContent models"""
    
    # Remove fields from scap_content table
    op.drop_column('scap_content', 'compliance_framework')
    op.drop_column('scap_content', 'os_family')
    
    # Remove fields from hosts table
    op.drop_column('hosts', 'last_os_detection')
    op.drop_column('hosts', 'architecture')
    op.drop_column('hosts', 'os_version')
    op.drop_column('hosts', 'os_family')