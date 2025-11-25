"""Add os_version field to ScapContent model

Revision ID: 007
Revises: 006
Create Date: 2025-09-02 17:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

# revision identifiers
revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add os_version field to ScapContent model"""

    # Add os_version field to scap_content table
    op.add_column("scap_content", sa.Column("os_version", sa.String(100), nullable=True))


def downgrade() -> None:
    """Remove os_version field from ScapContent model"""

    # Remove os_version field from scap_content table
    op.drop_column("scap_content", "os_version")
