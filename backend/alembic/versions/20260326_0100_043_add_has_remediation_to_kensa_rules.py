"""Add has_remediation column to kensa_rules table

Revision ID: 043_add_has_remediation
Revises: 042_make_scans_content_id_nullable
Create Date: 2026-03-26

The kensa_rules table is missing the has_remediation column that
sync_service.py writes to during rule sync. This causes the sync to
fail with: column "has_remediation" of relation "kensa_rules" does not exist
"""

from alembic import op
import sqlalchemy as sa

revision = "043_add_has_remediation"
down_revision = "042_make_scans_content_id_nullable"
branch_labels = None
depends_on = None


def upgrade():
    # Add has_remediation column if it doesn't exist (idempotent)
    conn = op.get_bind()
    result = conn.execute(
        sa.text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'kensa_rules' AND column_name = 'has_remediation'"
        )
    )
    if result.fetchone() is None:
        op.add_column(
            "kensa_rules",
            sa.Column("has_remediation", sa.Boolean(), nullable=True, server_default="false"),
        )


def downgrade():
    op.drop_column("kensa_rules", "has_remediation")
