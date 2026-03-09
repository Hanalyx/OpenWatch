"""Make scans.content_id nullable for Kensa scans

Revision ID: 042_make_scans_content_id_nullable
Revises: 041_add_manual_remediation_status
Create Date: 2026-03-08

Kensa compliance scans do not use SCAP content (content_id references
scap_content which is a legacy table). The NOT NULL constraint on
scans.content_id causes every scheduled Kensa scan INSERT to fail with:

  null value in column "content_id" of relation "scans" violates not-null constraint

Making the column nullable allows Kensa scans to be created without a
content_id while preserving existing SCAP scan data.
"""

from sqlalchemy import inspect as sa_inspect

from alembic import op

# Revision identifiers
revision = "042_make_scans_content_id_nullable"
down_revision = "041_add_manual_remediation_status"
branch_labels = None
depends_on = None


def upgrade():
    """Make content_id nullable on scans table (no-op if column was already dropped)."""
    conn = op.get_bind()
    inspector = sa_inspect(conn)
    columns = [c["name"] for c in inspector.get_columns("scans")]
    if "content_id" in columns:
        op.alter_column("scans", "content_id", nullable=True)


def downgrade():
    """Restore NOT NULL constraint on content_id (no-op if column doesn't exist)."""
    conn = op.get_bind()
    inspector = sa_inspect(conn)
    columns = [c["name"] for c in inspector.get_columns("scans")]
    if "content_id" in columns:
        op.alter_column("scans", "content_id", nullable=False)
