"""Rename aegis_remediation_id to kensa_remediation_id on scans table

Revision ID: 040_rename_aegis_remediation_id
Revises: 039_add_remediation_evidence
Create Date: 2026-02-24

Missed in the 036 aegis-to-kensa rename migration.  The SQLAlchemy model
was updated to reference kensa_remediation_id, but the DB column was not
renamed, causing ProgrammingError: column scans.kensa_remediation_id
does not exist.
"""

from alembic import op

# Revision identifiers
revision = "040_rename_aegis_remediation_id"
down_revision = "039_add_remediation_evidence"
branch_labels = None
depends_on = None


def upgrade():
    """Rename aegis_remediation_id -> kensa_remediation_id."""
    op.alter_column(
        "scans",
        "aegis_remediation_id",
        new_column_name="kensa_remediation_id",
    )


def downgrade():
    """Rename kensa_remediation_id -> aegis_remediation_id."""
    op.alter_column(
        "scans",
        "kensa_remediation_id",
        new_column_name="aegis_remediation_id",
    )
