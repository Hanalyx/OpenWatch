"""Add 'manual' value to remediation_status enum

Revision ID: 041_add_manual_remediation_status
Revises: 040_rename_aegis_remediation_id
Create Date: 2026-02-24

The remediation task sets rule_status = "manual" for rules that require
manual intervention, but the PostgreSQL enum type only had: pending,
running, completed, failed, rolled_back, cancelled. This caused an
INSERT failure with a PostgreSQL enum violation.

Note: ALTER TYPE ... ADD VALUE cannot run inside a transaction block,
so we use autocommit mode.
"""

from alembic import op

# Revision identifiers
revision = "041_add_manual_remediation_status"
down_revision = "040_rename_aegis_remediation_id"
branch_labels = None
depends_on = None


def upgrade():
    """Add 'manual' to the remediation_status enum type."""
    # ALTER TYPE ... ADD VALUE is non-transactional in PostgreSQL;
    # execute outside the default transaction.
    op.execute("COMMIT")
    op.execute("ALTER TYPE remediation_status ADD VALUE IF NOT EXISTS 'manual'")


def downgrade():
    """PostgreSQL does not support removing values from an enum type.

    To fully reverse this, you would need to:
    1. Create a new enum type without 'manual'
    2. Alter all columns using the enum to the new type
    3. Drop the old enum type

    This is intentionally left as a no-op because the 'manual' value
    is harmless if unused, and the full reversal is risky.
    """
    pass
