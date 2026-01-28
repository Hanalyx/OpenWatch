"""Merge all migration heads into single linear chain

Consolidates 3 parallel migration branches:
- 20251115_baseline_drift (baseline drift detection tables)
- 20251128_platform_identifier (system settings + platform identifier)
- 20250101_1200 (scheduler config - orphaned branch from baseline)

Revision ID: 20260128_merge_heads
Revises: 20251115_baseline_drift, 20251128_platform_identifier, 20250101_1200
Create Date: 2026-01-28
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "20260128_merge_heads"
down_revision = (
    "20251115_baseline_drift",
    "20251128_platform_identifier",
    "20250101_1200",
)
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Merge migration - no schema changes needed."""
    pass


def downgrade() -> None:
    """Merge migration - no schema changes to revert."""
    pass
