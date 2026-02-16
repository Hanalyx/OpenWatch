"""Merge alerts branches

Revision ID: 035_merge_alerts
Revises: 034_remove_scap_fields, 033b_alerts_full
Create Date: 2026-02-16

Merges the main branch (scan_templates -> stub alerts -> rename_schedule ->
remove_scap_fields) with the alerts feature branch (audit_events ->
host_metrics -> alerts_full).
"""

# Revision identifiers
revision = "035_merge_alerts"
down_revision = ("034_remove_scap_fields", "033b_alerts_full")
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Merge point - no schema changes needed."""
    pass


def downgrade() -> None:
    """Merge point - no schema changes needed."""
    pass
