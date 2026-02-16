"""Add alerts tables

Revision ID: 033_alerts
Revises: 031_scan_templates
Create Date: 2026-02-10

This is a stub migration file. The actual migration was applied but the file
was lost. The alerts tables (alerts, alert_settings, alert_notifications)
already exist in the database.
"""

# Stub migration - tables already exist, no operations needed

# Revision identifiers
revision = "033_alerts"
down_revision = "031_scan_templates"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Tables already exist - this is a stub migration."""
    pass


def downgrade() -> None:
    """Tables should be preserved - this is a stub migration."""
    pass
