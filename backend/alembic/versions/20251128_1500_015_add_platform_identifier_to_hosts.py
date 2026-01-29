"""
Add platform_identifier column to hosts table

Revision ID: 20251128_platform_identifier
Revises: 20251127_add_system_settings
Create Date: 2025-11-28 15:00:00

Phase 4: Host OS Detection and OVAL Alignment

This migration adds the platform_identifier column to the hosts table.
The platform_identifier is a normalized string (e.g., "rhel9", "ubuntu2204")
derived from os_family and os_version that matches the compliance rules
bundle structure for platform-specific OVAL selection.

Usage:
- Populated by os_discovery_tasks.py via _normalize_platform_identifier()
- Used by mongodb_scan_api.py to select correct OVAL definitions during scans
- Indexed for efficient querying during scan orchestration

Examples:
- RHEL 9.3 -> "rhel9"
- Ubuntu 22.04 -> "ubuntu2204"
- Debian 12 -> "debian12"
"""

import sqlalchemy as sa

from alembic import op

revision = "20251128_platform_identifier"
down_revision = "20251127_add_system_settings"
branch_labels = None
depends_on = None


def upgrade():
    """
    Add platform_identifier column to hosts table.

    The column is:
    - Nullable: Hosts may not have been discovered yet
    - Indexed: Efficient lookup during scan orchestration
    - String(50): Accommodates all platform identifiers (e.g., "ubuntu2204")
    """
    op.add_column(
        "hosts",
        sa.Column(
            "platform_identifier",
            sa.String(50),
            nullable=True,
            comment="Normalized platform ID for OVAL selection (e.g., rhel9, ubuntu2204)",
        ),
    )

    # Create index for efficient lookup during scan orchestration
    op.create_index(
        "ix_hosts_platform_identifier",
        "hosts",
        ["platform_identifier"],
        unique=False,
    )


def downgrade():
    """
    Remove platform_identifier column from hosts table.
    """
    op.drop_index("ix_hosts_platform_identifier", table_name="hosts")
    op.drop_column("hosts", "platform_identifier")
