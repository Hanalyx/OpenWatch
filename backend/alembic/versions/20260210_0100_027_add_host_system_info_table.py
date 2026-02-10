"""Add host_system_info table for detailed system information

Revision ID: 027_host_system_info
Revises: 026_compliance_scheduler
Create Date: 2026-02-10

Creates table for storing detailed host system information collected during scans:
- Kernel version, CPU info, memory, SELinux status, firewall status
- Historical tracking with updated_at timestamp
- Rich OS version info (RHEL 9.4 vs just RHEL)

Part of OpenWatch OS Transformation - Server Intelligence.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers
revision = "027_host_system_info"
down_revision = "026_compliance_scheduler"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create host_system_info table."""
    conn = op.get_bind()

    # Check if table already exists
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'host_system_info')")
    )
    if not result.scalar():
        op.create_table(
            "host_system_info",
            sa.Column(
                "id",
                postgresql.UUID(as_uuid=True),
                primary_key=True,
                server_default=sa.text("gen_random_uuid()"),
            ),
            sa.Column(
                "host_id",
                postgresql.UUID(as_uuid=True),
                sa.ForeignKey("hosts.id", ondelete="CASCADE"),
                nullable=False,
                unique=True,
            ),
            # OS Information
            sa.Column("os_name", sa.String(255), nullable=True),  # Red Hat Enterprise Linux
            sa.Column("os_version", sa.String(50), nullable=True),  # 9.4
            sa.Column("os_version_full", sa.String(255), nullable=True),  # 9.4 (Plow)
            sa.Column("os_pretty_name", sa.String(255), nullable=True),  # Red Hat Enterprise Linux 9.4 (Plow)
            sa.Column("os_id", sa.String(50), nullable=True),  # rhel
            sa.Column("os_id_like", sa.String(100), nullable=True),  # fedora
            # Kernel Information
            sa.Column("kernel_version", sa.String(100), nullable=True),  # 5.14.0-362.el9.x86_64
            sa.Column("kernel_release", sa.String(100), nullable=True),  # 5.14.0-362.el9.x86_64
            sa.Column("kernel_name", sa.String(50), nullable=True),  # Linux
            # Hardware Information
            sa.Column("architecture", sa.String(50), nullable=True),  # x86_64
            sa.Column("cpu_model", sa.String(255), nullable=True),  # Intel(R) Xeon(R) CPU @ 2.30GHz
            sa.Column("cpu_cores", sa.Integer, nullable=True),  # 4
            sa.Column("cpu_threads", sa.Integer, nullable=True),  # 8
            sa.Column("memory_total_mb", sa.Integer, nullable=True),  # 16384
            sa.Column("memory_available_mb", sa.Integer, nullable=True),  # 8192
            sa.Column("swap_total_mb", sa.Integer, nullable=True),  # 4096
            # Disk Information
            sa.Column("disk_total_gb", sa.Float, nullable=True),  # 100.0
            sa.Column("disk_used_gb", sa.Float, nullable=True),  # 45.5
            sa.Column("disk_free_gb", sa.Float, nullable=True),  # 54.5
            # Security Status
            sa.Column("selinux_status", sa.String(50), nullable=True),  # enforcing, permissive, disabled
            sa.Column("selinux_mode", sa.String(50), nullable=True),  # targeted, mls, minimum
            sa.Column("firewall_status", sa.String(50), nullable=True),  # active, inactive
            sa.Column("firewall_service", sa.String(50), nullable=True),  # firewalld, iptables, nftables
            # Network Information
            sa.Column("hostname", sa.String(255), nullable=True),
            sa.Column("fqdn", sa.String(255), nullable=True),
            sa.Column("primary_ip", sa.String(45), nullable=True),  # IPv4 or IPv6
            # System Uptime
            sa.Column("uptime_seconds", sa.BigInteger, nullable=True),
            sa.Column("boot_time", sa.DateTime(timezone=True), nullable=True),
            # Timestamps
            sa.Column(
                "collected_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
        )

        # Create index on host_id for lookups
        op.create_index(
            "ix_host_system_info_host_id",
            "host_system_info",
            ["host_id"],
            unique=True,
        )

        # Create index on collected_at for time-based queries
        op.create_index(
            "ix_host_system_info_collected_at",
            "host_system_info",
            ["collected_at"],
        )


def downgrade() -> None:
    """Drop host_system_info table."""
    conn = op.get_bind()

    # Check if table exists before dropping
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'host_system_info')")
    )
    if result.scalar():
        op.drop_index("ix_host_system_info_collected_at", table_name="host_system_info")
        op.drop_index("ix_host_system_info_host_id", table_name="host_system_info")
        op.drop_table("host_system_info")
