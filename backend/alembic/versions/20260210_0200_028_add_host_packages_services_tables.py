"""Add host_packages and host_services tables for server intelligence

Revision ID: 028_host_packages_services
Revises: 027_host_system_info
Create Date: 2026-02-10

Creates tables for storing installed packages and running services:
- host_packages: Installed RPM/DEB packages with version info
- host_services: Running systemd services with status and listening ports

Part of OpenWatch OS Transformation - Server Intelligence (doc 04).
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers
revision = "028_host_packages_services"
down_revision = "027_host_system_info"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create host_packages and host_services tables."""
    conn = op.get_bind()

    # Create host_packages table
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'host_packages')")
    )
    if not result.scalar():
        op.create_table(
            "host_packages",
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
            ),
            # Package information
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("version", sa.String(100), nullable=True),
            sa.Column("release", sa.String(100), nullable=True),
            sa.Column("arch", sa.String(50), nullable=True),
            sa.Column("source_repo", sa.String(255), nullable=True),
            sa.Column("installed_at", sa.DateTime(timezone=True), nullable=True),
            # Timestamps
            sa.Column(
                "collected_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            # Unique constraint on host_id, name, arch
            sa.UniqueConstraint("host_id", "name", "arch", name="uq_host_packages_host_name_arch"),
        )

        # Create indexes
        op.create_index("ix_host_packages_host_id", "host_packages", ["host_id"])
        op.create_index("ix_host_packages_name", "host_packages", ["name"])
        op.create_index("ix_host_packages_collected_at", "host_packages", ["collected_at"])

    # Create host_services table
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'host_services')")
    )
    if not result.scalar():
        op.create_table(
            "host_services",
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
            ),
            # Service information
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("display_name", sa.String(255), nullable=True),
            sa.Column("status", sa.String(50), nullable=True),  # running, stopped, failed
            sa.Column("enabled", sa.Boolean, nullable=True),
            sa.Column("service_type", sa.String(50), nullable=True),  # simple, forking, oneshot
            sa.Column("run_as_user", sa.String(100), nullable=True),
            # Listening ports as JSONB: [{"port": 22, "protocol": "tcp", "address": "0.0.0.0"}]
            sa.Column("listening_ports", postgresql.JSONB, nullable=True),
            # Timestamps
            sa.Column(
                "collected_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            # Unique constraint on host_id, name
            sa.UniqueConstraint("host_id", "name", name="uq_host_services_host_name"),
        )

        # Create indexes
        op.create_index("ix_host_services_host_id", "host_services", ["host_id"])
        op.create_index("ix_host_services_name", "host_services", ["name"])
        op.create_index("ix_host_services_status", "host_services", ["status"])
        op.create_index("ix_host_services_collected_at", "host_services", ["collected_at"])
        # GIN index for JSONB listening_ports queries
        op.create_index(
            "ix_host_services_listening_ports",
            "host_services",
            ["listening_ports"],
            postgresql_using="gin",
        )


def downgrade() -> None:
    """Drop host_packages and host_services tables."""
    conn = op.get_bind()

    # Drop host_services if exists
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'host_services')")
    )
    if result.scalar():
        op.drop_index("ix_host_services_listening_ports", table_name="host_services")
        op.drop_index("ix_host_services_collected_at", table_name="host_services")
        op.drop_index("ix_host_services_status", table_name="host_services")
        op.drop_index("ix_host_services_name", table_name="host_services")
        op.drop_index("ix_host_services_host_id", table_name="host_services")
        op.drop_table("host_services")

    # Drop host_packages if exists
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'host_packages')")
    )
    if result.scalar():
        op.drop_index("ix_host_packages_collected_at", table_name="host_packages")
        op.drop_index("ix_host_packages_name", table_name="host_packages")
        op.drop_index("ix_host_packages_host_id", table_name="host_packages")
        op.drop_table("host_packages")
