"""Add host_network and host_firewall_rules tables

Revision ID: 030_host_network
Revises: 029_host_users
Create Date: 2026-02-10

Creates tables for storing network configuration:
- host_network: Network interfaces with IP addresses and state
- host_firewall_rules: Firewall rules (iptables/firewalld)

Part of OpenWatch OS Transformation - Server Intelligence (doc 04).
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers
revision = "030_host_network"
down_revision = "029_host_users"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create host_network and host_firewall_rules tables."""
    conn = op.get_bind()

    # Create host_network table
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'host_network')")
    )
    if not result.scalar():
        op.create_table(
            "host_network",
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
            sa.Column("interface_name", sa.String(50), nullable=False),
            sa.Column("mac_address", sa.String(17)),
            sa.Column("ip_addresses", postgresql.JSONB),
            sa.Column("is_up", sa.Boolean),
            sa.Column("mtu", sa.Integer),
            sa.Column("speed_mbps", sa.Integer),
            sa.Column("interface_type", sa.String(50)),  # ethernet, loopback, bridge, vlan, etc.
            sa.Column(
                "collected_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.UniqueConstraint("host_id", "interface_name", name="uq_host_network_interface"),
        )

        # Create indexes for host_network
        op.create_index("idx_host_network_host", "host_network", ["host_id"])
        op.create_index(
            "idx_host_network_ip_addresses",
            "host_network",
            ["ip_addresses"],
            postgresql_using="gin",
        )

    # Create host_firewall_rules table
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'host_firewall_rules')")
    )
    if not result.scalar():
        op.create_table(
            "host_firewall_rules",
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
            sa.Column("firewall_type", sa.String(50)),  # iptables, nftables, firewalld
            sa.Column("chain", sa.String(50)),  # INPUT, OUTPUT, FORWARD
            sa.Column("rule_number", sa.Integer),
            sa.Column("protocol", sa.String(20)),  # tcp, udp, icmp, all
            sa.Column("source", sa.String(100)),
            sa.Column("destination", sa.String(100)),
            sa.Column("port", sa.String(50)),  # Can be range like "8000:8080"
            sa.Column("action", sa.String(20)),  # ACCEPT, DROP, REJECT
            sa.Column("interface_in", sa.String(50)),
            sa.Column("interface_out", sa.String(50)),
            sa.Column("state", sa.String(100)),  # NEW, ESTABLISHED, RELATED
            sa.Column("comment", sa.Text),
            sa.Column("raw_rule", sa.Text),  # Original rule text
            sa.Column(
                "collected_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
        )

        # Create indexes for host_firewall_rules
        op.create_index("idx_host_firewall_host", "host_firewall_rules", ["host_id"])
        op.create_index("idx_host_firewall_chain", "host_firewall_rules", ["chain"])
        op.create_index("idx_host_firewall_action", "host_firewall_rules", ["action"])

    # Create host_routes table (routing table information)
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'host_routes')")
    )
    if not result.scalar():
        op.create_table(
            "host_routes",
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
            sa.Column("destination", sa.String(100), nullable=False),  # Network/host CIDR
            sa.Column("gateway", sa.String(45)),  # Gateway IP (null for direct routes)
            sa.Column("interface", sa.String(50)),  # Output interface
            sa.Column("metric", sa.Integer),
            sa.Column("scope", sa.String(20)),  # link, host, global
            sa.Column("route_type", sa.String(20)),  # unicast, local, broadcast
            sa.Column("protocol", sa.String(20)),  # kernel, static, dhcp
            sa.Column("is_default", sa.Boolean, default=False),
            sa.Column(
                "collected_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
        )

        # Create indexes for host_routes
        op.create_index("idx_host_routes_host", "host_routes", ["host_id"])
        op.create_index("idx_host_routes_default", "host_routes", ["host_id", "is_default"])


def downgrade() -> None:
    """Drop host_network, host_firewall_rules, and host_routes tables."""
    op.drop_table("host_routes")
    op.drop_table("host_firewall_rules")
    op.drop_table("host_network")
