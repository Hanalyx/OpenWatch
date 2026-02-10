"""Add host_users table for server intelligence

Revision ID: 029_host_users
Revises: 028_host_packages_services
Create Date: 2026-02-10

Creates table for storing local user accounts and permissions:
- host_users: User accounts with groups, sudo rules, SSH keys, password info

Part of OpenWatch OS Transformation - Server Intelligence (doc 04).
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers
revision = "029_host_users"
down_revision = "028_host_packages_services"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create host_users table."""
    conn = op.get_bind()

    # Create host_users table
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'host_users')")
    )
    if not result.scalar():
        op.create_table(
            "host_users",
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
            # User information
            sa.Column("username", sa.String(100), nullable=False),
            sa.Column("uid", sa.Integer, nullable=True),
            sa.Column("gid", sa.Integer, nullable=True),
            sa.Column("groups", postgresql.JSONB, nullable=True),  # ["wheel", "docker"]
            sa.Column("home_dir", sa.String(255), nullable=True),
            sa.Column("shell", sa.String(255), nullable=True),
            sa.Column("gecos", sa.String(255), nullable=True),  # Full name/comment
            # Account type
            sa.Column("is_system_account", sa.Boolean, nullable=True),
            sa.Column("is_locked", sa.Boolean, nullable=True),
            # Password information
            sa.Column("has_password", sa.Boolean, nullable=True),
            sa.Column("password_last_changed", sa.DateTime(timezone=True), nullable=True),
            sa.Column("password_expires", sa.DateTime(timezone=True), nullable=True),
            sa.Column("password_max_days", sa.Integer, nullable=True),
            sa.Column("password_warn_days", sa.Integer, nullable=True),
            # Login information
            sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_login_ip", sa.String(45), nullable=True),
            # SSH access
            sa.Column("ssh_keys_count", sa.Integer, nullable=True),
            sa.Column("ssh_key_types", postgresql.JSONB, nullable=True),  # ["rsa", "ed25519"]
            # Sudo permissions
            sa.Column("sudo_rules", postgresql.JSONB, nullable=True),  # Parsed sudo permissions
            sa.Column("has_sudo_all", sa.Boolean, nullable=True),
            sa.Column("has_sudo_nopasswd", sa.Boolean, nullable=True),
            # Timestamps
            sa.Column(
                "collected_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            # Unique constraint on host_id, username
            sa.UniqueConstraint("host_id", "username", name="uq_host_users_host_username"),
        )

        # Create indexes
        op.create_index("ix_host_users_host_id", "host_users", ["host_id"])
        op.create_index("ix_host_users_username", "host_users", ["username"])
        op.create_index("ix_host_users_is_system_account", "host_users", ["is_system_account"])
        op.create_index("ix_host_users_has_sudo_all", "host_users", ["has_sudo_all"])
        op.create_index("ix_host_users_collected_at", "host_users", ["collected_at"])
        # GIN index for JSONB groups queries
        op.create_index(
            "ix_host_users_groups",
            "host_users",
            ["groups"],
            postgresql_using="gin",
        )


def downgrade() -> None:
    """Drop host_users table."""
    conn = op.get_bind()

    # Drop host_users if exists
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'host_users')")
    )
    if result.scalar():
        op.drop_index("ix_host_users_groups", table_name="host_users")
        op.drop_index("ix_host_users_collected_at", table_name="host_users")
        op.drop_index("ix_host_users_has_sudo_all", table_name="host_users")
        op.drop_index("ix_host_users_is_system_account", table_name="host_users")
        op.drop_index("ix_host_users_username", table_name="host_users")
        op.drop_index("ix_host_users_host_id", table_name="host_users")
        op.drop_table("host_users")
