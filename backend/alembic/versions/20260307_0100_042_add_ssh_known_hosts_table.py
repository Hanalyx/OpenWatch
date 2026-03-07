"""Add ssh_known_hosts table

Revision ID: 042_ssh_known_hosts
Revises: 20260224_0300_041_add_manual_remediation_status
Create Date: 2026-03-07
"""

import sqlalchemy as sa

from alembic import op

revision = "042_ssh_known_hosts"
down_revision = "20260224_0300_041_add_manual_remediation_status"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ssh_known_hosts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("key_type", sa.String(20), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(100), nullable=False),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("last_verified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_trusted", sa.Boolean(), server_default=sa.text("TRUE")),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.UniqueConstraint("hostname", "key_type"),
    )
    op.create_index("idx_ssh_known_hosts_hostname", "ssh_known_hosts", ["hostname"])
    op.create_index("idx_ssh_known_hosts_fingerprint", "ssh_known_hosts", ["fingerprint"])


def downgrade():
    op.drop_index("idx_ssh_known_hosts_fingerprint")
    op.drop_index("idx_ssh_known_hosts_hostname")
    op.drop_table("ssh_known_hosts")
