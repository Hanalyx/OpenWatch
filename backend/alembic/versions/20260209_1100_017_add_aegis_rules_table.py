"""Add aegis_rules table for Aegis rule metadata

Revision ID: 20260209_1100_017
Revises: 20260209_1000_016
Create Date: 2026-02-09

This migration creates the aegis_rules table to store Aegis rule metadata
synced from YAML files. This enables:
- Rule discovery via PostgreSQL queries
- Framework filtering without loading YAML files
- Rule metadata caching
- Historical rule version tracking

Note: This replaces MongoDB for rule storage as part of MongoDB deprecation.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic
revision = "20260209_1100_017"
down_revision = "20260209_1000_016"
branch_labels = None
depends_on = None


def upgrade():
    """Create aegis_rules table with indexes."""
    op.create_table(
        "aegis_rules",
        # Primary key
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        # Rule identification
        sa.Column(
            "rule_id",
            sa.String(255),
            nullable=False,
            unique=True,
            comment="Aegis rule ID (e.g., ssh-disable-root-login)",
        ),
        # Rule metadata
        sa.Column(
            "title",
            sa.String(500),
            nullable=False,
            comment="Human-readable rule title",
        ),
        sa.Column(
            "description",
            sa.Text(),
            nullable=True,
            comment="Detailed rule description",
        ),
        sa.Column(
            "rationale",
            sa.Text(),
            nullable=True,
            comment="Security rationale for the rule",
        ),
        sa.Column(
            "severity",
            sa.String(20),
            nullable=False,
            comment="Rule severity: critical, high, medium, low",
        ),
        sa.Column(
            "category",
            sa.String(100),
            nullable=False,
            comment="Rule category (e.g., access-control, audit)",
        ),
        # JSONB fields for complex data
        sa.Column(
            "tags",
            postgresql.JSONB(),
            nullable=False,
            server_default="[]",
            comment="Rule tags as JSON array",
        ),
        sa.Column(
            "platforms",
            postgresql.JSONB(),
            nullable=False,
            server_default="[]",
            comment="Supported platforms as JSON array",
        ),
        sa.Column(
            "references",
            postgresql.JSONB(),
            nullable=False,
            server_default="{}",
            comment="Framework references (cis, stig, nist) as JSON object",
        ),
        sa.Column(
            "implementations",
            postgresql.JSONB(),
            nullable=False,
            server_default="[]",
            comment="Rule implementations as JSON array",
        ),
        # Version tracking
        sa.Column(
            "aegis_version",
            sa.String(20),
            nullable=False,
            comment="Aegis version this rule was synced from",
        ),
        sa.Column(
            "file_path",
            sa.String(500),
            nullable=True,
            comment="Relative path to YAML file",
        ),
        sa.Column(
            "file_hash",
            sa.String(64),
            nullable=True,
            comment="SHA256 hash of source YAML file for change detection",
        ),
        # Timestamps
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
            comment="When rule was first synced",
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            comment="When rule was last updated",
        ),
        # Constraints
        sa.PrimaryKeyConstraint("id"),
    )

    # Create indexes for common query patterns
    op.create_index("idx_aegis_rules_rule_id", "aegis_rules", ["rule_id"], unique=True)
    op.create_index("idx_aegis_rules_severity", "aegis_rules", ["severity"])
    op.create_index("idx_aegis_rules_category", "aegis_rules", ["category"])

    # GIN indexes for JSONB queries
    op.create_index(
        "idx_aegis_rules_tags",
        "aegis_rules",
        ["tags"],
        postgresql_using="gin",
    )
    op.create_index(
        "idx_aegis_rules_references",
        "aegis_rules",
        ["references"],
        postgresql_using="gin",
    )


def downgrade():
    """Drop aegis_rules table and indexes."""
    op.drop_index("idx_aegis_rules_references", "aegis_rules")
    op.drop_index("idx_aegis_rules_tags", "aegis_rules")
    op.drop_index("idx_aegis_rules_category", "aegis_rules")
    op.drop_index("idx_aegis_rules_severity", "aegis_rules")
    op.drop_index("idx_aegis_rules_rule_id", "aegis_rules")
    op.drop_table("aegis_rules")
