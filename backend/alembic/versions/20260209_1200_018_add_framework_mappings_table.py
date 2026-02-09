"""Add framework_mappings table for control mappings

Revision ID: 20260209_1200_018
Revises: 20260209_1100_017
Create Date: 2026-02-09

This migration creates the framework_mappings table to store framework
control mappings extracted from Aegis rules. This enables:
- Fast framework coverage queries
- Control-to-rule lookups
- Framework compliance reporting
- Audit trail of control coverage

The data is extracted from aegis_rules.references JSONB field during sync.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic
revision = "20260209_1200_018"
down_revision = "20260209_1100_017"
branch_labels = None
depends_on = None


def upgrade():
    """Create framework_mappings table with indexes."""
    # Check if table already exists (idempotent migration)
    conn = op.get_bind()
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT FROM information_schema.tables " "WHERE table_name = 'framework_mappings')")
    )
    table_exists = result.scalar()

    if not table_exists:
        op.create_table(
            "framework_mappings",
            # Primary key
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            # Framework identification
            sa.Column(
                "framework",
                sa.String(50),
                nullable=False,
                comment="Framework name: cis, stig, nist_800_53, pci_dss, srg",
            ),
            sa.Column(
                "framework_version",
                sa.String(50),
                nullable=True,
                comment="Framework version (e.g., rhel9_v2, v2r7)",
            ),
            # Control identification
            sa.Column(
                "control_id",
                sa.String(100),
                nullable=False,
                comment="Control ID within framework (e.g., 5.1.20, V-257947, AC-6)",
            ),
            sa.Column(
                "control_title",
                sa.String(500),
                nullable=True,
                comment="Human-readable control title",
            ),
            # STIG-specific fields
            sa.Column(
                "stig_id",
                sa.String(50),
                nullable=True,
                comment="STIG rule ID (e.g., RHEL-09-255045)",
            ),
            sa.Column(
                "vuln_id",
                sa.String(50),
                nullable=True,
                comment="Vulnerability ID (e.g., V-257947)",
            ),
            sa.Column(
                "cci",
                postgresql.JSONB(),
                nullable=True,
                comment="CCI references as JSON array",
            ),
            # CIS-specific fields
            sa.Column(
                "cis_section",
                sa.String(50),
                nullable=True,
                comment="CIS section number (e.g., 5.1.20)",
            ),
            sa.Column(
                "cis_level",
                sa.String(10),
                nullable=True,
                comment="CIS level (L1 or L2)",
            ),
            sa.Column(
                "cis_type",
                sa.String(20),
                nullable=True,
                comment="Check type (Automated or Manual)",
            ),
            # Control severity
            sa.Column(
                "severity",
                sa.String(20),
                nullable=True,
                comment="Control severity (CAT I/II/III for STIG)",
            ),
            # Link to Aegis rule
            sa.Column(
                "aegis_rule_id",
                sa.String(255),
                nullable=False,
                comment="Aegis rule ID (FK to aegis_rules.rule_id)",
            ),
            # Timestamps
            sa.Column(
                "created_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.func.now(),
                comment="When mapping was created",
            ),
            # Constraints
            sa.PrimaryKeyConstraint("id"),
        )

    # Create indexes for common query patterns (idempotent with IF NOT EXISTS)
    op.execute("CREATE INDEX IF NOT EXISTS idx_framework_mappings_framework " "ON framework_mappings (framework)")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_framework_mappings_framework_version "
        "ON framework_mappings (framework, framework_version)"
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_framework_mappings_control_id " "ON framework_mappings (control_id)")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_framework_mappings_aegis_rule_id " "ON framework_mappings (aegis_rule_id)"
    )

    # Composite index for framework + control lookups
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_framework_mappings_lookup "
        "ON framework_mappings (framework, framework_version, control_id)"
    )

    # Unique constraint to prevent duplicates
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_framework_mappings_unique "
        "ON framework_mappings (framework, framework_version, control_id, aegis_rule_id)"
    )


def downgrade():
    """Drop framework_mappings table and indexes."""
    op.drop_index("idx_framework_mappings_unique", "framework_mappings")
    op.drop_index("idx_framework_mappings_lookup", "framework_mappings")
    op.drop_index("idx_framework_mappings_aegis_rule_id", "framework_mappings")
    op.drop_index("idx_framework_mappings_control_id", "framework_mappings")
    op.drop_index("idx_framework_mappings_framework_version", "framework_mappings")
    op.drop_index("idx_framework_mappings_framework", "framework_mappings")
    op.drop_table("framework_mappings")
