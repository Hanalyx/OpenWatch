"""Add smart group validation tables and enhance existing models

Revision ID: 005
Revises: 004
Create Date: 2025-08-26 14:00:00.000000

"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers
revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add smart group validation infrastructure"""

    # Create enum for OS families (idempotent)
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'os_family_type') THEN
                CREATE TYPE os_family_type AS ENUM (
                    'rhel', 'centos', 'fedora', 'ubuntu', 'debian', 'suse', 'opensuse',
                    'windows', 'windows_server', 'macos', 'freebsd', 'openbsd', 'solaris'
                );
            END IF;
        END
        $$;
    """
    )

    # Create enum for group validation rule types (idempotent)
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'group_validation_rule_type') THEN
                CREATE TYPE group_validation_rule_type AS ENUM (
                    'os_family_match', 'os_version_match', 'scap_content_compatibility',
                    'profile_compatibility', 'architecture_match', 'custom_expression'
                );
            END IF;
        END
        $$;
    """
    )

    # Create enum for validation severity (idempotent)
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'validation_severity') THEN
                CREATE TYPE validation_severity AS ENUM (
                    'error', 'warning', 'info'
                );
            END IF;
        END
        $$;
    """
    )

    # Enhanced Host Groups table with validation constraints
    op.add_column(
        "host_groups",
        sa.Column(
            "os_family",
            postgresql.ENUM(
                "rhel",
                "centos",
                "fedora",
                "ubuntu",
                "debian",
                "suse",
                "opensuse",
                "windows",
                "windows_server",
                "macos",
                "freebsd",
                "openbsd",
                "solaris",
                name="os_family_type",
            ),
            nullable=True,
        ),
    )
    op.add_column("host_groups", sa.Column("os_version_pattern", sa.String(length=50), nullable=True))
    op.add_column("host_groups", sa.Column("architecture", sa.String(length=20), nullable=True))
    op.add_column("host_groups", sa.Column("scap_content_id", sa.Integer(), nullable=True))
    op.add_column("host_groups", sa.Column("default_profile_id", sa.String(length=100), nullable=True))
    op.add_column("host_groups", sa.Column("compliance_framework", sa.String(length=50), nullable=True))
    op.add_column("host_groups", sa.Column("auto_scan_enabled", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("host_groups", sa.Column("scan_schedule", sa.String(length=100), nullable=True))
    op.add_column("host_groups", sa.Column("validation_rules", postgresql.JSON(astext_type=sa.Text()), nullable=True))
    op.add_column("host_groups", sa.Column("group_metadata", postgresql.JSON(astext_type=sa.Text()), nullable=True))

    # Add foreign key constraint for SCAP content
    op.create_foreign_key("fk_host_groups_scap_content", "host_groups", "scap_content", ["scap_content_id"], ["id"])

    # Enhanced Hosts table with structured OS information
    op.add_column(
        "hosts",
        sa.Column(
            "os_family",
            postgresql.ENUM(
                "rhel",
                "centos",
                "fedora",
                "ubuntu",
                "debian",
                "suse",
                "opensuse",
                "windows",
                "windows_server",
                "macos",
                "freebsd",
                "openbsd",
                "solaris",
                name="os_family_type",
            ),
            nullable=True,
        ),
    )
    op.add_column("hosts", sa.Column("os_version", sa.String(length=50), nullable=True))
    op.add_column("hosts", sa.Column("os_release", sa.String(length=100), nullable=True))
    op.add_column("hosts", sa.Column("architecture", sa.String(length=20), nullable=True))
    op.add_column("hosts", sa.Column("kernel_version", sa.String(length=100), nullable=True))
    op.add_column("hosts", sa.Column("os_metadata", postgresql.JSON(astext_type=sa.Text()), nullable=True))
    op.add_column("hosts", sa.Column("last_os_detection", sa.DateTime(), nullable=True))
    op.add_column("hosts", sa.Column("compatibility_metadata", postgresql.JSON(astext_type=sa.Text()), nullable=True))

    # Add missing SSH key metadata columns referenced in code
    op.add_column("hosts", sa.Column("ssh_key_fingerprint", sa.String(length=128), nullable=True))
    op.add_column("hosts", sa.Column("ssh_key_type", sa.String(length=20), nullable=True))
    op.add_column("hosts", sa.Column("ssh_key_bits", sa.Integer(), nullable=True))
    op.add_column("hosts", sa.Column("ssh_key_comment", sa.String(length=255), nullable=True))
    op.add_column("hosts", sa.Column("last_check", sa.DateTime(), nullable=True))

    # Create index for SSH key fingerprint
    op.create_index("idx_hosts_ssh_key_fingerprint", "hosts", ["ssh_key_fingerprint"])

    # Group Validation Rules table
    op.create_table(
        "group_validation_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.Column(
            "rule_type",
            postgresql.ENUM(
                "os_family_match",
                "os_version_match",
                "scap_content_compatibility",
                "profile_compatibility",
                "architecture_match",
                "custom_expression",
                name="group_validation_rule_type",
            ),
            nullable=False,
        ),
        sa.Column("rule_expression", sa.Text(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=False),
        sa.Column("severity", postgresql.ENUM("error", "warning", "info", name="validation_severity"), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
        ),
        sa.ForeignKeyConstraint(["group_id"], ["host_groups.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_group_validation_rules_group", "group_validation_rules", ["group_id"])
    op.create_index("idx_group_validation_rules_type", "group_validation_rules", ["rule_type"])
    op.create_index("idx_group_validation_rules_active", "group_validation_rules", ["is_active"])

    # Host Compatibility Cache table
    op.create_table(
        "host_compatibility_cache",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.Column("is_compatible", sa.Boolean(), nullable=False),
        sa.Column("compatibility_score", sa.Float(), nullable=True),
        sa.Column("validation_results", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("scap_content_compatible", sa.Boolean(), nullable=True),
        sa.Column("os_compatible", sa.Boolean(), nullable=True),
        sa.Column("architecture_compatible", sa.Boolean(), nullable=True),
        sa.Column("last_validated", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("cache_expires_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["group_id"], ["host_groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("host_id", "group_id", name="uq_host_group_compatibility"),
    )
    op.create_index("idx_host_compatibility_host", "host_compatibility_cache", ["host_id"])
    op.create_index("idx_host_compatibility_group", "host_compatibility_cache", ["group_id"])
    op.create_index("idx_host_compatibility_expires", "host_compatibility_cache", ["cache_expires_at"])
    op.create_index("idx_host_compatibility_score", "host_compatibility_cache", ["compatibility_score"])

    # Group Assignment History table
    op.create_table(
        "group_assignment_history",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(length=20), nullable=False),  # 'added', 'removed', 'rejected'
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("validation_results", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("performed_by", sa.Integer(), nullable=True),
        sa.Column("performed_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("batch_id", postgresql.UUID(as_uuid=True), nullable=True),  # For bulk operations
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["host_groups.id"],
        ),
        sa.ForeignKeyConstraint(
            ["host_id"],
            ["hosts.id"],
        ),
        sa.ForeignKeyConstraint(
            ["performed_by"],
            ["users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_group_assignment_history_host", "group_assignment_history", ["host_id"])
    op.create_index("idx_group_assignment_history_group", "group_assignment_history", ["group_id"])
    op.create_index("idx_group_assignment_history_action", "group_assignment_history", ["action"])
    op.create_index("idx_group_assignment_history_batch", "group_assignment_history", ["batch_id"])
    op.create_index("idx_group_assignment_history_date", "group_assignment_history", ["performed_at"])

    # SCAP Content Compatibility Matrix table
    op.create_table(
        "scap_content_compatibility",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("content_id", sa.Integer(), nullable=False),
        sa.Column(
            "os_family",
            postgresql.ENUM(
                "rhel",
                "centos",
                "fedora",
                "ubuntu",
                "debian",
                "suse",
                "opensuse",
                "windows",
                "windows_server",
                "macos",
                "freebsd",
                "openbsd",
                "solaris",
                name="os_family_type",
            ),
            nullable=False,
        ),
        sa.Column("os_version_pattern", sa.String(length=100), nullable=False),
        sa.Column("architecture", sa.String(length=20), nullable=True),
        sa.Column("compatibility_score", sa.Float(), nullable=False),
        sa.Column("supported_profiles", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("known_issues", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("last_tested", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["content_id"], ["scap_content.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "content_id", "os_family", "os_version_pattern", "architecture", name="uq_scap_os_compatibility"
        ),
    )
    op.create_index("idx_scap_compatibility_content", "scap_content_compatibility", ["content_id"])
    op.create_index("idx_scap_compatibility_os", "scap_content_compatibility", ["os_family", "os_version_pattern"])
    op.create_index("idx_scap_compatibility_score", "scap_content_compatibility", ["compatibility_score"])

    # Smart Group Recommendations table
    op.create_table(
        "smart_group_recommendations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("recommended_group_id", sa.Integer(), nullable=True),
        sa.Column(
            "recommendation_type", sa.String(length=50), nullable=False
        ),  # 'auto_detected', 'similarity_based', 'content_based'
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("reasoning", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("alternative_groups", postgresql.ARRAY(sa.Integer()), nullable=True),
        sa.Column("is_accepted", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["recommended_group_id"], ["host_groups.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_smart_recommendations_host", "smart_group_recommendations", ["host_id"])
    op.create_index("idx_smart_recommendations_group", "smart_group_recommendations", ["recommended_group_id"])
    op.create_index("idx_smart_recommendations_confidence", "smart_group_recommendations", ["confidence_score"])
    op.create_index("idx_smart_recommendations_type", "smart_group_recommendations", ["recommendation_type"])

    # Create indexes for enhanced host groups
    op.create_index("idx_host_groups_os_family", "host_groups", ["os_family"])
    op.create_index("idx_host_groups_scap_content", "host_groups", ["scap_content_id"])
    op.create_index("idx_host_groups_framework", "host_groups", ["compliance_framework"])
    op.create_index("idx_host_groups_auto_scan", "host_groups", ["auto_scan_enabled"])

    # Create indexes for enhanced hosts
    op.create_index("idx_hosts_os_family", "hosts", ["os_family"])
    op.create_index("idx_hosts_os_family_version", "hosts", ["os_family", "os_version"])
    op.create_index("idx_hosts_architecture", "hosts", ["architecture"])
    op.create_index("idx_hosts_last_os_detection", "hosts", ["last_os_detection"])

    # Create views for smart grouping insights
    op.execute(
        """
        CREATE OR REPLACE VIEW group_compatibility_summary AS
        SELECT
            hg.id as group_id,
            hg.name as group_name,
            hg.os_family,
            hg.os_version_pattern,
            hg.compliance_framework,
            COUNT(hgm.host_id) as total_hosts,
            COUNT(CASE WHEN hcc.is_compatible = true THEN 1 END) as compatible_hosts,
            COUNT(CASE WHEN hcc.is_compatible = false THEN 1 END) as incompatible_hosts,
            AVG(hcc.compatibility_score) as avg_compatibility_score,
            COUNT(sgr.host_id) as pending_recommendations
        FROM host_groups hg
        LEFT JOIN host_group_memberships hgm ON hg.id = hgm.group_id
        LEFT JOIN host_compatibility_cache hcc ON hg.id = hcc.group_id AND hgm.host_id = hcc.host_id
        LEFT JOIN smart_group_recommendations sgr ON hg.id = sgr.recommended_group_id AND sgr.is_accepted IS NULL
        GROUP BY hg.id, hg.name, hg.os_family, hg.os_version_pattern, hg.compliance_framework
        ORDER BY hg.name;
    """
    )

    op.execute(
        """
        CREATE OR REPLACE VIEW host_group_compatibility AS
        SELECT
            h.id as host_id,
            h.hostname,
            h.os_family,
            h.os_version,
            h.architecture,
            hg.id as group_id,
            hg.name as group_name,
            hg.os_family as group_os_family,
            hg.os_version_pattern,
            hcc.is_compatible,
            hcc.compatibility_score,
            hcc.validation_results,
            CASE
                WHEN hgm.host_id IS NOT NULL THEN 'assigned'
                WHEN hcc.is_compatible = true THEN 'compatible'
                WHEN hcc.is_compatible = false THEN 'incompatible'
                ELSE 'unknown'
            END as assignment_status
        FROM hosts h
        CROSS JOIN host_groups hg
        LEFT JOIN host_group_memberships hgm ON h.id = hgm.host_id AND hg.id = hgm.group_id
        LEFT JOIN host_compatibility_cache hcc ON h.id = hcc.host_id AND hg.id = hcc.group_id
        ORDER BY h.hostname, hg.name;
    """
    )

    # Insert some default validation rules for common group types
    op.execute(
        """
        -- These will be populated by the application when groups are created
        -- This is just the table structure for now
        SELECT 1 WHERE FALSE; -- Placeholder to ensure migration succeeds
    """
    )


def downgrade() -> None:
    """Remove smart group validation infrastructure"""

    # Drop views
    op.execute("DROP VIEW IF EXISTS host_group_compatibility")
    op.execute("DROP VIEW IF EXISTS group_compatibility_summary")

    # Drop indexes for enhanced hosts
    op.drop_index("idx_hosts_last_os_detection", table_name="hosts")
    op.drop_index("idx_hosts_architecture", table_name="hosts")
    op.drop_index("idx_hosts_os_family_version", table_name="hosts")
    op.drop_index("idx_hosts_os_family", table_name="hosts")

    # Drop indexes for enhanced host groups
    op.drop_index("idx_host_groups_auto_scan", table_name="host_groups")
    op.drop_index("idx_host_groups_framework", table_name="host_groups")
    op.drop_index("idx_host_groups_scap_content", table_name="host_groups")
    op.drop_index("idx_host_groups_os_family", table_name="host_groups")

    # Drop new tables
    op.drop_index("idx_smart_recommendations_type", table_name="smart_group_recommendations")
    op.drop_index("idx_smart_recommendations_confidence", table_name="smart_group_recommendations")
    op.drop_index("idx_smart_recommendations_group", table_name="smart_group_recommendations")
    op.drop_index("idx_smart_recommendations_host", table_name="smart_group_recommendations")
    op.drop_table("smart_group_recommendations")

    op.drop_index("idx_scap_compatibility_score", table_name="scap_content_compatibility")
    op.drop_index("idx_scap_compatibility_os", table_name="scap_content_compatibility")
    op.drop_index("idx_scap_compatibility_content", table_name="scap_content_compatibility")
    op.drop_table("scap_content_compatibility")

    op.drop_index("idx_group_assignment_history_date", table_name="group_assignment_history")
    op.drop_index("idx_group_assignment_history_batch", table_name="group_assignment_history")
    op.drop_index("idx_group_assignment_history_action", table_name="group_assignment_history")
    op.drop_index("idx_group_assignment_history_group", table_name="group_assignment_history")
    op.drop_index("idx_group_assignment_history_host", table_name="group_assignment_history")
    op.drop_table("group_assignment_history")

    op.drop_index("idx_host_compatibility_score", table_name="host_compatibility_cache")
    op.drop_index("idx_host_compatibility_expires", table_name="host_compatibility_cache")
    op.drop_index("idx_host_compatibility_group", table_name="host_compatibility_cache")
    op.drop_index("idx_host_compatibility_host", table_name="host_compatibility_cache")
    op.drop_table("host_compatibility_cache")

    op.drop_index("idx_group_validation_rules_active", table_name="group_validation_rules")
    op.drop_index("idx_group_validation_rules_type", table_name="group_validation_rules")
    op.drop_index("idx_group_validation_rules_group", table_name="group_validation_rules")
    op.drop_table("group_validation_rules")

    # Remove SSH key columns from hosts
    op.drop_index("idx_hosts_ssh_key_fingerprint", table_name="hosts")
    op.drop_column("hosts", "last_check")
    op.drop_column("hosts", "ssh_key_comment")
    op.drop_column("hosts", "ssh_key_bits")
    op.drop_column("hosts", "ssh_key_type")
    op.drop_column("hosts", "ssh_key_fingerprint")

    # Remove enhanced host columns
    op.drop_column("hosts", "compatibility_metadata")
    op.drop_column("hosts", "last_os_detection")
    op.drop_column("hosts", "os_metadata")
    op.drop_column("hosts", "kernel_version")
    op.drop_column("hosts", "architecture")
    op.drop_column("hosts", "os_release")
    op.drop_column("hosts", "os_version")
    op.drop_column("hosts", "os_family")

    # Remove enhanced host group columns
    op.drop_constraint("fk_host_groups_scap_content", "host_groups", type_="foreignkey")
    op.drop_column("host_groups", "group_metadata")
    op.drop_column("host_groups", "validation_rules")
    op.drop_column("host_groups", "scan_schedule")
    op.drop_column("host_groups", "auto_scan_enabled")
    op.drop_column("host_groups", "compliance_framework")
    op.drop_column("host_groups", "default_profile_id")
    op.drop_column("host_groups", "scap_content_id")
    op.drop_column("host_groups", "architecture")
    op.drop_column("host_groups", "os_version_pattern")
    op.drop_column("host_groups", "os_family")

    # Drop enum types
    op.execute("DROP TYPE IF EXISTS validation_severity")
    op.execute("DROP TYPE IF EXISTS group_validation_rule_type")
    op.execute("DROP TYPE IF EXISTS os_family_type")
