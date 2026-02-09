"""Add saved_queries and audit_exports tables for Phase 6 Audit Queries

Revision ID: 024_audit_query_tables
Revises: 023_add_plugin_updates
Create Date: 2026-02-09

Phase 6: Audit Queries
Enables auditors to build, save, and execute compliance evidence queries,
and export results in multiple formats.

OS Claim 3.3: "Audits are queries over canonical evidence"
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# Revision identifiers
revision = "024_audit_query_tables"
down_revision = "023_add_plugin_updates"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create saved_queries and audit_exports tables (idempotent)."""
    conn = op.get_bind()

    # Check if saved_queries table already exists
    result = conn.execute(
        sa.text("SELECT EXISTS (SELECT 1 FROM information_schema.tables " "WHERE table_name = 'saved_queries')")
    )
    if result.scalar():
        # Table exists, just ensure indexes exist
        op.execute("CREATE INDEX IF NOT EXISTS ix_saved_queries_owner " "ON saved_queries (owner_id)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_saved_queries_visibility " "ON saved_queries (visibility)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_audit_exports_query " "ON audit_exports (query_id)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_audit_exports_status " "ON audit_exports (status)")
        return

    # Create query_visibility enum
    op.execute(
        """
        DO $$ BEGIN
            CREATE TYPE query_visibility AS ENUM (
                'private',
                'shared'
            );
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
        """
    )

    # Create export_format enum
    op.execute(
        """
        DO $$ BEGIN
            CREATE TYPE export_format AS ENUM (
                'json',
                'csv',
                'pdf'
            );
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
        """
    )

    # Create export_status enum
    op.execute(
        """
        DO $$ BEGIN
            CREATE TYPE export_status AS ENUM (
                'pending',
                'processing',
                'completed',
                'failed'
            );
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
        """
    )

    # Create saved_queries table
    op.create_table(
        "saved_queries",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("query_definition", JSONB, nullable=False),
        sa.Column(
            "owner_id",
            sa.Integer,
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "visibility",
            postgresql.ENUM(
                "private",
                "shared",
                name="query_visibility",
                create_type=False,
            ),
            nullable=False,
            server_default="private",
            index=True,
        ),
        sa.Column("last_executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("execution_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )

    # Add unique constraint: name must be unique per owner
    op.create_index(
        "ix_saved_queries_owner_name",
        "saved_queries",
        ["owner_id", "name"],
        unique=True,
    )

    # Add GIN index for JSONB query_definition searches
    op.execute("CREATE INDEX ix_saved_queries_definition_gin " "ON saved_queries USING GIN (query_definition)")

    # Create audit_exports table
    op.create_table(
        "audit_exports",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        # Optional reference to saved query (can export ad-hoc queries too)
        sa.Column(
            "query_id",
            UUID(as_uuid=True),
            sa.ForeignKey("saved_queries.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
        # Snapshot of query at export time (required for ad-hoc, copied from saved)
        sa.Column("query_definition", JSONB, nullable=False),
        sa.Column(
            "format",
            postgresql.ENUM(
                "json",
                "csv",
                "pdf",
                name="export_format",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "status",
            postgresql.ENUM(
                "pending",
                "processing",
                "completed",
                "failed",
                name="export_status",
                create_type=False,
            ),
            nullable=False,
            server_default="pending",
            index=True,
        ),
        # File details (populated on completion)
        sa.Column("file_path", sa.String(500), nullable=True),
        sa.Column("file_size_bytes", sa.BigInteger, nullable=True),
        sa.Column("file_checksum", sa.String(64), nullable=True),  # SHA-256
        # Error details (populated on failure)
        sa.Column("error_message", sa.Text, nullable=True),
        # Audit trail
        sa.Column(
            "requested_by",
            sa.Integer,
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        # Retention: exports expire after 7 days by default
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP + INTERVAL '7 days'"),
        ),
    )

    # Index for cleanup of expired exports
    op.create_index(
        "ix_audit_exports_expires",
        "audit_exports",
        ["expires_at"],
        postgresql_where=sa.text("status = 'completed'"),
    )

    # Index for user's exports
    op.create_index(
        "ix_audit_exports_user",
        "audit_exports",
        ["requested_by", "created_at"],
    )


def downgrade() -> None:
    """Drop saved_queries and audit_exports tables."""
    # Drop audit_exports first (has FK to saved_queries)
    op.drop_index("ix_audit_exports_user")
    op.drop_index("ix_audit_exports_expires")
    op.drop_index("ix_audit_exports_status")
    op.drop_index("ix_audit_exports_query")
    op.drop_table("audit_exports")

    # Drop saved_queries
    op.execute("DROP INDEX IF EXISTS ix_saved_queries_definition_gin")
    op.drop_index("ix_saved_queries_owner_name")
    op.drop_index("ix_saved_queries_visibility")
    op.drop_index("ix_saved_queries_owner")
    op.drop_table("saved_queries")

    # Drop enums
    op.execute("DROP TYPE IF EXISTS export_status")
    op.execute("DROP TYPE IF EXISTS export_format")
    op.execute("DROP TYPE IF EXISTS query_visibility")
