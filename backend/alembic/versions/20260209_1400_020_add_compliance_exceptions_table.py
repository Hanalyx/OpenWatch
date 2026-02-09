"""Add compliance_exceptions table for governance primitives

Revision ID: 020_compliance_exceptions
Revises: 019_posture_snapshots
Create Date: 2026-02-09

Part of Phase 3: Governance Primitives (Aegis Integration Plan)
Enables structured exceptions with approval workflows.

OS Claim: "Exceptions are explicit state, not narrative artifacts"
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# Revision identifiers
revision = "020_compliance_exceptions"
down_revision = "019_posture_snapshots"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create compliance_exceptions table."""
    # Create status enum
    op.execute(
        """
        CREATE TYPE exception_status AS ENUM (
            'pending',
            'approved',
            'rejected',
            'expired',
            'revoked'
        )
        """
    )

    op.create_table(
        "compliance_exceptions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, index=True),
        # Scope - what rule and where
        sa.Column("rule_id", sa.String(255), nullable=False, index=True),
        sa.Column(
            "host_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("hosts.id", ondelete="CASCADE"),
            nullable=True,
            index=True,
        ),
        sa.Column(
            "host_group_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("host_groups.id", ondelete="CASCADE"),
            nullable=True,
        ),
        # Exception details
        sa.Column("justification", sa.Text, nullable=False),
        sa.Column("risk_acceptance", sa.Text, nullable=True),
        sa.Column("compensating_controls", sa.Text, nullable=True),
        sa.Column("business_impact", sa.Text, nullable=True),
        # Lifecycle
        sa.Column(
            "status",
            postgresql.ENUM(
                "pending",
                "approved",
                "rejected",
                "expired",
                "revoked",
                name="exception_status",
                create_type=False,
            ),
            nullable=False,
            server_default="pending",
            index=True,
        ),
        sa.Column(
            "requested_by",
            sa.Integer,
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        sa.Column(
            "requested_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "approved_by",
            sa.Integer,
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column("approved_at", sa.DateTime, nullable=True),
        sa.Column("rejected_by", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("rejected_at", sa.DateTime, nullable=True),
        sa.Column("rejection_reason", sa.Text, nullable=True),
        sa.Column("expires_at", sa.DateTime, nullable=False, index=True),
        sa.Column("revoked_by", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("revoked_at", sa.DateTime, nullable=True),
        sa.Column("revocation_reason", sa.Text, nullable=True),
        # Audit trail
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        # Constraints
        sa.CheckConstraint(
            "(host_id IS NOT NULL) OR (host_group_id IS NOT NULL)",
            name="ck_exception_scope",
        ),
    )

    # Create indexes for common query patterns
    op.create_index(
        "ix_exceptions_active",
        "compliance_exceptions",
        ["rule_id", "status"],
        postgresql_where=sa.text("status = 'approved'"),
    )

    op.create_index(
        "ix_exceptions_expiring",
        "compliance_exceptions",
        ["expires_at"],
        postgresql_where=sa.text("status = 'approved'"),
    )


def downgrade() -> None:
    """Drop compliance_exceptions table."""
    op.drop_index("ix_exceptions_expiring")
    op.drop_index("ix_exceptions_active")
    op.drop_table("compliance_exceptions")
    op.execute("DROP TYPE exception_status")
