"""Add transactions table for unified transaction log

Revision ID: 044_add_transactions_table
Revises: 043_add_has_remediation
Create Date: 2026-04-11

Implements the transaction log as the primary data model per OPENWATCH_VISION.md.
Every Kensa compliance check and remediation is recorded as a four-phase
transaction (capture -> apply -> validate -> commit/rollback).

This migration creates the table alongside existing scan tables (dual-write).
Old tables are NOT dropped; they continue to be written for rollback safety.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "044_add_transactions_table"
down_revision = "043_add_has_remediation"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "transactions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("rule_id", sa.String(255), nullable=True),
        sa.Column(
            "scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
        ),
        sa.Column("phase", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("initiator_type", sa.String(16), nullable=False, server_default="scheduler"),
        sa.Column("initiator_id", sa.String(255), nullable=True),
        sa.Column("pre_state", postgresql.JSONB, nullable=True),
        sa.Column("apply_plan", postgresql.JSONB, nullable=True),
        sa.Column("validate_result", postgresql.JSONB, nullable=True),
        sa.Column("post_state", postgresql.JSONB, nullable=True),
        sa.Column("evidence_envelope", postgresql.JSONB, nullable=True),
        sa.Column("framework_refs", postgresql.JSONB, nullable=True),
        sa.Column(
            "baseline_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_baselines.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("remediation_job_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
    )

    # Primary per-host timeline query
    op.create_index(
        "ix_transactions_host_started",
        "transactions",
        ["host_id", sa.text("started_at DESC")],
    )

    # Legacy join during migration window
    op.create_index(
        "ix_transactions_scan_id",
        "transactions",
        ["scan_id"],
    )

    # Alert queries: "all failures in last N hours"
    op.create_index(
        "ix_transactions_status_started",
        "transactions",
        ["status", "started_at"],
    )

    # Framework mapping queries via GIN
    op.create_index(
        "ix_transactions_framework_refs_gin",
        "transactions",
        ["framework_refs"],
        postgresql_using="gin",
    )

    # Evidence search via GIN
    op.create_index(
        "ix_transactions_evidence_envelope_gin",
        "transactions",
        ["evidence_envelope"],
        postgresql_using="gin",
    )

    # Remediation chain lookup
    op.create_index(
        "ix_transactions_remediation_job_id",
        "transactions",
        ["remediation_job_id"],
        postgresql_ops={},
    )

    # Multi-tenancy (nullable for now)
    op.create_index(
        "ix_transactions_tenant_id",
        "transactions",
        ["tenant_id"],
    )


def downgrade():
    op.drop_index("ix_transactions_tenant_id")
    op.drop_index("ix_transactions_remediation_job_id")
    op.drop_index("ix_transactions_evidence_envelope_gin")
    op.drop_index("ix_transactions_framework_refs_gin")
    op.drop_index("ix_transactions_status_started")
    op.drop_index("ix_transactions_scan_id")
    op.drop_index("ix_transactions_host_started")
    op.drop_table("transactions")
