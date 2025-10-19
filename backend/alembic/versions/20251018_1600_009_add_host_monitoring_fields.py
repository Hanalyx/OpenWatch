"""Add host monitoring fields for multi-level status tracking

Revision ID: 009
Revises: 008
Create Date: 2025-10-18 16:00:00.000000

This migration adds comprehensive monitoring fields to support:
- Multi-level status tracking (ping -> ssh -> privilege)
- Adaptive check intervals based on host state
- Response time tracking
- Priority-based monitoring scheduling

Status values:
- online: Can ping AND ssh to host (fully operational)
- down: No ping, no ssh (completely unavailable)
- unknown: Host added but not yet checked
- critical: Can ping but can't ssh (partial connectivity)
- maintenance: Planned/manual maintenance mode
- degraded: Can ping and ssh, but no elevated privilege (permission issues)
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = '009'
down_revision = '008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add monitoring fields to hosts table"""

    # Add monitoring scheduling fields
    op.execute("""
        DO $$
        BEGIN
            -- Next check time
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'hosts' AND column_name = 'next_check_time'
            ) THEN
                ALTER TABLE hosts ADD COLUMN next_check_time TIMESTAMP WITHOUT TIME ZONE;
            END IF;

            -- Check priority (1-10, higher = more urgent)
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'hosts' AND column_name = 'check_priority'
            ) THEN
                ALTER TABLE hosts ADD COLUMN check_priority INTEGER NOT NULL DEFAULT 5;
            END IF;

            -- Response time in milliseconds
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'hosts' AND column_name = 'response_time_ms'
            ) THEN
                ALTER TABLE hosts ADD COLUMN response_time_ms INTEGER;
            END IF;

            -- Last state change timestamp
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'hosts' AND column_name = 'last_state_change'
            ) THEN
                ALTER TABLE hosts ADD COLUMN last_state_change TIMESTAMP WITHOUT TIME ZONE;
            END IF;
        END $$
    """)

    # Add consecutive check counters for multi-level monitoring
    op.execute("""
        DO $$
        BEGIN
            -- Ping level counters
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'hosts' AND column_name = 'ping_consecutive_failures'
            ) THEN
                ALTER TABLE hosts ADD COLUMN ping_consecutive_failures INTEGER NOT NULL DEFAULT 0;
            END IF;

            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'hosts' AND column_name = 'ping_consecutive_successes'
            ) THEN
                ALTER TABLE hosts ADD COLUMN ping_consecutive_successes INTEGER NOT NULL DEFAULT 0;
            END IF;

            -- SSH level counters
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'hosts' AND column_name = 'ssh_consecutive_failures'
            ) THEN
                ALTER TABLE hosts ADD COLUMN ssh_consecutive_failures INTEGER NOT NULL DEFAULT 0;
            END IF;

            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'hosts' AND column_name = 'ssh_consecutive_successes'
            ) THEN
                ALTER TABLE hosts ADD COLUMN ssh_consecutive_successes INTEGER NOT NULL DEFAULT 0;
            END IF;

            -- Privilege escalation level counters
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'hosts' AND column_name = 'privilege_consecutive_failures'
            ) THEN
                ALTER TABLE hosts ADD COLUMN privilege_consecutive_failures INTEGER NOT NULL DEFAULT 0;
            END IF;

            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'hosts' AND column_name = 'privilege_consecutive_successes'
            ) THEN
                ALTER TABLE hosts ADD COLUMN privilege_consecutive_successes INTEGER NOT NULL DEFAULT 0;
            END IF;
        END $$
    """)

    # Update existing hosts to have default check priority
    op.execute("""
        UPDATE hosts
        SET check_priority = 5
        WHERE check_priority IS NULL
    """)

    # Create indexes for monitoring performance
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_hosts_next_check_time ON hosts(next_check_time) WHERE is_active = true
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_hosts_check_priority ON hosts(check_priority) WHERE is_active = true
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status) WHERE is_active = true
    """)


def downgrade() -> None:
    """Remove monitoring fields from hosts table"""

    # Drop indexes
    op.execute("DROP INDEX IF EXISTS idx_hosts_status")
    op.execute("DROP INDEX IF EXISTS idx_hosts_check_priority")
    op.execute("DROP INDEX IF EXISTS idx_hosts_next_check_time")

    # Remove monitoring scheduling fields
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'hosts' AND column_name = 'next_check_time') THEN
                ALTER TABLE hosts DROP COLUMN next_check_time;
            END IF;
            IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'hosts' AND column_name = 'check_priority') THEN
                ALTER TABLE hosts DROP COLUMN check_priority;
            END IF;
            IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'hosts' AND column_name = 'response_time_ms') THEN
                ALTER TABLE hosts DROP COLUMN response_time_ms;
            END IF;
            IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'hosts' AND column_name = 'last_state_change') THEN
                ALTER TABLE hosts DROP COLUMN last_state_change;
            END IF;
        END $$
    """)

    # Remove consecutive check counters
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'hosts' AND column_name = 'ping_consecutive_failures') THEN
                ALTER TABLE hosts DROP COLUMN ping_consecutive_failures;
            END IF;
            IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'hosts' AND column_name = 'ping_consecutive_successes') THEN
                ALTER TABLE hosts DROP COLUMN ping_consecutive_successes;
            END IF;
            IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'hosts' AND column_name = 'ssh_consecutive_failures') THEN
                ALTER TABLE hosts DROP COLUMN ssh_consecutive_failures;
            END IF;
            IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'hosts' AND column_name = 'ssh_consecutive_successes') THEN
                ALTER TABLE hosts DROP COLUMN ssh_consecutive_successes;
            END IF;
            IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'hosts' AND column_name = 'privilege_consecutive_failures') THEN
                ALTER TABLE hosts DROP COLUMN privilege_consecutive_failures;
            END IF;
            IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'hosts' AND column_name = 'privilege_consecutive_successes') THEN
                ALTER TABLE hosts DROP COLUMN privilege_consecutive_successes;
            END IF;
        END $$
    """)
