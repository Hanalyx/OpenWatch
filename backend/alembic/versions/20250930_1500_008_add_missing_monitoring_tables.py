"""Add missing monitoring tables and columns

Revision ID: 008
Revises: 010
Create Date: 2025-09-30 15:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '008'
down_revision = '010'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add missing alert_settings table and last_check column if not exists"""
    
    # Create alert_settings table if it doesn't exist
    op.execute("""
        CREATE TABLE IF NOT EXISTS alert_settings (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            alert_type VARCHAR(50) NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT true,
            email_enabled BOOLEAN NOT NULL DEFAULT false,
            email_addresses JSON,
            webhook_url VARCHAR(500),
            webhook_enabled BOOLEAN NOT NULL DEFAULT false,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT uq_user_alert_type UNIQUE (user_id, alert_type)
        )
    """)
    
    # Add last_check column to hosts table if it doesn't exist
    op.execute("""
        DO $$ 
        BEGIN 
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'hosts' AND column_name = 'last_check'
            ) THEN
                ALTER TABLE hosts ADD COLUMN last_check TIMESTAMP WITHOUT TIME ZONE;
            END IF;
        END $$
    """)
    
    # Create indexes for performance
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_alert_settings_user_id ON alert_settings(user_id)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_alert_settings_alert_type ON alert_settings(alert_type)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_alert_settings_enabled ON alert_settings(enabled)
    """)


def downgrade() -> None:
    """Remove alert_settings table and last_check column"""
    
    # Drop indexes
    op.execute("DROP INDEX IF EXISTS idx_alert_settings_enabled")
    op.execute("DROP INDEX IF EXISTS idx_alert_settings_alert_type")
    op.execute("DROP INDEX IF EXISTS idx_alert_settings_user_id")
    
    # Drop alert_settings table
    op.drop_table('alert_settings')
    
    # Remove last_check column from hosts
    op.execute("""
        DO $$ 
        BEGIN 
            IF EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'hosts' AND column_name = 'last_check'
            ) THEN
                ALTER TABLE hosts DROP COLUMN last_check;
            END IF;
        END $$
    """)