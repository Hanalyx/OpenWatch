"""Add MFA support to user model

Revision ID: 20250817_1500_002
Revises: 20250817_1400_001
Create Date: 2025-08-17 15:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '20250817_1500_002'
down_revision = '20250817_1400_001'
branch_labels = None
depends_on = None


def upgrade():
    """Add MFA support columns to users table"""
    
    # Add MFA-related columns to users table
    op.add_column('users', sa.Column('mfa_enabled', sa.Boolean(), nullable=False, server_default='false'))
    op.add_column('users', sa.Column('mfa_secret', sa.Text(), nullable=True, comment='Encrypted TOTP secret'))
    op.add_column('users', sa.Column('backup_codes', sa.JSON(), nullable=True, comment='Hashed backup codes'))
    op.add_column('users', sa.Column('mfa_enrolled_at', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('last_mfa_use', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('mfa_recovery_codes_generated_at', sa.DateTime(), nullable=True))
    
    # Create index for efficient MFA lookups
    op.create_index('idx_users_mfa_enabled', 'users', ['mfa_enabled'])
    
    # Create MFA audit log table for security monitoring
    op.create_table('mfa_audit_log',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('action', sa.String(50), nullable=False, comment='MFA action: enroll, validate, disable, etc.'),
        sa.Column('method', sa.String(20), nullable=True, comment='MFA method used: totp, backup_code'),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True, comment='Additional audit details'),
        sa.Column('timestamp', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Index('idx_mfa_audit_user_timestamp', 'user_id', 'timestamp'),
        sa.Index('idx_mfa_audit_action', 'action'),
        sa.Index('idx_mfa_audit_timestamp', 'timestamp')
    )
    
    # Create table for TOTP replay protection
    op.create_table('mfa_used_codes',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('code_hash', sa.String(64), nullable=False, comment='SHA-256 hash of used code + timestamp'),
        sa.Column('used_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Index('idx_mfa_used_codes_user', 'user_id'),
        sa.Index('idx_mfa_used_codes_hash', 'code_hash'),
        sa.Index('idx_mfa_used_codes_timestamp', 'used_at'),
        # Ensure no duplicate code usage
        sa.UniqueConstraint('user_id', 'code_hash', name='uq_user_code_hash')
    )


def downgrade():
    """Remove MFA support"""
    
    # Drop MFA tables
    op.drop_table('mfa_used_codes')
    op.drop_table('mfa_audit_log')
    
    # Drop MFA indexes
    op.drop_index('idx_users_mfa_enabled', table_name='users')
    
    # Remove MFA columns from users table
    op.drop_column('users', 'mfa_recovery_codes_generated_at')
    op.drop_column('users', 'last_mfa_use')
    op.drop_column('users', 'mfa_enrolled_at')
    op.drop_column('users', 'backup_codes')
    op.drop_column('users', 'mfa_secret')
    op.drop_column('users', 'mfa_enabled')