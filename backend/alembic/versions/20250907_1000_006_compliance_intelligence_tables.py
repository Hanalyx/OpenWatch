"""Add compliance intelligence tables

Revision ID: 006
Revises: 005
Create Date: 2025-09-07 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add compliance intelligence tables for semantic SCAP processing"""
    
    # Create rule_intelligence table
    op.create_table('rule_intelligence',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scap_rule_id', sa.String(length=500), nullable=False),
        sa.Column('semantic_name', sa.String(length=200), nullable=False),
        sa.Column('title', sa.Text(), nullable=False),
        sa.Column('compliance_intent', sa.Text(), nullable=False),
        sa.Column('business_impact', sa.String(length=20), nullable=False),
        sa.Column('risk_level', sa.String(length=20), nullable=False),
        sa.Column('applicable_frameworks', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('remediation_complexity', sa.String(length=20), nullable=False),
        sa.Column('estimated_fix_time', sa.Integer(), nullable=False),
        sa.Column('remediation_available', sa.Boolean(), nullable=False, default=False),
        sa.Column('dependencies', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('cross_framework_mappings', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('confidence_score', sa.Float(), nullable=False, default=1.0),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('scap_rule_id')
    )
    op.create_index('idx_rule_intelligence_scap_rule', 'rule_intelligence', ['scap_rule_id'])
    op.create_index('idx_rule_intelligence_semantic_name', 'rule_intelligence', ['semantic_name'])
    op.create_index('idx_rule_intelligence_frameworks', 'rule_intelligence', ['applicable_frameworks'])
    op.create_index('idx_rule_intelligence_business_impact', 'rule_intelligence', ['business_impact'])
    
    # Create semantic_scan_analysis table
    op.create_table('semantic_scan_analysis',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('host_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('semantic_rules_count', sa.Integer(), nullable=False),
        sa.Column('frameworks_analyzed', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('remediation_available_count', sa.Integer(), nullable=False),
        sa.Column('processing_metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('analysis_data', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('scan_id')
    )
    op.create_index('idx_semantic_scan_analysis_scan', 'semantic_scan_analysis', ['scan_id'])
    op.create_index('idx_semantic_scan_analysis_host', 'semantic_scan_analysis', ['host_id'])
    
    # Create framework_compliance_matrix table
    op.create_table('framework_compliance_matrix',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('host_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('framework', sa.String(length=50), nullable=False),
        sa.Column('compliance_score', sa.Float(), nullable=False),
        sa.Column('total_rules', sa.Integer(), nullable=False),
        sa.Column('passed_rules', sa.Integer(), nullable=False),
        sa.Column('failed_rules', sa.Integer(), nullable=False),
        sa.Column('previous_score', sa.Float(), nullable=True),
        sa.Column('trend', sa.String(length=20), nullable=True),
        sa.Column('last_scan_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=False),
        sa.Column('predicted_next_score', sa.Float(), nullable=True),
        sa.Column('prediction_confidence', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], ),
        sa.ForeignKeyConstraint(['last_scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('host_id', 'framework')
    )
    op.create_index('idx_framework_compliance_matrix_host', 'framework_compliance_matrix', ['host_id'])
    op.create_index('idx_framework_compliance_matrix_framework', 'framework_compliance_matrix', ['framework'])
    op.create_index('idx_framework_compliance_matrix_updated', 'framework_compliance_matrix', ['last_updated'])
    
    # Create compliance_intelligence_metadata table for tracking processing state
    op.create_table('compliance_intelligence_metadata',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('metadata_key', sa.String(length=100), nullable=False),
        sa.Column('metadata_value', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('metadata_key')
    )
    
    # Insert default metadata
    op.execute("""
        INSERT INTO compliance_intelligence_metadata (id, metadata_key, metadata_value, last_updated)
        VALUES 
        (gen_random_uuid(), 'engine_version', '{"version": "1.0.0", "capabilities": ["semantic_analysis", "cross_framework", "predictive"]}', NOW()),
        (gen_random_uuid(), 'last_rule_sync', '{"timestamp": null, "source": null}', NOW())
    """)
    
    # Create view for compliance intelligence dashboard
    op.execute("""
        CREATE OR REPLACE VIEW compliance_intelligence_summary AS
        SELECT 
            h.id as host_id,
            h.name as host_name,
            COUNT(DISTINCT fcm.framework) as frameworks_tracked,
            AVG(fcm.compliance_score) as average_compliance_score,
            MAX(fcm.last_updated) as last_updated,
            SUM(fcm.failed_rules) as total_failed_rules,
            SUM(CASE WHEN fcm.trend = 'improving' THEN 1 ELSE 0 END) as improving_frameworks,
            SUM(CASE WHEN fcm.trend = 'declining' THEN 1 ELSE 0 END) as declining_frameworks
        FROM hosts h
        LEFT JOIN framework_compliance_matrix fcm ON h.id = fcm.host_id
        GROUP BY h.id, h.name
        ORDER BY average_compliance_score DESC;
    """)


def downgrade() -> None:
    """Remove compliance intelligence tables"""
    # Drop view
    op.execute("DROP VIEW IF EXISTS compliance_intelligence_summary")
    
    # Drop tables
    op.drop_table('compliance_intelligence_metadata')
    op.drop_table('framework_compliance_matrix')
    op.drop_table('semantic_scan_analysis')
    op.drop_table('rule_intelligence')