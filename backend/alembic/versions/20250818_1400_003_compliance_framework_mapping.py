"""Add compliance framework mapping tables

Revision ID: 003
Revises: 002
Create Date: 2025-08-18 14:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add compliance framework mapping and enhanced SCAP processing tables"""
    
    # Create enum for compliance frameworks
    op.execute("""
        CREATE TYPE compliance_framework AS ENUM (
            'DISA-STIG', 'NIST-800-53', 'CIS-Controls', 'CMMC-2.0', 
            'PCI-DSS', 'HIPAA', 'ISO-27001', 'SOC2'
        )
    """)
    
    # Create enum for remediation status
    op.execute("""
        CREATE TYPE remediation_status AS ENUM (
            'pending', 'in_progress', 'completed', 'failed', 'partial'
        )
    """)
    
    # Compliance Framework Mappings table
    op.create_table('compliance_framework_mappings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scap_rule_id', sa.String(length=500), nullable=False),
        sa.Column('framework', postgresql.ENUM('DISA-STIG', 'NIST-800-53', 'CIS-Controls', 'CMMC-2.0', 'PCI-DSS', 'HIPAA', 'ISO-27001', 'SOC2', name='compliance_framework'), nullable=False),
        sa.Column('control_id', sa.String(length=100), nullable=False),
        sa.Column('control_title', sa.Text(), nullable=False),
        sa.Column('control_family', sa.String(length=100), nullable=False),
        sa.Column('implementation_guidance', sa.Text(), nullable=True),
        sa.Column('assessment_objectives', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('related_controls', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('maturity_level', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_framework_mappings_scap_rule', 'compliance_framework_mappings', ['scap_rule_id'])
    op.create_index('idx_framework_mappings_framework', 'compliance_framework_mappings', ['framework'])
    op.create_index('idx_framework_mappings_control', 'compliance_framework_mappings', ['framework', 'control_id'])
    
    # SCAP to AEGIS Mappings table
    op.create_table('scap_aegis_mappings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scap_rule_id', sa.String(length=500), nullable=False),
        sa.Column('aegis_rule_id', sa.String(length=200), nullable=False),
        sa.Column('rule_category', sa.String(length=50), nullable=False),
        sa.Column('remediation_type', sa.String(length=50), nullable=False),
        sa.Column('implementation_commands', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('verification_commands', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('rollback_commands', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('estimated_duration', sa.Integer(), nullable=False),
        sa.Column('requires_reboot', sa.Boolean(), nullable=False),
        sa.Column('dependencies', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('platforms', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('scap_rule_id', 'aegis_rule_id')
    )
    op.create_index('idx_scap_aegis_scap_rule', 'scap_aegis_mappings', ['scap_rule_id'])
    op.create_index('idx_scap_aegis_aegis_rule', 'scap_aegis_mappings', ['aegis_rule_id'])
    op.create_index('idx_scap_aegis_category', 'scap_aegis_mappings', ['rule_category'])
    
    # Remediation Plans table
    op.create_table('remediation_plans',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('plan_id', sa.String(length=100), nullable=False),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('host_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('total_rules', sa.Integer(), nullable=False),
        sa.Column('remediable_rules', sa.Integer(), nullable=False),
        sa.Column('remediated_rules', sa.Integer(), nullable=False),
        sa.Column('estimated_duration', sa.Integer(), nullable=False),
        sa.Column('actual_duration', sa.Integer(), nullable=True),
        sa.Column('requires_reboot', sa.Boolean(), nullable=False),
        sa.Column('status', postgresql.ENUM('pending', 'in_progress', 'completed', 'failed', 'partial', name='remediation_status'), nullable=False),
        sa.Column('execution_order', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('rule_groups', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('aegis_job_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], ),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('plan_id')
    )
    op.create_index('idx_remediation_plans_scan', 'remediation_plans', ['scan_id'])
    op.create_index('idx_remediation_plans_host', 'remediation_plans', ['host_id'])
    op.create_index('idx_remediation_plans_status', 'remediation_plans', ['status'])
    
    # Rule Scan History table (for tracking rule-specific scans)
    op.create_table('rule_scan_history',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_id', sa.String(length=100), nullable=False),
        sa.Column('host_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('rule_id', sa.String(length=500), nullable=False),
        sa.Column('profile_id', sa.String(length=100), nullable=False),
        sa.Column('result', sa.String(length=20), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=True),
        sa.Column('scan_output', sa.Text(), nullable=True),
        sa.Column('compliance_frameworks', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('automated_remediation_available', sa.Boolean(), nullable=False),
        sa.Column('aegis_rule_id', sa.String(length=200), nullable=True),
        sa.Column('scan_timestamp', sa.DateTime(), nullable=False),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_rule_scan_history_scan', 'rule_scan_history', ['scan_id'])
    op.create_index('idx_rule_scan_history_host_rule', 'rule_scan_history', ['host_id', 'rule_id'])
    op.create_index('idx_rule_scan_history_timestamp', 'rule_scan_history', ['scan_timestamp'])
    
    # Compliance Dashboard Metrics table
    op.create_table('compliance_dashboard_metrics',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('host_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('framework', postgresql.ENUM('DISA-STIG', 'NIST-800-53', 'CIS-Controls', 'CMMC-2.0', 'PCI-DSS', 'HIPAA', 'ISO-27001', 'SOC2', name='compliance_framework'), nullable=False),
        sa.Column('metric_date', sa.Date(), nullable=False),
        sa.Column('compliance_score', sa.Float(), nullable=False),
        sa.Column('total_controls', sa.Integer(), nullable=False),
        sa.Column('passed_controls', sa.Integer(), nullable=False),
        sa.Column('failed_controls', sa.Integer(), nullable=False),
        sa.Column('control_families', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('severity_distribution', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('maturity_distribution', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('trend_direction', sa.String(length=20), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_compliance_metrics_host_framework', 'compliance_dashboard_metrics', ['host_id', 'framework'])
    op.create_index('idx_compliance_metrics_date', 'compliance_dashboard_metrics', ['metric_date'])
    
    # Add new columns to existing tables
    
    # Add framework-related columns to scap_content table
    op.add_column('scap_content', sa.Column('os_family', sa.String(length=50), nullable=True))
    op.add_column('scap_content', sa.Column('os_version', sa.String(length=50), nullable=True))
    op.add_column('scap_content', sa.Column('compliance_framework', sa.String(length=50), nullable=True))
    op.add_column('scap_content', sa.Column('source', sa.String(length=50), nullable=True))
    op.add_column('scap_content', sa.Column('status', sa.String(length=20), nullable=True))
    op.add_column('scap_content', sa.Column('update_available', sa.Boolean(), nullable=True))
    op.add_column('scap_content', sa.Column('data_stream_id', sa.String(length=200), nullable=True))
    op.add_column('scap_content', sa.Column('benchmark_id', sa.String(length=200), nullable=True))
    op.add_column('scap_content', sa.Column('benchmark_version', sa.String(length=50), nullable=True))
    op.add_column('scap_content', sa.Column('profile_metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True))
    
    # Add rule-specific scanning columns to scans table
    op.add_column('scans', sa.Column('scan_mode', sa.String(length=20), nullable=True))
    op.add_column('scans', sa.Column('specific_rules', postgresql.ARRAY(sa.String()), nullable=True))
    op.add_column('scans', sa.Column('is_verification_scan', sa.Boolean(), nullable=True))
    op.add_column('scans', sa.Column('parent_scan_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column('scans', sa.Column('remediation_plan_id', postgresql.UUID(as_uuid=True), nullable=True))
    
    # Add framework mapping columns to scan_results table
    op.add_column('scan_results', sa.Column('framework_compliance', postgresql.JSON(astext_type=sa.Text()), nullable=True))
    op.add_column('scan_results', sa.Column('remediable_rules_count', sa.Integer(), nullable=True))
    op.add_column('scan_results', sa.Column('rule_details', postgresql.JSON(astext_type=sa.Text()), nullable=True))
    
    # Create views for compliance reporting
    op.execute("""
        CREATE OR REPLACE VIEW compliance_framework_coverage AS
        SELECT 
            cfm.framework,
            cfm.control_family,
            COUNT(DISTINCT cfm.control_id) as total_controls,
            COUNT(DISTINCT cfm.scap_rule_id) as mapped_rules,
            AVG(CASE WHEN cfm.severity = 'critical' THEN 4
                     WHEN cfm.severity = 'high' THEN 3
                     WHEN cfm.severity = 'medium' THEN 2
                     WHEN cfm.severity = 'low' THEN 1
                     ELSE 0 END) as avg_severity_score
        FROM compliance_framework_mappings cfm
        GROUP BY cfm.framework, cfm.control_family
        ORDER BY cfm.framework, cfm.control_family;
    """)
    
    op.execute("""
        CREATE OR REPLACE VIEW host_compliance_summary AS
        SELECT 
            h.id as host_id,
            h.hostname,
            h.display_name,
            cdm.framework,
            cdm.compliance_score,
            cdm.total_controls,
            cdm.passed_controls,
            cdm.failed_controls,
            cdm.metric_date,
            cdm.trend_direction
        FROM hosts h
        JOIN compliance_dashboard_metrics cdm ON h.id = cdm.host_id
        WHERE cdm.metric_date = (
            SELECT MAX(metric_date) 
            FROM compliance_dashboard_metrics cdm2 
            WHERE cdm2.host_id = h.id AND cdm2.framework = cdm.framework
        )
        ORDER BY h.hostname, cdm.framework;
    """)
    
    # Insert initial compliance framework mappings
    op.execute("""
        INSERT INTO compliance_framework_mappings (
            id, scap_rule_id, framework, control_id, control_title, 
            control_family, implementation_guidance, severity, maturity_level,
            created_at, updated_at
        ) VALUES
        -- SSH Root Login
        (gen_random_uuid(), 'xccdf_mil.disa.stig_rule_SV-230221r792832_rule', 'DISA-STIG', 
         'SV-230221r792832', 'SSH daemon must disable root login', 'Access Control',
         'Configure SSH daemon to prevent root login by setting PermitRootLogin to no',
         'high', 3, NOW(), NOW()),
        (gen_random_uuid(), 'xccdf_mil.disa.stig_rule_SV-230221r792832_rule', 'NIST-800-53', 
         'AC-6(2)', 'Non-Privileged Access for Nonsecurity Functions', 'Access Control',
         'Require users to use non-privileged accounts when accessing nonsecurity functions',
         'high', 3, NOW(), NOW()),
        (gen_random_uuid(), 'xccdf_mil.disa.stig_rule_SV-230221r792832_rule', 'CIS-Controls', 
         '5.4', 'Restrict Administrator Privileges to Dedicated Administrator Accounts', 'Account Management',
         'Ensure administrative privileges are restricted to dedicated admin accounts',
         'high', 3, NOW(), NOW()),
        (gen_random_uuid(), 'xccdf_mil.disa.stig_rule_SV-230221r792832_rule', 'CMMC-2.0', 
         'AC.L2-3.1.5', 'Employ the principle of least privilege', 'Access Control',
         'Employ the principle of least privilege, including for specific security functions',
         'high', 2, NOW(), NOW()),
         
        -- Password Policy
        (gen_random_uuid(), 'xccdf_mil.disa.stig_rule_SV-230365r792936_rule', 'DISA-STIG', 
         'SV-230365r792936', 'System must enforce minimum password length', 'Identification and Authentication',
         'Configure PAM to enforce minimum password length of 15 characters',
         'medium', 2, NOW(), NOW()),
        (gen_random_uuid(), 'xccdf_mil.disa.stig_rule_SV-230365r792936_rule', 'NIST-800-53', 
         'IA-5(1)(a)', 'Password-Based Authentication - Complexity', 'Identification and Authentication',
         'Enforce minimum password complexity requirements including length',
         'medium', 2, NOW(), NOW()),
         
        -- Audit Daemon
        (gen_random_uuid(), 'xccdf_mil.disa.stig_rule_SV-230423r793041_rule', 'DISA-STIG', 
         'SV-230423r793041', 'Audit daemon must be enabled', 'Audit and Accountability',
         'Enable and configure auditd service to capture security-relevant events',
         'high', 2, NOW(), NOW()),
        (gen_random_uuid(), 'xccdf_mil.disa.stig_rule_SV-230423r793041_rule', 'NIST-800-53', 
         'AU-12', 'Audit Record Generation', 'Audit and Accountability',
         'Generate audit records for security-relevant events',
         'high', 2, NOW(), NOW())
    """)
    
    # Insert initial SCAP to AEGIS mappings
    op.execute("""
        INSERT INTO scap_aegis_mappings (
            id, scap_rule_id, aegis_rule_id, rule_category, remediation_type,
            implementation_commands, verification_commands, estimated_duration,
            requires_reboot, platforms, is_active, created_at, updated_at
        ) VALUES
        (gen_random_uuid(), 'xccdf_mil.disa.stig_rule_SV-230221r792832_rule', 'RHEL-09-255045',
         'authentication', 'configuration',
         '["sed -i ''s/^#*PermitRootLogin.*/PermitRootLogin no/'' /etc/ssh/sshd_config", "systemctl restart sshd"]',
         '["grep -E ''^PermitRootLogin\\\\s+no'' /etc/ssh/sshd_config"]',
         30, false, '{"rhel8", "rhel9", "ubuntu20", "ubuntu22"}', true, NOW(), NOW()),
         
        (gen_random_uuid(), 'xccdf_mil.disa.stig_rule_SV-230365r792936_rule', 'RHEL-09-611045',
         'authentication', 'configuration',
         '["sed -i ''s/^#*\\\\s*minlen.*/minlen = 15/'' /etc/security/pwquality.conf"]',
         '["grep -E ''^minlen\\\\s*=\\\\s*(1[5-9]|[2-9][0-9])'' /etc/security/pwquality.conf"]',
         20, false, '{"rhel8", "rhel9"}', true, NOW(), NOW()),
         
        (gen_random_uuid(), 'xccdf_mil.disa.stig_rule_SV-230423r793041_rule', 'RHEL-09-653015',
         'audit', 'service',
         '["systemctl enable auditd", "systemctl start auditd", "augenrules --load"]',
         '["systemctl is-enabled auditd", "systemctl is-active auditd"]',
         45, false, '{"rhel8", "rhel9"}', true, NOW(), NOW())
    """)


def downgrade() -> None:
    """Remove compliance framework mapping tables"""
    
    # Drop views
    op.execute('DROP VIEW IF EXISTS host_compliance_summary')
    op.execute('DROP VIEW IF EXISTS compliance_framework_coverage')
    
    # Drop columns from existing tables
    op.drop_column('scan_results', 'rule_details')
    op.drop_column('scan_results', 'remediable_rules_count')
    op.drop_column('scan_results', 'framework_compliance')
    
    op.drop_column('scans', 'remediation_plan_id')
    op.drop_column('scans', 'parent_scan_id')
    op.drop_column('scans', 'is_verification_scan')
    op.drop_column('scans', 'specific_rules')
    op.drop_column('scans', 'scan_mode')
    
    op.drop_column('scap_content', 'profile_metadata')
    op.drop_column('scap_content', 'benchmark_version')
    op.drop_column('scap_content', 'benchmark_id')
    op.drop_column('scap_content', 'data_stream_id')
    op.drop_column('scap_content', 'update_available')
    op.drop_column('scap_content', 'status')
    op.drop_column('scap_content', 'source')
    op.drop_column('scap_content', 'compliance_framework')
    op.drop_column('scap_content', 'os_version')
    op.drop_column('scap_content', 'os_family')
    
    # Drop tables
    op.drop_index('idx_compliance_metrics_date', table_name='compliance_dashboard_metrics')
    op.drop_index('idx_compliance_metrics_host_framework', table_name='compliance_dashboard_metrics')
    op.drop_table('compliance_dashboard_metrics')
    
    op.drop_index('idx_rule_scan_history_timestamp', table_name='rule_scan_history')
    op.drop_index('idx_rule_scan_history_host_rule', table_name='rule_scan_history')
    op.drop_index('idx_rule_scan_history_scan', table_name='rule_scan_history')
    op.drop_table('rule_scan_history')
    
    op.drop_index('idx_remediation_plans_status', table_name='remediation_plans')
    op.drop_index('idx_remediation_plans_host', table_name='remediation_plans')
    op.drop_index('idx_remediation_plans_scan', table_name='remediation_plans')
    op.drop_table('remediation_plans')
    
    op.drop_index('idx_scap_aegis_category', table_name='scap_aegis_mappings')
    op.drop_index('idx_scap_aegis_aegis_rule', table_name='scap_aegis_mappings')
    op.drop_index('idx_scap_aegis_scap_rule', table_name='scap_aegis_mappings')
    op.drop_table('scap_aegis_mappings')
    
    op.drop_index('idx_framework_mappings_control', table_name='compliance_framework_mappings')
    op.drop_index('idx_framework_mappings_framework', table_name='compliance_framework_mappings')
    op.drop_index('idx_framework_mappings_scap_rule', table_name='compliance_framework_mappings')
    op.drop_table('compliance_framework_mappings')
    
    # Drop enum types
    op.execute('DROP TYPE IF EXISTS remediation_status')
    op.execute('DROP TYPE IF EXISTS compliance_framework')