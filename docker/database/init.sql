-- OpenWatch Database Initialization
-- This script runs after the database is created by POSTGRES_DB

-- Basic initialization message
SELECT 'Initializing OpenWatch database...' AS status;

-- Create audit logging
CREATE SCHEMA IF NOT EXISTS audit;

-- Create audit log table
CREATE TABLE IF NOT EXISTS audit.logs (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID,
    username VARCHAR(255),
    action VARCHAR(255) NOT NULL,
    resource_type VARCHAR(255),
    resource_id UUID,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index for audit logs
CREATE INDEX idx_audit_logs_created_at ON audit.logs(created_at);
CREATE INDEX idx_audit_logs_user_id ON audit.logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit.logs(action);

-- Create function for automatic audit logging
CREATE OR REPLACE FUNCTION audit.log_action()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO audit.logs (
        user_id,
        username,
        action,
        resource_type,
        resource_id,
        details,
        created_at
    ) VALUES (
        current_setting('app.current_user_id', true)::UUID,
        current_setting('app.current_username', true),
        TG_OP,
        TG_TABLE_NAME,
        NEW.id,
        row_to_json(NEW),
        CURRENT_TIMESTAMP
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Grant necessary permissions
GRANT USAGE ON SCHEMA audit TO openwatch;
GRANT SELECT, INSERT ON audit.logs TO openwatch;
GRANT USAGE ON SEQUENCE audit.logs_id_seq TO openwatch;

-- Create extension for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create extension for encryption
CREATE EXTENSION IF NOT EXISTS pgcrypto;
