-- Migration: Add Group Scan Session Tracking Tables
-- Description: Create tables for tracking group scan sessions and host progress
-- Date: 2025-08-27

-- Group scan sessions table
CREATE TABLE IF NOT EXISTS group_scan_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id VARCHAR(255) UNIQUE NOT NULL,
    group_id INTEGER NOT NULL REFERENCES host_groups(id) ON DELETE CASCADE,
    group_name VARCHAR(255) NOT NULL,
    total_hosts INTEGER NOT NULL,
    initiated_by INTEGER REFERENCES users(id),
    start_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    estimated_completion TIMESTAMP,
    completed_at TIMESTAMP,
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'cancelled')),
    scan_config TEXT, -- JSON configuration for the group scan
    metadata JSONB, -- Additional metadata
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create index on session_id for fast lookups
CREATE INDEX IF NOT EXISTS idx_group_scan_sessions_session_id ON group_scan_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_group_scan_sessions_status ON group_scan_sessions(status);
CREATE INDEX IF NOT EXISTS idx_group_scan_sessions_initiated_by ON group_scan_sessions(initiated_by);

-- Host scan progress tracking within group scans
CREATE TABLE IF NOT EXISTS group_scan_host_progress (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id VARCHAR(255) NOT NULL REFERENCES group_scan_sessions(session_id) ON DELETE CASCADE,
    host_id UUID NOT NULL, -- References hosts.id but allows for flexibility
    host_name VARCHAR(255) NOT NULL,
    host_ip VARCHAR(45) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'scanning', 'completed', 'failed', 'cancelled')),
    scan_id UUID, -- References scans.id when individual scan is created
    scan_start_time TIMESTAMP,
    scan_end_time TIMESTAMP,
    scan_result_id UUID, -- Link to scan_results when completed
    error_message TEXT,
    progress INTEGER DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(session_id, host_id)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_group_scan_host_progress_session_id ON group_scan_host_progress(session_id);
CREATE INDEX IF NOT EXISTS idx_group_scan_host_progress_host_id ON group_scan_host_progress(host_id);
CREATE INDEX IF NOT EXISTS idx_group_scan_host_progress_status ON group_scan_host_progress(status);
CREATE INDEX IF NOT EXISTS idx_group_scan_host_progress_scan_id ON group_scan_host_progress(scan_id);

-- Create trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply triggers to both tables
DROP TRIGGER IF EXISTS update_group_scan_sessions_updated_at ON group_scan_sessions;
CREATE TRIGGER update_group_scan_sessions_updated_at
    BEFORE UPDATE ON group_scan_sessions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_group_scan_host_progress_updated_at ON group_scan_host_progress;
CREATE TRIGGER update_group_scan_host_progress_updated_at
    BEFORE UPDATE ON group_scan_host_progress
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Add comments for documentation
COMMENT ON TABLE group_scan_sessions IS 'Tracks group scan sessions with overall progress and metadata';
COMMENT ON TABLE group_scan_host_progress IS 'Tracks individual host scan progress within group scan sessions';

COMMENT ON COLUMN group_scan_sessions.session_id IS 'Unique session identifier for external API access';
COMMENT ON COLUMN group_scan_sessions.scan_config IS 'JSON configuration including SCAP content, profile, and options';
COMMENT ON COLUMN group_scan_sessions.metadata IS 'Additional metadata for the scan session';

COMMENT ON COLUMN group_scan_host_progress.scan_id IS 'References the individual scan record when created';
COMMENT ON COLUMN group_scan_host_progress.scan_result_id IS 'References scan results when scan completes';
COMMENT ON COLUMN group_scan_host_progress.progress IS 'Individual host scan progress (0-100)';

-- Grant necessary permissions (adjust as needed for your setup)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON group_scan_sessions TO openwatch_app;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON group_scan_host_progress TO openwatch_app;
-- GRANT USAGE ON SEQUENCE group_scan_sessions_id_seq TO openwatch_app;
-- GRANT USAGE ON SEQUENCE group_scan_host_progress_id_seq TO openwatch_app;
