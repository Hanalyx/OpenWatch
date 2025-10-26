-- Migration: Add host_monitoring_history table
-- Date: 2025-10-25
-- Purpose: Track host monitoring check history for trend analysis and debugging

-- Create host_monitoring_history table
CREATE TABLE IF NOT EXISTS host_monitoring_history (
    id SERIAL PRIMARY KEY,
    host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    check_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    monitoring_state VARCHAR(20) NOT NULL,
    previous_state VARCHAR(20),
    response_time_ms INTEGER,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    error_type VARCHAR(50),

    -- Metadata
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_host_monitoring_history_host_id
ON host_monitoring_history(host_id);

CREATE INDEX IF NOT EXISTS idx_host_monitoring_history_check_time
ON host_monitoring_history(check_time DESC);

CREATE INDEX IF NOT EXISTS idx_host_monitoring_history_state
ON host_monitoring_history(monitoring_state);

CREATE INDEX IF NOT EXISTS idx_host_monitoring_history_host_time
ON host_monitoring_history(host_id, check_time DESC);

-- Add comment
COMMENT ON TABLE host_monitoring_history IS 'Historical log of all host monitoring checks for trend analysis, debugging, and compliance reporting.';
