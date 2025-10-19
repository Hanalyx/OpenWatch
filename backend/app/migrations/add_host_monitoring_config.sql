-- Migration: Add host_monitoring_config table for adaptive scheduler configuration
-- Date: 2025-10-18
-- Purpose: Enable configurable adaptive Celery-based host monitoring scheduler

-- Create host_monitoring_config table
CREATE TABLE IF NOT EXISTS host_monitoring_config (
    id SERIAL PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT true,

    -- Check intervals (minutes)
    interval_unknown INTEGER NOT NULL DEFAULT 0,      -- Immediate checks for new hosts
    interval_online INTEGER NOT NULL DEFAULT 15,      -- Healthy hosts (5-60 min range)
    interval_degraded INTEGER NOT NULL DEFAULT 5,     -- 1 failure (1-15 min range)
    interval_critical INTEGER NOT NULL DEFAULT 2,     -- 2 failures (1-10 min range)
    interval_down INTEGER NOT NULL DEFAULT 30,        -- 3+ failures (10-120 min range)
    interval_maintenance INTEGER NOT NULL DEFAULT 60, -- Maintenance mode (15-1440 min range)

    -- Maintenance mode behavior
    maintenance_mode VARCHAR(20) NOT NULL DEFAULT 'reduced',  -- 'skip', 'passive', 'reduced'

    -- Advanced settings
    max_concurrent_checks INTEGER NOT NULL DEFAULT 10,
    check_timeout_seconds INTEGER NOT NULL DEFAULT 30,
    retry_on_failure BOOLEAN NOT NULL DEFAULT true,

    -- Queue priorities (1-10, higher = more urgent)
    priority_unknown INTEGER NOT NULL DEFAULT 10,
    priority_critical INTEGER NOT NULL DEFAULT 8,
    priority_degraded INTEGER NOT NULL DEFAULT 6,
    priority_online INTEGER NOT NULL DEFAULT 4,
    priority_down INTEGER NOT NULL DEFAULT 2,
    priority_maintenance INTEGER NOT NULL DEFAULT 1,

    -- Metadata
    updated_by INTEGER REFERENCES users(id),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Ensure only one configuration row
    CONSTRAINT single_config_row CHECK (id = 1)
);

-- Insert default configuration
INSERT INTO host_monitoring_config (
    id,
    enabled,
    interval_unknown,
    interval_online,
    interval_degraded,
    interval_critical,
    interval_down,
    interval_maintenance,
    maintenance_mode,
    max_concurrent_checks,
    check_timeout_seconds,
    retry_on_failure,
    priority_unknown,
    priority_critical,
    priority_degraded,
    priority_online,
    priority_down,
    priority_maintenance
) VALUES (
    1,
    true,
    0,    -- unknown: immediate
    15,   -- online: 15 min
    5,    -- degraded: 5 min
    2,    -- critical: 2 min
    30,   -- down: 30 min
    60,   -- maintenance: 60 min
    'reduced',
    10,   -- max concurrent checks
    30,   -- timeout seconds
    true, -- retry on failure
    10,   -- priority unknown
    8,    -- priority critical
    6,    -- priority degraded
    4,    -- priority online
    2,    -- priority down
    1     -- priority maintenance
)
ON CONFLICT (id) DO NOTHING;

-- Add index for fast config lookups
CREATE INDEX IF NOT EXISTS idx_host_monitoring_config_enabled ON host_monitoring_config(enabled);

-- Update hosts table to ensure next_check_time is properly initialized
-- Set next_check_time to NOW for hosts that don't have it set
UPDATE hosts
SET next_check_time = CURRENT_TIMESTAMP
WHERE next_check_time IS NULL AND is_active = true;

-- Create index on next_check_time for efficient scheduler queries
CREATE INDEX IF NOT EXISTS idx_hosts_next_check_priority
ON hosts(next_check_time, check_priority)
WHERE is_active = true;

-- Add comment
COMMENT ON TABLE host_monitoring_config IS 'Configuration for adaptive Celery-based host monitoring scheduler. Uses state-based intervals to optimize resource usage and enable rapid issue detection.';
