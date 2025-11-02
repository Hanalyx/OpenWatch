#!/usr/bin/env python3
"""
Database Migration: Create scheduler_config table
Adds persistence for scheduler state across application restarts
"""
import sys
import os

# Add the app directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import create_engine, text
from config import get_settings
import logging

logger = logging.getLogger(__name__)


def create_scheduler_config_table():
    """Create scheduler_config table for persisting scheduler state"""
    settings = get_settings()
    engine = create_engine(settings.database_url)

    try:
        with engine.connect() as conn:
            # Create scheduler_config table
            conn.execute(
                text(
                    """
                CREATE TABLE IF NOT EXISTS scheduler_config (
                    id SERIAL PRIMARY KEY,
                    service_name VARCHAR(50) UNIQUE NOT NULL,
                    enabled BOOLEAN NOT NULL DEFAULT FALSE,
                    interval_minutes INTEGER NOT NULL DEFAULT 15,
                    last_started TIMESTAMP,
                    last_stopped TIMESTAMP,
                    auto_start BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """
                )
            )

            # Insert default configuration for host monitoring
            conn.execute(
                text(
                    """
                INSERT INTO scheduler_config (
                    service_name, enabled, interval_minutes, auto_start
                ) VALUES (
                    'host_monitoring', TRUE, 15, TRUE
                ) ON CONFLICT (service_name) DO UPDATE SET
                    updated_at = CURRENT_TIMESTAMP;
            """
                )
            )

            conn.commit()
            logger.info("Scheduler config table created successfully")
            print("✓ Scheduler config table created with default settings:")
            print("  - Service: host_monitoring")
            print("  - Enabled: TRUE")
            print("  - Interval: 15 minutes")
            print("  - Auto-start: TRUE")

    except Exception as e:
        logger.error(f"Failed to create scheduler config table: {e}")
        print(f"✗ Migration failed: {e}")
        raise


if __name__ == "__main__":
    create_scheduler_config_table()
