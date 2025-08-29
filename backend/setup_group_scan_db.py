#!/usr/bin/env python3
"""
Database setup script for Group Scan Progress Tracking
Applies the database migration for group scan session tables
"""
import os
import sys
import logging
from pathlib import Path

# Add the backend app directory to Python path
backend_dir = Path(__file__).parent / "app"
sys.path.insert(0, str(backend_dir))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from app.config import get_settings

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def apply_group_scan_migration():
    """Apply the group scan tracking database migration"""
    try:
        settings = get_settings()
        
        # Create database connection
        engine = create_engine(settings.database_url)
        
        # Read migration SQL
        migration_file = Path(__file__).parent / "app" / "migrations" / "add_group_scan_tracking.sql"
        
        if not migration_file.exists():
            logger.error(f"Migration file not found: {migration_file}")
            return False
        
        with open(migration_file, 'r') as f:
            migration_sql = f.read()
        
        # Execute migration
        with engine.connect() as conn:
            # Split SQL by statement and execute each one
            statements = [stmt.strip() for stmt in migration_sql.split(';') if stmt.strip()]
            
            for statement in statements:
                # Skip comments and empty statements
                if statement.startswith('--') or not statement:
                    continue
                    
                logger.info(f"Executing: {statement[:50]}...")
                try:
                    conn.execute(text(statement))
                    conn.commit()
                except Exception as e:
                    if "already exists" in str(e).lower():
                        logger.info(f"  Object already exists, skipping...")
                    else:
                        logger.error(f"  Error executing statement: {e}")
                        raise
        
        logger.info("✅ Group scan migration applied successfully!")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to apply migration: {e}")
        return False


def verify_tables():
    """Verify that the new tables were created successfully"""
    try:
        settings = get_settings()
        engine = create_engine(settings.database_url)
        
        with engine.connect() as conn:
            # Check if tables exist
            result = conn.execute(text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name IN ('group_scan_sessions', 'group_scan_host_progress')
                ORDER BY table_name
            """))
            
            tables = [row.table_name for row in result]
            
            if len(tables) == 2:
                logger.info("✅ All tables created successfully:")
                for table in tables:
                    logger.info(f"  - {table}")
                
                # Check table structure
                for table in tables:
                    result = conn.execute(text(f"""
                        SELECT column_name, data_type 
                        FROM information_schema.columns 
                        WHERE table_name = '{table}' 
                        ORDER BY ordinal_position
                    """))
                    
                    columns = list(result)
                    logger.info(f"  {table} has {len(columns)} columns")
                
                return True
            else:
                logger.error(f"❌ Expected 2 tables, found {len(tables)}: {tables}")
                return False
                
    except Exception as e:
        logger.error(f"❌ Failed to verify tables: {e}")
        return False


def main():
    """Main setup function"""
    print("🔧 OpenWatch Group Scan Database Setup")
    print("=" * 50)
    
    # Check if we can connect to database
    try:
        settings = get_settings()
        logger.info(f"Connecting to database: {settings.database_url}")
    except Exception as e:
        logger.error(f"Failed to get database settings: {e}")
        sys.exit(1)
    
    # Apply migration
    if apply_group_scan_migration():
        logger.info("Migration applied successfully")
    else:
        logger.error("Migration failed")
        sys.exit(1)
    
    # Verify tables
    if verify_tables():
        logger.info("Table verification passed")
    else:
        logger.error("Table verification failed")
        sys.exit(1)
    
    print("\n✅ Group Scan Database Setup Complete!")
    print("\nNew API endpoints available:")
    print("  POST /api/host-groups/{group_id}/scan")
    print("  GET  /api/host-groups/scan-sessions/{session_id}/progress") 
    print("  GET  /api/host-groups/scan-sessions/{session_id}/hosts")
    print("  POST /api/host-groups/scan-sessions/{session_id}/cancel")
    print("  GET  /api/host-groups/scan-sessions/active")
    print("  GET  /api/host-groups/scan-sessions/{session_id}/summary")
    print("  GET  /api/host-groups/scan-sessions")


if __name__ == "__main__":
    main()