"""
Database Schema Initialization Script

This script ensures ALL required tables are created, including those without
SQLAlchemy ORM models (like unified_credentials).

Critical for first-run experience when users clone the repo and run start-openwatch.sh
"""

import logging
from sqlalchemy import text
from sqlalchemy.orm import Session
from .database import engine, SessionLocal, Base

# Import all models to ensure they're registered with Base.metadata
from .models.system_models import SystemSettings  # noqa: F401

logger = logging.getLogger(__name__)


def create_unified_credentials_table(db: Session) -> bool:
    """
    Create unified_credentials table for centralized SSH authentication.

    This table is critical for SSH functionality but has no SQLAlchemy model,
    so it won't be created by Base.metadata.create_all().

    Returns:
        bool: True if table created or already exists, False on error
    """
    try:
        # Check if table already exists
        result = db.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name = 'unified_credentials'
            )
        """))

        table_exists = result.scalar()

        if table_exists:
            logger.info("✅ unified_credentials table already exists")
            return True

        logger.info("Creating unified_credentials table...")

        # Create the table
        db.execute(text("""
            CREATE TABLE unified_credentials (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name VARCHAR(255) NOT NULL,
                description TEXT,

                -- Scope and targeting
                scope VARCHAR(50) NOT NULL CHECK (scope IN ('system', 'host', 'group')),
                target_id UUID,

                -- Authentication data
                username VARCHAR(255) NOT NULL,
                auth_method VARCHAR(50) NOT NULL CHECK (auth_method IN ('ssh_key', 'password', 'both')),

                -- ENCRYPTED fields (AES-256-GCM) - stored as BYTEA
                encrypted_password BYTEA,
                encrypted_private_key BYTEA,
                encrypted_passphrase BYTEA,

                -- SSH key metadata
                ssh_key_fingerprint VARCHAR(255),
                ssh_key_type VARCHAR(50),
                ssh_key_bits INTEGER,
                ssh_key_comment TEXT,

                -- Management fields
                is_default BOOLEAN NOT NULL DEFAULT false,
                is_active BOOLEAN NOT NULL DEFAULT true,
                created_by UUID NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMP NOT NULL DEFAULT NOW()
            )
        """))

        # Create indexes for performance
        db.execute(text("""
            CREATE INDEX idx_unified_credentials_scope_target
                ON unified_credentials(scope, target_id)
        """))

        db.execute(text("""
            CREATE INDEX idx_unified_credentials_default
                ON unified_credentials(scope, is_default)
        """))

        db.execute(text("""
            CREATE INDEX idx_unified_credentials_active
                ON unified_credentials(is_active)
        """))

        # Create unique index for default credentials per scope/target
        db.execute(text("""
            CREATE UNIQUE INDEX idx_unified_credentials_unique_default
                ON unified_credentials(scope, target_id)
                WHERE is_default = true
        """))

        db.commit()
        logger.info("✅ unified_credentials table created successfully with indexes")
        return True

    except Exception as e:
        logger.error(f"❌ Failed to create unified_credentials table: {e}")
        db.rollback()
        return False


def create_scheduler_config_table(db: Session) -> bool:
    """
    Create scheduler_config table for host monitoring scheduler.

    Returns:
        bool: True if table created or already exists, False on error
    """
    try:
        # Check if table already exists
        result = db.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name = 'scheduler_config'
            )
        """))

        table_exists = result.scalar()

        if table_exists:
            logger.info("✅ scheduler_config table already exists")
            return True

        logger.info("Creating scheduler_config table...")

        # Create the table
        db.execute(text("""
            CREATE TABLE scheduler_config (
                service_name VARCHAR(100) PRIMARY KEY,
                enabled BOOLEAN NOT NULL DEFAULT false,
                interval_minutes INTEGER NOT NULL DEFAULT 5,
                auto_start BOOLEAN NOT NULL DEFAULT false,
                last_run TIMESTAMP,
                created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMP NOT NULL DEFAULT NOW()
            )
        """))

        # Insert default configuration for host monitoring
        db.execute(text("""
            INSERT INTO scheduler_config (service_name, enabled, interval_minutes, auto_start)
            VALUES ('host_monitoring', false, 5, false)
            ON CONFLICT (service_name) DO NOTHING
        """))

        db.commit()
        logger.info("✅ scheduler_config table created successfully")
        return True

    except Exception as e:
        logger.error(f"❌ Failed to create scheduler_config table: {e}")
        db.rollback()
        return False


def verify_critical_tables(db: Session) -> dict:
    """
    Verify all critical tables exist.

    Returns:
        dict: Status of critical tables
    """
    critical_tables = [
        'users',
        'roles',
        'hosts',
        'scans',
        'system_credentials',
        'unified_credentials',  # CRITICAL for SSH
        'scheduler_config',      # CRITICAL for monitoring
        'scap_content',
        'host_groups'
    ]

    status = {}

    for table_name in critical_tables:
        try:
            result = db.execute(text(f"""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_schema = 'public'
                    AND table_name = '{table_name}'
                )
            """))

            exists = result.scalar()
            status[table_name] = '✅' if exists else '❌'

            if not exists:
                logger.warning(f"❌ Critical table missing: {table_name}")
        except Exception as e:
            status[table_name] = f'❌ Error: {e}'
            logger.error(f"Error checking table {table_name}: {e}")

    return status


def initialize_database_schema() -> bool:
    """
    Initialize complete database schema including tables without ORM models.

    This is the main entry point called during application startup.

    Returns:
        bool: True if successful, False if critical errors occurred
    """
    try:
        logger.info("=" * 60)
        logger.info("DATABASE SCHEMA INITIALIZATION")
        logger.info("=" * 60)

        # Create standard ORM tables first
        logger.info("Creating standard SQLAlchemy ORM tables...")
        Base.metadata.create_all(bind=engine)
        logger.info("✅ Standard tables created")

        # Create tables without ORM models
        db = SessionLocal()
        try:
            # Create unified_credentials (CRITICAL for SSH)
            if not create_unified_credentials_table(db):
                logger.error("❌ CRITICAL: Failed to create unified_credentials table")
                logger.error("   SSH credential creation will FAIL without this table!")
                return False

            # Create scheduler_config (CRITICAL for monitoring)
            if not create_scheduler_config_table(db):
                logger.warning("⚠️  Warning: Failed to create scheduler_config table")
                logger.warning("   Host monitoring scheduler may not work correctly")
                # Don't return False - this is not critical enough to abort startup

            # Verify all critical tables
            logger.info("")
            logger.info("Verifying critical tables...")
            table_status = verify_critical_tables(db)

            logger.info("")
            logger.info("Critical Tables Status:")
            for table, status in table_status.items():
                logger.info(f"  {status} {table}")

            # Check if any critical tables are missing
            missing_critical = [
                table for table, status in table_status.items()
                if status.startswith('❌') and table in ['users', 'unified_credentials', 'hosts']
            ]

            if missing_critical:
                logger.error("")
                logger.error("❌ CRITICAL TABLES MISSING:")
                for table in missing_critical:
                    logger.error(f"   - {table}")
                logger.error("")
                logger.error("Application will NOT function correctly!")
                return False

            logger.info("")
            logger.info("=" * 60)
            logger.info("✅ DATABASE SCHEMA INITIALIZATION COMPLETE")
            logger.info("=" * 60)
            return True

        finally:
            db.close()

    except Exception as e:
        logger.error(f"❌ Database schema initialization failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False


if __name__ == "__main__":
    # Allow running this script standalone for testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    success = initialize_database_schema()
    if success:
        print("\n✅ Database schema initialized successfully!")
        exit(0)
    else:
        print("\n❌ Database schema initialization failed!")
        exit(1)
