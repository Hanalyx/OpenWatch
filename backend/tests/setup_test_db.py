#!/usr/bin/env python3
"""
Initialize test database schema for pytest.

This script creates all required tables in the openwatch_test database.
Run this once before running tests, or tests will fail with missing tables.

Usage:
    python tests/setup_test_db.py
"""
import os
import sys

# Add backend to path so we can import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine  # noqa: E402

from app.database import Base  # noqa: E402
from app.init_database_schema import (  # noqa: E402
    create_scheduler_config_table,
    create_unified_credentials_table,
    verify_critical_tables,
)

# Test database URL (same as conftest.py)
TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL", "postgresql://openwatch:openwatch_secure_db_2025@localhost:5432/openwatch_test"
)


def setup_test_database():
    """Initialize complete test database schema"""
    print("Initializing test database schema...")
    print(f"   Database: {TEST_DATABASE_URL.split('@')[1]}")

    try:
        # Create engine
        engine = create_engine(TEST_DATABASE_URL)

        # Create all ORM tables
        print("\n1️⃣  Creating ORM tables (SQLAlchemy models)...")
        Base.metadata.create_all(bind=engine)
        print("   [OK] ORM tables created")

        # Create non-ORM tables (unified_credentials, scheduler_config)
        print("\n2️⃣  Creating non-ORM tables...")
        from sqlalchemy.orm import sessionmaker

        Session = sessionmaker(bind=engine)
        db = Session()

        try:
            # Create unified_credentials table
            success = create_unified_credentials_table(db)
            if success:
                print("   [OK] unified_credentials table created")
            else:
                print("   ℹ️  unified_credentials table already exists")

            # Create scheduler_config table
            success = create_scheduler_config_table(db)
            if success:
                print("   [OK] scheduler_config table created")
            else:
                print("   ℹ️  scheduler_config table already exists")

            db.commit()

        except Exception as e:
            db.rollback()
            print(f"   [ERROR] Error creating non-ORM tables: {e}")
            raise
        finally:
            db.close()

        # Verify all critical tables exist
        print("\n3️⃣  Verifying critical tables...")
        db = Session()
        try:
            status = verify_critical_tables(db)

            all_exist = all("[OK]" in v for v in status.values())

            print("\n   Table Status:")
            for table, symbol in status.items():
                print(f"   {symbol} {table}")

            if all_exist:
                print("\n[OK] Test database schema initialized successfully!")
                print("\nYou can now run tests:")
                print("   pytest tests/ -v")
                return True
            else:
                print("\n[ERROR] Some critical tables are missing!")
                return False

        finally:
            db.close()

    except Exception as e:
        print(f"\n[ERROR] Failed to initialize test database: {e}")
        print("\nTroubleshooting:")
        print("1. Verify PostgreSQL is running: docker ps | grep postgres")
        print("2. Verify database exists: docker exec openwatch-db psql -U openwatch -l")
        print("3. Check connection string in conftest.py")
        return False


if __name__ == "__main__":
    success = setup_test_database()
    sys.exit(0 if success else 1)
