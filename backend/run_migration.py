#!/usr/bin/env python3
"""
Run credential migration to fix SSH authentication issues
"""
import sys
sys.path.insert(0, '/app/backend')

try:
    from app.database import SessionLocal
    from app.services.credential_migration import CredentialMigrationService
    import logging
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    
    def run_migration():
        """Run the credential migration"""
        db = SessionLocal()
        migration_service = CredentialMigrationService(db)
        
        try:
            print("🔧 Starting credential migration...")
            
            # First, clear any existing unified credentials (they have wrong format)
            print("Clearing existing unified credentials...")
            from sqlalchemy import text
            db.execute(text("DELETE FROM unified_credentials WHERE scope = 'system'"))
            db.commit()
            
            # Run migration
            stats = migration_service.migrate_all_credentials(dry_run=False)
            
            print("✅ Migration completed!")
            print(f"   System credentials migrated: {stats['system_credentials_migrated']}")
            print(f"   Host credentials migrated: {stats['host_credentials_migrated']}")
            print(f"   Migration errors: {stats['migration_errors']}")
            print(f"   Total processed: {stats['total_processed']}")
            
            return True
            
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            db.close()
    
    if __name__ == "__main__":
        success = run_migration()
        sys.exit(0 if success else 1)
        
except ImportError as e:
    print(f"❌ Import failed: {e}")
    print("Run this script from the OpenWatch backend environment")
    sys.exit(1)