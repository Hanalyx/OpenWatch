#!/usr/bin/env python3
"""Apply compliance intelligence migration manually"""
import os
import sys
import subprocess
from pathlib import Path

# Add backend to Python path
backend_path = Path(__file__).parent.absolute()
sys.path.insert(0, str(backend_path))

from app.config import get_settings
from app.database import engine

def apply_migration():
    """Apply the compliance intelligence migration"""
    try:
        # Check if we can connect to the database
        with engine.connect() as conn:
            print("✓ Connected to database successfully")
            
        # Apply the migration using alembic
        os.chdir(backend_path)
        result = subprocess.run([
            sys.executable, "-m", "alembic", "upgrade", "head"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✓ Migration applied successfully")
            print(result.stdout)
        else:
            print("✗ Migration failed:")
            print(result.stderr)
            return False
            
        # Verify tables were created
        with engine.connect() as conn:
            tables_to_check = [
                'rule_intelligence',
                'semantic_scan_analysis', 
                'framework_compliance_matrix',
                'compliance_intelligence_metadata'
            ]
            
            for table in tables_to_check:
                result = conn.execute(f"SELECT 1 FROM information_schema.tables WHERE table_name = '{table}'")
                if result.fetchone():
                    print(f"✓ Table '{table}' created successfully")
                else:
                    print(f"✗ Table '{table}' was not created")
                    return False
                    
        return True
        
    except Exception as e:
        print(f"✗ Error applying migration: {e}")
        return False

if __name__ == "__main__":
    success = apply_migration()
    sys.exit(0 if success else 1)