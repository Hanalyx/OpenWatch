#!/usr/bin/env python3
"""
Minimal Authorization Tables Creation Script
Creates only the essential tables for the authorization framework
"""
import sys
import logging
import os
from sqlalchemy import create_engine, text

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv("OPENWATCH_DATABASE_URL", "postgresql://openwatch:secure_password@localhost:5432/openwatch")

def create_essential_authorization_tables():
    """
    Create only the essential authorization tables
    """
    try:
        engine = create_engine(DATABASE_URL)
        logger.info("Connected to database")
        
        with engine.connect() as conn:
            trans = conn.begin()
            
            try:
                # 1. Host Permissions Table
                logger.info("Creating host_permissions table...")
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS host_permissions (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        group_id INTEGER REFERENCES user_groups(id) ON DELETE CASCADE,
                        role_name VARCHAR(50),
                        host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                        actions JSON NOT NULL DEFAULT '[]'::json,
                        effect VARCHAR(10) NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow', 'deny')),
                        conditions JSON NOT NULL DEFAULT '{}'::json,
                        granted_by INTEGER NOT NULL REFERENCES users(id),
                        granted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                        expires_at TIMESTAMP WITH TIME ZONE,
                        is_active BOOLEAN NOT NULL DEFAULT true,
                        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                        
                        -- Ensure exactly one subject is specified
                        CONSTRAINT host_permissions_subject_check CHECK (
                            (user_id IS NOT NULL)::int + (group_id IS NOT NULL)::int + (role_name IS NOT NULL)::int = 1
                        ),
                        
                        -- Prevent duplicate permissions
                        CONSTRAINT host_permissions_unique UNIQUE NULLS NOT DISTINCT (user_id, group_id, role_name, host_id, effect)
                    )
                """))
                
                # 2. Host Group Permissions Table
                logger.info("Creating host_group_permissions table...")
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS host_group_permissions (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                        group_id INTEGER REFERENCES user_groups(id) ON DELETE CASCADE,
                        role_name VARCHAR(50),
                        host_group_id INTEGER NOT NULL REFERENCES host_groups(id) ON DELETE CASCADE,
                        actions JSON NOT NULL DEFAULT '[]'::json,
                        effect VARCHAR(10) NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow', 'deny')),
                        inherit_to_hosts BOOLEAN NOT NULL DEFAULT true,
                        conditions JSON NOT NULL DEFAULT '{}'::json,
                        granted_by INTEGER NOT NULL REFERENCES users(id),
                        granted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                        expires_at TIMESTAMP WITH TIME ZONE,
                        is_active BOOLEAN NOT NULL DEFAULT true,
                        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                        
                        -- Ensure exactly one subject is specified
                        CONSTRAINT host_group_permissions_subject_check CHECK (
                            (user_id IS NOT NULL)::int + (group_id IS NOT NULL)::int + (role_name IS NOT NULL)::int = 1
                        ),
                        
                        -- Prevent duplicate permissions
                        CONSTRAINT host_group_permissions_unique UNIQUE NULLS NOT DISTINCT (user_id, group_id, role_name, host_group_id, effect)
                    )
                """))
                
                # 3. Authorization Audit Log Table
                logger.info("Creating authorization_audit_log table...")
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS authorization_audit_log (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        event_type VARCHAR(50) NOT NULL,
                        user_id INTEGER NOT NULL REFERENCES users(id),
                        resource_type VARCHAR(50) NOT NULL,
                        resource_id VARCHAR(100),
                        action VARCHAR(50) NOT NULL,
                        decision VARCHAR(20) NOT NULL CHECK (decision IN ('allow', 'deny', 'not_applicable')),
                        policies_evaluated TEXT,
                        context TEXT,
                        ip_address INET,
                        user_agent TEXT,
                        session_id VARCHAR(100),
                        evaluation_time_ms INTEGER NOT NULL DEFAULT 0,
                        reason TEXT NOT NULL,
                        risk_score NUMERIC(3,2) NOT NULL DEFAULT 0.0 CHECK (risk_score >= 0.0 AND risk_score <= 1.0),
                        timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
                    )
                """))
                
                # Create essential indexes
                logger.info("Creating performance indexes...")
                conn.execute(text("CREATE INDEX IF NOT EXISTS idx_host_permissions_host_id ON host_permissions(host_id);"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS idx_host_permissions_user_id ON host_permissions(user_id) WHERE user_id IS NOT NULL;"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS idx_authorization_audit_timestamp ON authorization_audit_log(timestamp DESC);"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS idx_authorization_audit_user_id ON authorization_audit_log(user_id);"))
                
                # Give admin users default permissions
                logger.info("Setting up default admin permissions...")
                conn.execute(text("""
                    INSERT INTO host_permissions (user_id, host_id, actions, effect, granted_by, granted_at)
                    SELECT 
                        u.id as user_id,
                        h.id as host_id,
                        '["read", "write", "execute", "delete", "manage", "scan"]'::json as actions,
                        'allow' as effect,
                        u.id as granted_by,
                        NOW() as granted_at
                    FROM users u
                    CROSS JOIN hosts h
                    WHERE u.role IN ('super_admin', 'security_admin')
                        AND u.is_active = true
                    ON CONFLICT ON CONSTRAINT host_permissions_unique DO NOTHING;
                """))
                
                # Commit transaction
                trans.commit()
                logger.info("Essential authorization tables created successfully!")
                
                # Verify tables
                result = conn.execute(text("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_name IN ('host_permissions', 'host_group_permissions', 'authorization_audit_log')
                    AND table_schema = 'public'
                """))
                
                created_tables = [row[0] for row in result]
                logger.info(f"Created tables: {created_tables}")
                
                if len(created_tables) == 3:
                    logger.info("✅ Authorization framework ready!")
                else:
                    logger.warning(f"⚠️ Only {len(created_tables)} of 3 tables created")
                
            except Exception as e:
                trans.rollback()
                raise e
                
    except Exception as e:
        logger.error(f"Failed to create authorization tables: {e}")
        raise

if __name__ == "__main__":
    print("🔒 Creating Essential Authorization Tables")
    try:
        create_essential_authorization_tables()
        print("🎉 SUCCESS: Authorization tables are ready!")
    except Exception as e:
        print(f"💥 FAILED: {e}")
        sys.exit(1)