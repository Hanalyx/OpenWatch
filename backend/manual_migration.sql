-- Manual migration for unified_credentials table
-- This creates the centralized authentication infrastructure

-- Create unified_credentials table
CREATE TABLE IF NOT EXISTS unified_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    scope VARCHAR(50) NOT NULL,
    target_id UUID,
    username VARCHAR(255) NOT NULL,
    auth_method VARCHAR(50) NOT NULL,
    
    -- Encrypted credential fields (all use AES-256-GCM)
    encrypted_password BYTEA,
    encrypted_private_key BYTEA,
    encrypted_passphrase BYTEA,
    
    -- SSH key metadata
    ssh_key_fingerprint VARCHAR(255),
    ssh_key_type VARCHAR(50),
    ssh_key_bits INTEGER,
    ssh_key_comment TEXT,
    
    -- Management fields
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CHECK (scope IN ('system', 'host', 'group')),
    CHECK (auth_method IN ('ssh_key', 'password', 'both'))
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_unified_credentials_scope_target 
ON unified_credentials (scope, target_id);

CREATE INDEX IF NOT EXISTS idx_unified_credentials_default 
ON unified_credentials (scope, is_default);

CREATE INDEX IF NOT EXISTS idx_unified_credentials_active 
ON unified_credentials (is_active);

-- Unique constraint for default credentials per scope/target
CREATE UNIQUE INDEX IF NOT EXISTS idx_unified_credentials_unique_default
ON unified_credentials (scope, target_id)
WHERE is_default = true;

-- Insert a comment to track migration
INSERT INTO unified_credentials 
(id, name, description, scope, username, auth_method, is_default, is_active, created_by)
VALUES 
('00000000-0000-0000-0000-000000000001', 
 'Migration Marker', 
 'Created during centralized auth migration', 
 'system', 
 'migration-user', 
 'ssh_key', 
 false, 
 false, 
 '00000000-0000-0000-0000-000000000000')
ON CONFLICT (id) DO NOTHING;