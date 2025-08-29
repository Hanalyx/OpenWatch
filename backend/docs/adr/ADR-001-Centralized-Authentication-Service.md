# ADR-001: Centralized Authentication Service Architecture

**Status**: Proposed  
**Date**: 2025-01-22  
**Architect**: Alex Morgan (@alexmorgan9000)

## Context

OpenWatch currently has two separate authentication systems causing SSH authentication failures:

1. **System Credentials**: Uses AES-256-GCM encryption, stored in `system_credentials` table
2. **Host Credentials**: Uses base64 encoding only, stored in `hosts.encrypted_credentials`

**Current Issues:**
- Inconsistent field naming (`ssh_key` vs `private_key`) 
- Different encryption methods (AES vs base64)
- Separate validation logic paths
- No unified credential resolution
- Host SSH authentication fails while system defaults work

## Decision

Implement a **Centralized Authentication Service** that provides:

1. **Single API** for all credential operations
2. **Unified encryption** using AES-256-GCM for all credentials
3. **Consistent data schema** with standardized field names
4. **Central validation** that all paths must use
5. **Abstracted credential resolution** that handles scope inheritance

## Architecture Design

### Core Service Structure

```
┌─────────────────────────────────────────────────┐
│             CentralizedAuthService              │
├─────────────────────────────────────────────────┤
│  + store_credential(data, scope, target_id)     │
│  + get_credential(target_id, use_default)       │
│  + validate_credential(credential)              │
│  + list_credentials(scope, user_id)             │
│  + delete_credential(credential_id)             │
│  + migrate_legacy_credential(old_format)        │
└─────────────────┬───────────────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
    ▼             ▼             ▼
┌─────────┐ ┌─────────┐ ┌─────────────┐
│Validator│ │Encryptor│ │Resolver     │
│- SSH    │ │- AES-GCM│ │- Inheritance│
│- Format │ │- Keys   │ │- Fallbacks  │
│- Network│ │- Audit  │ │- Scoping    │
└─────────┘ └─────────┘ └─────────────┘
```

### Unified Data Schema

```sql
-- New unified credentials table
CREATE TABLE unified_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    scope VARCHAR(50) NOT NULL, -- 'system', 'host', 'group'
    target_id UUID, -- NULL for system, host_id for host, group_id for group
    username VARCHAR(255) NOT NULL,
    auth_method VARCHAR(50) NOT NULL, -- 'ssh_key', 'password', 'both'
    
    -- Encrypted fields (all use AES-256-GCM)
    encrypted_password BYTEA,
    encrypted_private_key BYTEA,
    encrypted_passphrase BYTEA,
    
    -- SSH key metadata
    ssh_key_fingerprint VARCHAR(255),
    ssh_key_type VARCHAR(50),
    ssh_key_bits INTEGER,
    ssh_key_comment TEXT,
    
    -- Management fields
    is_default BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_by UUID NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    -- Constraints
    UNIQUE(scope, target_id, is_default) WHERE is_default = TRUE,
    CHECK (scope IN ('system', 'host', 'group')),
    CHECK (auth_method IN ('ssh_key', 'password', 'both'))
);
```

### API Contract

```yaml
# OpenAPI specification for centralized auth
paths:
  /api/v2/credentials:
    post:
      summary: Store credential
      requestBody:
        schema:
          type: object
          required: [scope, username, auth_method]
          properties:
            scope: {enum: [system, host, group]}
            target_id: {type: string, format: uuid}
            username: {type: string}
            auth_method: {enum: [ssh_key, password, both]}
            private_key: {type: string}
            password: {type: string}
            
  /api/v2/credentials/resolve/{target_id}:
    get:
      summary: Resolve effective credentials
      parameters:
        - name: target_id
          schema: {type: string, format: uuid}
        - name: use_default
          schema: {type: boolean}
      responses:
        200:
          schema:
            type: object
            properties:
              username: {type: string}
              auth_method: {type: string}
              private_key: {type: string}
              password: {type: string}
              source: {enum: [host, system, inherited]}
```

### Credential Resolution Logic

```python
def resolve_credential(self, target_id: str = None, use_default: bool = False):
    """
    Unified credential resolution with inheritance:
    1. If use_default=True -> system default
    2. If target_id and has credential -> target-specific  
    3. If target_id but no credential -> system default fallback
    4. Validate and normalize before return
    """
```

### Migration Strategy

**Phase 1: Deploy Service (Zero Downtime)**
- Deploy `CentralizedAuthService` alongside existing system
- Both old and new APIs work simultaneously
- No changes to existing functionality

**Phase 2: Migrate System Credentials**
- Copy `system_credentials` to `unified_credentials`
- Already AES encrypted, just schema transformation
- Update system settings UI to use new API

**Phase 3: Re-encrypt Host Credentials**
- Read base64 host credentials from `hosts.encrypted_credentials`
- Re-encrypt with AES-256-GCM
- Store in `unified_credentials` with `scope='host'`
- Preserve existing host functionality

**Phase 4: Update Consumers**
- Scan tasks use `credential_service.resolve_credential()`
- Host monitoring uses unified service
- All components get consistent behavior

**Phase 5: Cleanup**
- Remove old credential fields
- Drop legacy helper functions
- Update documentation

### Security Considerations

**Encryption Standards:**
- AES-256-GCM for all stored credentials
- PBKDF2 key derivation with high iteration count
- Separate encryption keys per credential type
- Audit logging for all credential operations

**Access Control:**
- RBAC integration for credential management
- User isolation for credential visibility
- Admin-only access for system defaults
- Encrypted credential never logged

### Benefits

1. **Consistency**: Same encryption, validation, and field names everywhere
2. **Maintainability**: Single codebase for all credential operations
3. **Security**: Unified encryption eliminates weak base64 encoding
4. **Debugging**: One service to troubleshoot authentication issues
5. **Extensibility**: Easy to add new credential types or scopes

### Risks & Mitigations

**Risk: Migration Complexity**
- *Mitigation*: Phased rollout with backward compatibility

**Risk: Performance Impact**
- *Mitigation*: Credential caching and async resolution

**Risk: Key Management**
- *Mitigation*: Existing encryption service handles key lifecycle

## Implementation Plan

1. **Phase 1**: Core service implementation (Priya + Daniel)
2. **Phase 2**: Security review and hardening (Emily)
3. **Phase 3**: Frontend integration (Sofia)
4. **Phase 4**: Migration scripts and testing (Rachel)
5. **Phase 5**: Documentation and rollout (Maya)

## Acceptance Criteria

- [ ] Single API handles all credential operations
- [ ] Host SSH authentication works identically to system defaults  
- [ ] Zero regression in existing functionality
- [ ] All credentials use AES-256-GCM encryption
- [ ] Migration completes with zero downtime
- [ ] Performance impact < 50ms per credential operation

---

**Next Steps**: Hand off to backend team for service implementation.