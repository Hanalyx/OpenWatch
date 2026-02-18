# Secret Rotation Procedures

This guide documents how to rotate each secret used by OpenWatch with minimal or zero downtime.

## Overview

OpenWatch uses these secrets, all provided via environment variables:

| Secret | Variable | Purpose | Rotation Impact |
|--------|----------|---------|-----------------|
| Application secret key | `OPENWATCH_SECRET_KEY` | JWT token signing | Invalidates all active sessions |
| Master encryption key | `OPENWATCH_MASTER_KEY` | AES-256-GCM credential encryption | Requires re-encryption of stored credentials |
| Encryption key | `OPENWATCH_ENCRYPTION_KEY` | Data-at-rest encryption | Requires re-encryption |
| Database password | `POSTGRES_PASSWORD` | PostgreSQL authentication | Brief downtime during rotation |
| Redis password | `REDIS_PASSWORD` | Redis authentication | Brief downtime during rotation |

## Before You Begin

1. Schedule a maintenance window (even for "zero-downtime" rotations, have a window reserved)
2. Create a full backup (see [Backup & Recovery](BACKUP_RECOVERY.md))
3. Document current secret values in a secure vault (not plaintext files)
4. Test the rotation procedure in staging first

## Rotating the Database Password

**Impact**: Brief service interruption (30-60 seconds)

### Procedure

1. Generate a new password:

   ```bash
   NEW_DB_PASS=$(openssl rand -base64 32)
   echo "New password: $NEW_DB_PASS"
   ```

2. Update the password in PostgreSQL:

   ```bash
   docker exec openwatch-db psql -U openwatch -d openwatch \
     -c "ALTER USER openwatch WITH PASSWORD '$NEW_DB_PASS';"
   ```

3. Update the `.env` file with the new password:

   ```bash
   # Update POSTGRES_PASSWORD in .env
   # Update OPENWATCH_DATABASE_URL connection string
   ```

4. Restart services that connect to the database:

   ```bash
   docker restart openwatch-backend openwatch-worker openwatch-celery-beat
   ```

5. Verify connectivity:

   ```bash
   curl -f http://localhost:8000/health
   docker exec openwatch-db psql -U openwatch -d openwatch -c "SELECT 1;"
   ```

## Rotating the Redis Password

**Impact**: Brief service interruption (15-30 seconds). Queued Celery tasks are preserved in Redis.

### Procedure

1. Generate a new password:

   ```bash
   NEW_REDIS_PASS=$(openssl rand -base64 32)
   ```

2. Update the Redis password at runtime:

   ```bash
   docker exec openwatch-redis redis-cli -a "$OLD_REDIS_PASS" \
     CONFIG SET requirepass "$NEW_REDIS_PASS"
   ```

3. Update the `.env` file:

   ```bash
   # Update REDIS_PASSWORD
   # Update OPENWATCH_REDIS_URL connection string
   ```

4. Restart services that connect to Redis:

   ```bash
   docker restart openwatch-backend openwatch-worker openwatch-celery-beat
   ```

5. Verify connectivity:

   ```bash
   docker exec openwatch-redis redis-cli -a "$NEW_REDIS_PASS" ping
   ```

## Rotating the JWT Secret Key (OPENWATCH_SECRET_KEY)

**Impact**: All active sessions are invalidated. Users must re-authenticate.

### Procedure

1. Generate a new key (minimum 32 characters):

   ```bash
   NEW_SECRET=$(openssl rand -base64 48)
   ```

2. Notify users of upcoming session reset (optional, depending on user count).

3. Update the `.env` file with the new `OPENWATCH_SECRET_KEY`.

4. Restart all backend services:

   ```bash
   docker restart openwatch-backend openwatch-worker openwatch-celery-beat
   ```

5. Verify the backend starts successfully:

   ```bash
   curl -f http://localhost:8000/health
   ```

6. Confirm users can log in with the new token signing.

### Reducing Impact

There is no dual-key support for JWT. To minimize disruption:
- Rotate during a low-usage window
- Keep access token lifetime short (default 30 minutes) so most tokens expire naturally
- Communicate the rotation to users in advance

## Rotating the Master Encryption Key (OPENWATCH_MASTER_KEY)

**Impact**: High -- stored SSH credentials must be re-encrypted. Plan carefully.

The master key encrypts SSH credentials stored in PostgreSQL. Changing it without re-encryption makes all stored credentials unreadable.

### Procedure

1. **Export current credentials** (while old key is active):

   ```bash
   docker exec openwatch-backend python -c "
   from app.encryption.encryption_service import EncryptionService
   # Export decrypted credentials for re-encryption
   # This must be done via a migration script specific to your deployment
   "
   ```

2. Generate a new key:

   ```bash
   NEW_MASTER=$(openssl rand -base64 48)
   ```

3. **Re-encrypt all credentials** with the new key. This requires a custom migration script that:
   - Decrypts each credential with the old master key
   - Re-encrypts with the new master key
   - Updates the database record

4. Update the `.env` file with the new `OPENWATCH_MASTER_KEY`.

5. Restart all services:

   ```bash
   docker restart openwatch-backend openwatch-worker openwatch-celery-beat
   ```

6. Verify credential access:

   ```bash
   # Test SSH connectivity to a known host
   curl -f http://localhost:8000/health
   ```

### Warning

If you change `OPENWATCH_MASTER_KEY` without re-encrypting, all stored SSH credentials become permanently unrecoverable. Always back up the database before rotating this key.

## Rotating the Encryption Key (OPENWATCH_ENCRYPTION_KEY)

**Impact**: Same as master key -- encrypted data must be re-encrypted.

Follow the same procedure as the master key rotation. The encryption key is used by the `EncryptionService` for additional data-at-rest encryption.

## Rotation Schedule

Recommended rotation intervals for compliance environments:

| Secret | Interval | Compliance Requirement |
|--------|----------|----------------------|
| Database password | 90 days | NIST SP 800-53 IA-5 |
| Redis password | 90 days | NIST SP 800-53 IA-5 |
| JWT secret key | 180 days | Organization policy |
| Master encryption key | 365 days | NIST SP 800-57 |
| TLS certificates | Before expiry | CA/Browser Forum (398 days max) |

## Post-Rotation Checklist

After rotating any secret:

- [ ] Verify all services are healthy (`curl http://localhost:8000/health`)
- [ ] Verify Celery workers are processing tasks (`docker logs openwatch-worker --tail 20`)
- [ ] Verify at least one scan can execute successfully
- [ ] Update the secret in any external secret management system (Vault, AWS Secrets Manager)
- [ ] Document the rotation date and next scheduled rotation
- [ ] Verify audit log captured the restart events
