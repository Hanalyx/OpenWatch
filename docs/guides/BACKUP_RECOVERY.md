# Backup & Recovery Procedures

This guide documents backup, restore, and disaster recovery procedures for OpenWatch.

## Overview

OpenWatch stores data in:

| Component | Storage | Data |
|-----------|---------|------|
| PostgreSQL | `postgres_data` volume | Hosts, scans, findings, users, credentials, compliance data |
| Redis | `redis_data` volume | Celery task queue, session cache |
| Application data | `app_data` volume | Uploaded files, generated reports |
| Application logs | `app_logs` volume | Service logs |
| SSH known hosts | `ssh_known_hosts` volume | Trusted host fingerprints |
| TLS certificates | `security/certs/` bind mount | TLS certificates (read-only) |
| SSH keys | `security/keys/` bind mount | SSH private keys |

**Critical data** requiring regular backup: PostgreSQL, SSH keys, TLS certificates, `.env` file.

**Recoverable data** (can be regenerated): Redis queue, application logs, SSH known hosts.

## Backup Strategy

### Recommended Schedule

| Backup Type | Frequency | Retention | Storage |
|-------------|-----------|-----------|---------|
| Full PostgreSQL dump | Daily | 30 days | Off-site / S3 |
| Incremental WAL archive | Continuous (if configured) | 7 days | Off-site / S3 |
| Configuration files | On change | 10 versions | Version control |
| Volume snapshots | Weekly | 4 weeks | Off-site |
| TLS certificates | On renewal | Previous + current | Secure vault |

## PostgreSQL Backup

### Full Database Dump

Create a compressed SQL dump of the entire database:

```bash
# Create backup directory
mkdir -p /opt/openwatch/backups/postgres

# Full compressed dump
docker exec openwatch-db pg_dump \
  -U openwatch \
  -d openwatch \
  -Fc \
  --verbose \
  -f /tmp/openwatch_backup.dump

# Copy from container to host
docker cp openwatch-db:/tmp/openwatch_backup.dump \
  /opt/openwatch/backups/postgres/openwatch_$(date +%Y%m%d_%H%M%S).dump

# Clean up container temp file
docker exec openwatch-db rm /tmp/openwatch_backup.dump
```

### Plain-Text SQL Dump (for inspection)

```bash
docker exec openwatch-db pg_dump \
  -U openwatch \
  -d openwatch \
  --clean \
  --if-exists \
  > /opt/openwatch/backups/postgres/openwatch_$(date +%Y%m%d).sql
```

### Schema-Only Dump

```bash
docker exec openwatch-db pg_dump \
  -U openwatch \
  -d openwatch \
  --schema-only \
  > /opt/openwatch/backups/postgres/schema_$(date +%Y%m%d).sql
```

### Specific Table Backup

```bash
# Back up hosts and scan results
docker exec openwatch-db pg_dump \
  -U openwatch \
  -d openwatch \
  -Fc \
  -t hosts \
  -t scans \
  -t scan_findings \
  -f /tmp/scan_data_backup.dump

docker cp openwatch-db:/tmp/scan_data_backup.dump \
  /opt/openwatch/backups/postgres/scan_data_$(date +%Y%m%d).dump
```

### Automated Daily Backup Script

Create `/opt/openwatch/scripts/backup.sh`:

```bash
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/opt/openwatch/backups"
POSTGRES_BACKUP_DIR="$BACKUP_DIR/postgres"
RETENTION_DAYS=30
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$BACKUP_DIR/backup.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Create directories
mkdir -p "$POSTGRES_BACKUP_DIR"

log "Starting OpenWatch backup..."

# 1. PostgreSQL dump
log "Backing up PostgreSQL..."
docker exec openwatch-db pg_dump \
    -U openwatch -d openwatch -Fc --verbose \
    -f /tmp/openwatch_backup.dump 2>&1 | tee -a "$LOG_FILE"

docker cp openwatch-db:/tmp/openwatch_backup.dump \
    "$POSTGRES_BACKUP_DIR/openwatch_${TIMESTAMP}.dump"
docker exec openwatch-db rm /tmp/openwatch_backup.dump

DUMP_SIZE=$(du -h "$POSTGRES_BACKUP_DIR/openwatch_${TIMESTAMP}.dump" | cut -f1)
log "PostgreSQL backup complete: $DUMP_SIZE"

# 2. Back up configuration
log "Backing up configuration..."
mkdir -p "$BACKUP_DIR/config"
cp -f "$(dirname "$0")/../.env" "$BACKUP_DIR/config/env_${TIMESTAMP}" 2>/dev/null || true

# 3. Verify backup integrity
log "Verifying backup integrity..."
docker exec openwatch-db pg_restore \
    --list /tmp/openwatch_backup.dump > /dev/null 2>&1 || true
# Verify from host copy
pg_restore --list "$POSTGRES_BACKUP_DIR/openwatch_${TIMESTAMP}.dump" > /dev/null 2>&1 && \
    log "Backup verification: PASSED" || \
    log "Backup verification: WARNING - pg_restore --list failed (may need pg_restore installed on host)"

# 4. Clean up old backups
log "Cleaning up backups older than $RETENTION_DAYS days..."
find "$POSTGRES_BACKUP_DIR" -name "openwatch_*.dump" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR/config" -name "env_*" -mtime +$RETENTION_DAYS -delete

# 5. Report
BACKUP_COUNT=$(find "$POSTGRES_BACKUP_DIR" -name "openwatch_*.dump" | wc -l)
TOTAL_SIZE=$(du -sh "$POSTGRES_BACKUP_DIR" | cut -f1)
log "Backup complete. $BACKUP_COUNT backups on disk, total size: $TOTAL_SIZE"
```

Add to crontab:

```bash
# Daily at 2:00 AM
0 2 * * * /opt/openwatch/scripts/backup.sh >> /opt/openwatch/backups/cron.log 2>&1
```

## Redis Backup

Redis data (Celery task queue) is transient and generally does not require backup. If you need to preserve it:

```bash
# Trigger Redis RDB snapshot
docker exec openwatch-redis redis-cli \
  -a "$REDIS_PASSWORD" BGSAVE

# Wait for save to complete
docker exec openwatch-redis redis-cli \
  -a "$REDIS_PASSWORD" LASTSAVE

# Copy the dump file
docker cp openwatch-redis:/data/dump.rdb \
  /opt/openwatch/backups/redis/dump_$(date +%Y%m%d).rdb
```

## Volume Backup

For full disaster recovery, back up Docker volumes directly:

```bash
# Stop services for consistent backup
./stop-openwatch.sh --simple

# Back up PostgreSQL volume
docker run --rm \
  -v postgres_data:/source:ro \
  -v /opt/openwatch/backups/volumes:/backup \
  alpine tar czf /backup/postgres_data_$(date +%Y%m%d).tar.gz -C /source .

# Back up application data volume
docker run --rm \
  -v app_data:/source:ro \
  -v /opt/openwatch/backups/volumes:/backup \
  alpine tar czf /backup/app_data_$(date +%Y%m%d).tar.gz -C /source .

# Back up SSH known hosts
docker run --rm \
  -v ssh_known_hosts:/source:ro \
  -v /opt/openwatch/backups/volumes:/backup \
  alpine tar czf /backup/ssh_known_hosts_$(date +%Y%m%d).tar.gz -C /source .

# Restart services
./start-openwatch.sh --runtime docker
```

## Configuration Backup

Back up files that are NOT in version control:

```bash
BACKUP_DIR="/opt/openwatch/backups/config/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Environment file (contains secrets)
cp .env "$BACKUP_DIR/env.bak"

# TLS certificates
cp -r security/certs/ "$BACKUP_DIR/certs/"

# SSH keys
cp -r security/keys/ "$BACKUP_DIR/keys/"

# Encrypt the backup (contains secrets)
tar czf - "$BACKUP_DIR" | \
  openssl enc -aes-256-cbc -salt -pbkdf2 \
  -out "/opt/openwatch/backups/config_$(date +%Y%m%d).tar.gz.enc"

# Remove unencrypted copy
rm -rf "$BACKUP_DIR"
```

## Restore Procedures

### Restore PostgreSQL from Dump

```bash
# Stop application services (keep database running)
docker stop openwatch-backend openwatch-worker openwatch-celery-beat

# Drop and recreate the database
docker exec openwatch-db psql -U openwatch -d postgres \
  -c "DROP DATABASE IF EXISTS openwatch;"
docker exec openwatch-db psql -U openwatch -d postgres \
  -c "CREATE DATABASE openwatch OWNER openwatch;"

# Copy backup into container
docker cp /opt/openwatch/backups/postgres/openwatch_YYYYMMDD_HHMMSS.dump \
  openwatch-db:/tmp/restore.dump

# Restore from custom-format dump
docker exec openwatch-db pg_restore \
  -U openwatch \
  -d openwatch \
  --verbose \
  --no-owner \
  --no-privileges \
  /tmp/restore.dump

# Clean up
docker exec openwatch-db rm /tmp/restore.dump

# Restart application services
docker start openwatch-backend openwatch-worker openwatch-celery-beat

# Verify
curl -f http://localhost:8000/health
```

### Restore from Plain-Text SQL

```bash
docker cp /opt/openwatch/backups/postgres/openwatch_YYYYMMDD.sql \
  openwatch-db:/tmp/restore.sql

docker exec openwatch-db psql -U openwatch -d openwatch \
  -f /tmp/restore.sql

docker exec openwatch-db rm /tmp/restore.sql
```

### Restore a Single Table

```bash
# Restore only the hosts table from a full dump
docker cp /opt/openwatch/backups/postgres/openwatch_YYYYMMDD_HHMMSS.dump \
  openwatch-db:/tmp/restore.dump

docker exec openwatch-db pg_restore \
  -U openwatch \
  -d openwatch \
  --verbose \
  --no-owner \
  --data-only \
  -t hosts \
  /tmp/restore.dump
```

### Restore Docker Volumes

```bash
# Stop all services
./stop-openwatch.sh --simple

# Restore PostgreSQL volume
docker run --rm \
  -v postgres_data:/target \
  -v /opt/openwatch/backups/volumes:/backup:ro \
  alpine sh -c "rm -rf /target/* && tar xzf /backup/postgres_data_YYYYMMDD.tar.gz -C /target"

# Restore application data
docker run --rm \
  -v app_data:/target \
  -v /opt/openwatch/backups/volumes:/backup:ro \
  alpine sh -c "rm -rf /target/* && tar xzf /backup/app_data_YYYYMMDD.tar.gz -C /target"

# Restart
./start-openwatch.sh --runtime docker
```

### Restore Configuration

```bash
# Decrypt config backup
openssl enc -aes-256-cbc -d -salt -pbkdf2 \
  -in /opt/openwatch/backups/config_YYYYMMDD.tar.gz.enc | \
  tar xzf -

# Restore .env
cp backup/env.bak .env

# Restore certificates
cp -r backup/certs/ security/certs/
cp -r backup/keys/ security/keys/
```

## Disaster Recovery

### Full Recovery from Scratch

This procedure rebuilds OpenWatch from backups on a new machine.

**Prerequisites**: Docker/Podman installed, OpenWatch repository cloned, backup files available.

1. **Restore configuration**:

   ```bash
   # Restore .env file with all secrets
   cp /path/to/backup/env.bak .env

   # Restore TLS certificates
   cp -r /path/to/backup/certs/ security/certs/
   cp -r /path/to/backup/keys/ security/keys/
   ```

2. **Start infrastructure only**:

   ```bash
   # Start database and Redis first
   docker compose up -d database redis
   docker compose exec database pg_isready -U openwatch
   ```

3. **Restore database**:

   ```bash
   docker cp /path/to/backup/openwatch_latest.dump \
     openwatch-db:/tmp/restore.dump

   docker exec openwatch-db pg_restore \
     -U openwatch -d openwatch \
     --verbose --no-owner --no-privileges \
     /tmp/restore.dump
   ```

4. **Run pending migrations** (if backup is older than current code):

   ```bash
   docker compose run --rm backend \
     alembic -c /app/backend/alembic.ini upgrade head
   ```

5. **Start all services**:

   ```bash
   ./start-openwatch.sh --runtime docker --build
   ```

6. **Verify recovery**:

   ```bash
   # Health check
   curl -f http://localhost:8000/health

   # Check data integrity
   docker exec openwatch-db psql -U openwatch -d openwatch \
     -c "SELECT COUNT(*) FROM hosts;"
   docker exec openwatch-db psql -U openwatch -d openwatch \
     -c "SELECT COUNT(*) FROM scans;"

   # Verify Celery workers
   docker logs openwatch-worker --tail 20
   ```

### Recovery Time Objectives

| Scenario | RTO | RPO | Procedure |
|----------|-----|-----|-----------|
| Container restart | < 2 min | 0 | `docker restart <service>` |
| Database corruption | 15-30 min | Last backup | Restore from pg_dump |
| Full host failure | 30-60 min | Last backup | Full DR from scratch |
| Volume loss | 15-30 min | Last volume backup | Restore volume tarball |

## Backup Verification

Periodically verify that backups can be restored:

```bash
# Create a test database from backup
docker exec openwatch-db psql -U openwatch -d postgres \
  -c "CREATE DATABASE openwatch_test;"

docker cp /opt/openwatch/backups/postgres/latest.dump \
  openwatch-db:/tmp/verify.dump

docker exec openwatch-db pg_restore \
  -U openwatch -d openwatch_test \
  --verbose --no-owner /tmp/verify.dump

# Verify row counts
docker exec openwatch-db psql -U openwatch -d openwatch_test \
  -c "SELECT 'hosts' as tbl, COUNT(*) FROM hosts
      UNION ALL
      SELECT 'scans', COUNT(*) FROM scans
      UNION ALL
      SELECT 'users', COUNT(*) FROM users;"

# Clean up
docker exec openwatch-db psql -U openwatch -d postgres \
  -c "DROP DATABASE openwatch_test;"
docker exec openwatch-db rm /tmp/verify.dump
```

## Backup Checklist

After each backup:

- [ ] Backup file exists and has non-zero size
- [ ] `pg_restore --list` succeeds on the dump file
- [ ] Backup copied to off-site storage
- [ ] Old backups cleaned up per retention policy
- [ ] Backup log reviewed for errors

Quarterly:

- [ ] Full restore test performed on isolated environment
- [ ] Recovery time measured against RTO targets
- [ ] Backup scripts and procedures reviewed
- [ ] Off-site backup accessibility verified
