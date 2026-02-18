# Upgrade Procedures

This guide documents how to upgrade OpenWatch to a new version with minimal downtime.

## Before You Upgrade

### Pre-Upgrade Checklist

- [ ] Read the release notes for the target version
- [ ] Verify current system is healthy (`curl http://localhost:8000/health`)
- [ ] Create a full database backup (see [Backup & Recovery](BACKUP_RECOVERY.md))
- [ ] Back up `.env` and certificate files
- [ ] Note the current version (`cat VERSION`)
- [ ] Note the current Alembic migration head:
  ```bash
  docker exec openwatch-backend alembic -c /app/backend/alembic.ini current
  ```
- [ ] Verify sufficient disk space for new images (2-3 GB)
- [ ] Schedule a maintenance window
- [ ] Notify users of planned downtime

### Version Compatibility

OpenWatch follows semantic versioning:

| Change Type | Version Bump | Migration Required | Downtime Expected |
|-------------|-------------|-------------------|-------------------|
| Patch (0.1.0 -> 0.1.1) | Patch | Possible | < 1 minute |
| Minor (0.1.x -> 0.2.0) | Minor | Likely | 2-5 minutes |
| Major (0.x -> 1.0) | Major | Yes | 5-15 minutes |

## Standard Upgrade Procedure

### Step 1: Pull the Latest Code

```bash
cd /opt/openwatch

# Save current version for rollback reference
cat VERSION > /tmp/openwatch_prev_version

# Pull the new version
git fetch origin
git checkout v<NEW_VERSION>
# Or for latest main:
git pull origin main
```

### Step 2: Review Changes

```bash
# Check for new environment variables
diff .env .env.example

# Check for new migrations
ls backend/alembic/versions/ | tail -10

# Check for breaking changes in config
git diff v<OLD_VERSION>..v<NEW_VERSION> -- backend/app/config.py
```

### Step 3: Update Configuration

```bash
# Add any new required environment variables to .env
# Compare with .env.example for new variables and defaults
```

### Step 4: Create Backup

```bash
# Full database backup
docker exec openwatch-db pg_dump \
  -U openwatch -d openwatch -Fc \
  -f /tmp/pre_upgrade_backup.dump

docker cp openwatch-db:/tmp/pre_upgrade_backup.dump \
  /opt/openwatch/backups/postgres/pre_upgrade_$(date +%Y%m%d_%H%M%S).dump
```

### Step 5: Stop Application Services

```bash
# Stop application containers (keep database and Redis running)
docker stop openwatch-frontend openwatch-backend openwatch-worker openwatch-celery-beat
```

### Step 6: Run Database Migrations

```bash
# Run migrations against the running database
docker compose run --rm backend \
  alembic -c /app/backend/alembic.ini upgrade head

# Verify migration
docker compose run --rm backend \
  alembic -c /app/backend/alembic.ini current
```

If migrations fail, see [Rollback Procedures](#rollback-procedures).

### Step 7: Rebuild and Start Services

```bash
# Rebuild images with new code
./start-openwatch.sh --runtime docker --build
```

For production with the overlay:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

### Step 8: Verify the Upgrade

```bash
# Health check
curl -f http://localhost:8000/health

# Check version
cat VERSION

# Verify all services are running
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep openwatch

# Check for errors in logs
docker logs openwatch-backend --tail 50 --since 5m
docker logs openwatch-worker --tail 50 --since 5m

# Verify database connectivity
docker exec openwatch-db psql -U openwatch -d openwatch -c "SELECT 1;"

# Verify Celery workers are processing
docker logs openwatch-worker --tail 20 | grep -i "ready\|connected"

# Run a quick scan to verify end-to-end functionality
curl -f http://localhost:8000/api/scans/aegis/health
```

## Production Upgrade (with Overlay)

For production deployments using `docker-compose.prod.yml`:

```bash
# 1. Backup
docker exec openwatch-db pg_dump -U openwatch -d openwatch -Fc \
  -f /tmp/pre_upgrade.dump
docker cp openwatch-db:/tmp/pre_upgrade.dump /opt/openwatch/backups/postgres/

# 2. Pull new code
git fetch origin && git checkout v<NEW_VERSION>

# 3. Stop services (keep DB + Redis)
docker stop openwatch-frontend openwatch-backend openwatch-worker openwatch-celery-beat

# 4. Migrate
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  run --rm backend alembic -c /app/backend/alembic.ini upgrade head

# 5. Rebuild and start
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

# 6. Verify
curl -f http://localhost:8000/health
docker ps --format "table {{.Names}}\t{{.Status}}" | grep openwatch
```

## Rollback Procedures

### Quick Rollback (Code Only)

If the upgrade fails but migrations have NOT run:

```bash
# Revert to previous version
git checkout v<OLD_VERSION>

# Rebuild with old code
./start-openwatch.sh --runtime docker --build

# Verify
curl -f http://localhost:8000/health
```

### Full Rollback (Code + Database)

If migrations ran and need to be reverted:

```bash
# 1. Stop application services
docker stop openwatch-frontend openwatch-backend openwatch-worker openwatch-celery-beat

# 2. Downgrade migrations
# Find the migration revision of the old version
docker compose run --rm backend \
  alembic -c /app/backend/alembic.ini history | head -20

# Downgrade to specific revision
docker compose run --rm backend \
  alembic -c /app/backend/alembic.ini downgrade <OLD_REVISION>

# 3. Revert code
git checkout v<OLD_VERSION>

# 4. Rebuild and start
./start-openwatch.sh --runtime docker --build
```

### Emergency Rollback (Database Restore)

If migration downgrade fails or data is corrupted:

```bash
# 1. Stop all services
./stop-openwatch.sh --simple

# 2. Restore database from pre-upgrade backup
docker start openwatch-db
sleep 5

docker exec openwatch-db psql -U openwatch -d postgres \
  -c "DROP DATABASE IF EXISTS openwatch;"
docker exec openwatch-db psql -U openwatch -d postgres \
  -c "CREATE DATABASE openwatch OWNER openwatch;"

docker cp /opt/openwatch/backups/postgres/pre_upgrade_YYYYMMDD.dump \
  openwatch-db:/tmp/restore.dump

docker exec openwatch-db pg_restore \
  -U openwatch -d openwatch \
  --no-owner --no-privileges \
  /tmp/restore.dump

docker exec openwatch-db rm /tmp/restore.dump

# 3. Revert code
git checkout v<OLD_VERSION>

# 4. Rebuild and start
./start-openwatch.sh --runtime docker --build

# 5. Verify
curl -f http://localhost:8000/health
```

## Upgrading Individual Components

### Backend Only

```bash
docker stop openwatch-backend openwatch-worker openwatch-celery-beat

# Run migrations if needed
docker compose run --rm backend \
  alembic -c /app/backend/alembic.ini upgrade head

# Rebuild and restart
docker compose up -d --build backend worker celery-beat
```

### Frontend Only

```bash
docker compose up -d --build frontend
```

### Database (PostgreSQL)

Upgrading PostgreSQL major versions requires a dump-and-restore cycle:

```bash
# 1. Backup with current version
docker exec openwatch-db pg_dumpall -U openwatch > /tmp/full_dump.sql

# 2. Stop all services
./stop-openwatch.sh --simple

# 3. Update PostgreSQL image version in docker-compose.yml

# 4. Remove old data volume
docker volume rm openwatch_postgres_data

# 5. Start new PostgreSQL
docker compose up -d database
sleep 10

# 6. Restore data
docker cp /tmp/full_dump.sql openwatch-db:/tmp/full_dump.sql
docker exec openwatch-db psql -U openwatch -d postgres -f /tmp/full_dump.sql

# 7. Start all services
./start-openwatch.sh --runtime docker
```

### Redis

Redis upgrades are generally backward-compatible:

```bash
# Update image version in docker-compose.yml
# Restart Redis
docker compose up -d redis
```

### Aegis Rules

Aegis rules are bundled in `backend/aegis/`. To update rules:

```bash
# Pull latest Aegis rules
cd backend/aegis
git pull origin main

# Rebuild backend
docker compose up -d --build backend worker

# Verify rules loaded
curl -f http://localhost:8000/api/scans/aegis/health
curl http://localhost:8000/api/rules/reference/ | python3 -m json.tool | head -20
```

## Upgrade Troubleshooting

### Migration Fails

```bash
# Check migration error details
docker compose run --rm backend \
  alembic -c /app/backend/alembic.ini current

# If "multiple heads" error:
docker compose run --rm backend \
  alembic -c /app/backend/alembic.ini heads

# Create a merge migration if needed:
docker compose run --rm backend \
  alembic -c /app/backend/alembic.ini merge heads -m "merge migration"
```

### Service Fails to Start After Upgrade

```bash
# Check logs for the failing service
docker logs openwatch-backend --tail 100

# Common issues:
# - Missing environment variable -> add to .env
# - Database schema mismatch -> run migrations
# - Port conflict -> check for other processes on 8000/3000
```

### Health Check Fails After Upgrade

```bash
# Check each service individually
docker exec openwatch-db pg_isready -U openwatch
docker exec openwatch-redis redis-cli -a "$REDIS_PASSWORD" ping
curl -v http://localhost:8000/health

# Check if backend can reach database
docker exec openwatch-backend python3 -c "
from app.config import settings
print(f'DB URL: {settings.database_url[:30]}...')
"
```

## Post-Upgrade Checklist

After a successful upgrade:

- [ ] Health endpoint returns healthy
- [ ] All containers running and healthy (`docker ps`)
- [ ] No errors in backend logs
- [ ] No errors in worker logs
- [ ] Celery workers connected and processing
- [ ] At least one scan can execute successfully
- [ ] Frontend loads and users can log in
- [ ] API documentation accessible at `/api/docs`
- [ ] Monitoring dashboards show data (if configured)
- [ ] Document the upgrade in your change log
- [ ] Remove pre-upgrade backup after validation period (7 days recommended)
