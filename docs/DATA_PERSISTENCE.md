# OpenWatch Data Persistence Guide

## Overview

OpenWatch uses Docker volumes to persist data across container restarts. However, the stop script behavior changed to be **safe by default** after users reported data loss.

## Critical Issue: Data Loss on Stop

**Previous Behavior (DANGEROUS):**
```bash
./stop-openwatch.sh  # Would DELETE ALL DATA by default
```

**Current Behavior (SAFE):**
```bash
./stop-openwatch.sh  # Preserves all data volumes
```

## How Data is Stored

### Volume Mappings

```yaml
# PostgreSQL - Application database
postgres_data → /var/lib/postgresql/data
  - User accounts
  - Host inventory
  - Scan history
  - System configuration

# MongoDB - Compliance data
mongodb_data → /data/db
  - Compliance rules (1,387 SCAP rules)
  - Framework mappings (CIS, STIG, NIST)
  - Platform implementations

# Application data
app_data → /app/data
  - Uploaded SCAP content (.xml files)
  - Scan results (XML, ARF, HTML)
  - Logs and certificates
```

### Verifying Data Persistence

Check volumes exist:
```bash
docker volume ls | grep openwatch
```

Expected output:
```
openwatch_app_data
openwatch_mongodb_data
openwatch_postgres_data
```

Inspect volume mount points:
```bash
docker inspect openwatch-mongodb --format='{{json .Mounts}}' | python3 -m json.tool
docker inspect openwatch-db --format='{{json .Mounts}}' | python3 -m json.tool
```

## Safe vs Clean Mode

### Safe Mode (Default - Preserves Data)

```bash
./stop-openwatch.sh                    # Safe stop
./stop-openwatch.sh --simple          # Alias for safe stop
```

**What happens:**
- Containers stopped and removed
- **Volumes preserved** (all data retained)
- Networks cleaned up
- Next startup restores all data

**Use this when:**
- Restarting services after updates
- Debugging container issues
- Normal day-to-day operations
- Any time you want to keep your data

### Clean Mode (DANGEROUS - Deletes Data)

```bash
OPENWATCH_CLEAN_STOP=true ./stop-openwatch.sh  # Clean stop
./stop-openwatch.sh --deep-clean               # Nuclear option
```

**What happens:**
- Containers stopped and removed
- **Volumes deleted** (ALL DATA LOST)
- Networks cleaned up
- Next startup is completely fresh

**Use this when:**
- Testing fresh installations
- Cleaning up development environment
- Troubleshooting database corruption
- **NEVER in production** unless intentional

**Warning signs:**
```
⚠️  CLEAN MODE: Will DELETE ALL DATA (volumes will be removed)
⚠️  This includes hosts, credentials, scan results, and SCAP content
```

## Common Scenarios

### Scenario 1: Update Backend Code
```bash
# Copy new code to container
docker cp backend/app/file.py openwatch-backend:/app/backend/app/file.py

# Restart services (preserves data)
./stop-openwatch.sh
./start-openwatch.sh --runtime docker
```

### Scenario 2: Rebuild Containers
```bash
# Rebuild with data preservation
./stop-openwatch.sh
./start-openwatch.sh --force-build --runtime docker

# Data is restored from volumes after rebuild
```

### Scenario 3: Complete Fresh Start
```bash
# Delete everything and start over
OPENWATCH_CLEAN_STOP=true ./stop-openwatch.sh
./start-openwatch.sh --force-build --runtime docker

# All data lost, fresh installation
```

### Scenario 4: Backup Before Cleanup
```bash
# Backup volumes first
docker run --rm \
  -v openwatch_postgres_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/postgres_backup.tar.gz /data

docker run --rm \
  -v openwatch_mongodb_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/mongodb_backup.tar.gz /data

# Now safe to clean
./stop-openwatch.sh --deep-clean
```

## Troubleshooting Data Issues

### Data disappeared after restart

**Cause:** Ran `./stop-openwatch.sh` when it defaulted to clean mode (older versions)

**Fix:**
1. Update to latest `stop-openwatch.sh` (safe by default)
2. Data is lost, must re-enter
3. Use safe mode going forward

### Data not persisting between restarts

**Check 1:** Verify volumes exist
```bash
docker volume ls | grep openwatch
```

**Check 2:** Verify containers use volumes
```bash
docker inspect openwatch-mongodb --format='{{json .Mounts}}' | python3 -m json.tool
```

**Check 3:** Check for clean mode flag
```bash
grep "CLEAN_MODE" stop-openwatch.sh
# Should show: CLEAN_MODE=${OPENWATCH_CLEAN_STOP:-false}
```

### Want to reset database but keep SCAP content

```bash
# Stop services safely
./stop-openwatch.sh

# Delete only PostgreSQL volume
docker volume rm openwatch_postgres_data

# Restart (PostgreSQL will be fresh, MongoDB preserved)
./start-openwatch.sh --runtime docker
```

## Best Practices

1. **Default to safe mode** - Always use `./stop-openwatch.sh` without flags
2. **Explicit clean mode** - Only use `OPENWATCH_CLEAN_STOP=true` when intentional
3. **Backup before cleanup** - Always backup volumes before `--deep-clean`
4. **Test in development** - Use clean mode in dev, safe mode everywhere else
5. **Document data loss** - If using clean mode in scripts, add prominent warnings

## Migration Notes

**For users upgrading from older versions:**

The default behavior changed from clean mode (deletes data) to safe mode (preserves data).

If you relied on automatic cleanup, update your scripts:
```bash
# Old behavior (automatic cleanup)
./stop-openwatch.sh

# New equivalent
OPENWATCH_CLEAN_STOP=true ./stop-openwatch.sh
```

**Why this change?**

Multiple users reported unexpected data loss. The principle of least surprise dictates that "stop" should not delete data. Cleanup should be explicit and intentional.
