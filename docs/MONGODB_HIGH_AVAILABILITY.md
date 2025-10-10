# MongoDB High Availability Setup for OpenWatch

## Overview
MongoDB is a critical component for OpenWatch, storing all compliance rules and framework mappings. This guide covers setting up MongoDB for high availability and troubleshooting common issues.

## Current Issue Resolution

### Problem Identified
- MongoDB container exited 2 days ago with exit code 0 (normal shutdown)
- Container was not automatically restarted
- Missing MongoDB credentials in .env file

### Immediate Fix Applied
```bash
# Remove old container
docker rm b24dd07df31b_openwatch-mongodb

# Start fresh MongoDB instance
docker-compose up -d mongodb
```

## High Availability Configuration

### 1. MongoDB Replica Set Configuration

Create a MongoDB replica set for high availability:

```yaml
# docker-compose-ha.yml
services:
  mongodb-primary:
    image: mongo:7.0.15-jammy
    container_name: openwatch-mongodb-primary
    restart: always  # Changed from 'unless-stopped' for HA
    environment:
      MONGO_INITDB_ROOT_USERNAME: ${MONGO_ROOT_USER:-openwatch}
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_ROOT_PASSWORD}
      MONGO_INITDB_DATABASE: openwatch_rules
      MONGO_REPLICA_SET_NAME: openwatch-rs
    volumes:
      - mongodb_primary_data:/data/db
      - ./backend/app/data/mongo/init:/docker-entrypoint-initdb.d:ro
      - ./security/certs/mongodb:/etc/ssl:ro
    ports:
      - "127.0.0.1:27017:27017"
    networks:
      - openwatch-network
    command: >
      mongod
      --auth
      --bind_ip_all
      --replSet openwatch-rs
      --keyFile /etc/ssl/mongodb-keyfile
      --tlsMode allowTLS
      --tlsCertificateKeyFile /etc/ssl/mongodb.pem
      --tlsCAFile /etc/ssl/ca.crt
    healthcheck:
      test: |
        mongosh --eval "rs.status().ok || rs.initiate({_id: 'openwatch-rs', members: [{_id: 0, host: 'mongodb-primary:27017', priority: 2}]})" \
        -u ${MONGO_ROOT_USER:-openwatch} -p ${MONGO_ROOT_PASSWORD} \
        --authenticationDatabase admin --quiet
      interval: 10s
      timeout: 10s
      retries: 5
      start_period: 40s

  mongodb-secondary1:
    image: mongo:7.0.15-jammy
    container_name: openwatch-mongodb-secondary1
    restart: always
    environment:
      MONGO_INITDB_ROOT_USERNAME: ${MONGO_ROOT_USER:-openwatch}
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_ROOT_PASSWORD}
    volumes:
      - mongodb_secondary1_data:/data/db
      - ./security/certs/mongodb:/etc/ssl:ro
    networks:
      - openwatch-network
    command: >
      mongod
      --auth
      --bind_ip_all
      --replSet openwatch-rs
      --keyFile /etc/ssl/mongodb-keyfile
      --tlsMode allowTLS
      --tlsCertificateKeyFile /etc/ssl/mongodb.pem
      --tlsCAFile /etc/ssl/ca.crt
    depends_on:
      - mongodb-primary

  mongodb-secondary2:
    image: mongo:7.0.15-jammy
    container_name: openwatch-mongodb-secondary2
    restart: always
    environment:
      MONGO_INITDB_ROOT_USERNAME: ${MONGO_ROOT_USER:-openwatch}
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_ROOT_PASSWORD}
    volumes:
      - mongodb_secondary2_data:/data/db
      - ./security/certs/mongodb:/etc/ssl:ro
    networks:
      - openwatch-network
    command: >
      mongod
      --auth
      --bind_ip_all
      --replSet openwatch-rs
      --keyFile /etc/ssl/mongodb-keyfile
      --tlsMode allowTLS
      --tlsCertificateKeyFile /etc/ssl/mongodb.pem
      --tlsCAFile /etc/ssl/ca.crt
    depends_on:
      - mongodb-primary

  mongodb-arbiter:
    image: mongo:7.0.15-jammy
    container_name: openwatch-mongodb-arbiter
    restart: always
    environment:
      MONGO_INITDB_ROOT_USERNAME: ${MONGO_ROOT_USER:-openwatch}
      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_ROOT_PASSWORD}
    volumes:
      - mongodb_arbiter_data:/data/db
      - ./security/certs/mongodb:/etc/ssl:ro
    networks:
      - openwatch-network
    command: >
      mongod
      --auth
      --bind_ip_all
      --replSet openwatch-rs
      --keyFile /etc/ssl/mongodb-keyfile
      --port 27019
    depends_on:
      - mongodb-primary
```

### 2. Update .env File

Add MongoDB credentials to your `.env` file:

```bash
# MongoDB Configuration
MONGO_ROOT_USER=openwatch
MONGO_ROOT_PASSWORD=openwatch_secure_mongo_2025
MONGO_REPLICA_SET=mongodb://openwatch:openwatch_secure_mongo_2025@mongodb-primary:27017,mongodb-secondary1:27017,mongodb-secondary2:27017/openwatch_rules?replicaSet=openwatch-rs&authSource=admin
```

### 3. Generate MongoDB Keyfile for Replica Set

```bash
# Generate keyfile for replica set authentication
openssl rand -base64 756 > security/certs/mongodb-keyfile
chmod 400 security/certs/mongodb-keyfile
```

### 4. Initialize Replica Set

After starting all MongoDB containers:

```bash
# Connect to primary
docker exec -it openwatch-mongodb-primary mongosh -u openwatch -p openwatch_secure_mongo_2025 --authenticationDatabase admin

# Initialize replica set
rs.initiate({
  _id: "openwatch-rs",
  members: [
    { _id: 0, host: "mongodb-primary:27017", priority: 2 },
    { _id: 1, host: "mongodb-secondary1:27017", priority: 1 },
    { _id: 2, host: "mongodb-secondary2:27017", priority: 1 },
    { _id: 3, host: "mongodb-arbiter:27019", arbiterOnly: true }
  ]
})

# Check status
rs.status()
```

## Monitoring and Health Checks

### 1. Enhanced Health Check Script

Create `scripts/check_mongodb_health.sh`:

```bash
#!/bin/bash

# MongoDB health check script
MONGO_USER=${MONGO_ROOT_USER:-openwatch}
MONGO_PASS=${MONGO_ROOT_PASSWORD}

# Check primary health
echo "Checking MongoDB Primary..."
docker exec openwatch-mongodb-primary mongosh \
  -u $MONGO_USER -p $MONGO_PASS \
  --authenticationDatabase admin \
  --eval "db.adminCommand('ping')" --quiet

# Check replica set status
echo "Checking Replica Set Status..."
docker exec openwatch-mongodb-primary mongosh \
  -u $MONGO_USER -p $MONGO_PASS \
  --authenticationDatabase admin \
  --eval "rs.status().ok" --quiet

# Check OpenWatch rules collection
echo "Checking OpenWatch Rules Collection..."
docker exec openwatch-mongodb-primary mongosh \
  -u $MONGO_USER -p $MONGO_PASS \
  --authenticationDatabase admin \
  openwatch_rules \
  --eval "db.compliance_rules.countDocuments({})" --quiet
```

### 2. Automated Monitoring

Add to your monitoring stack:

```yaml
# prometheus/mongodb_exporter.yml
mongodb_exporter:
  image: percona/mongodb_exporter:0.40
  container_name: mongodb-exporter
  restart: always
  environment:
    MONGODB_URI: mongodb://openwatch:${MONGO_ROOT_PASSWORD}@mongodb-primary:27017/admin?ssl=false
  ports:
    - "9216:9216"
  networks:
    - openwatch-network
```

## Backup Strategy

### 1. Automated Backups

Create `scripts/backup_mongodb.sh`:

```bash
#!/bin/bash

# MongoDB backup script
BACKUP_DIR="/app/data/backups/mongodb"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="openwatch_rules_backup_$TIMESTAMP"

# Create backup directory
mkdir -p $BACKUP_DIR

# Perform backup
docker exec openwatch-mongodb-primary mongodump \
  -u openwatch -p ${MONGO_ROOT_PASSWORD} \
  --authenticationDatabase admin \
  --db openwatch_rules \
  --out /data/backup/$BACKUP_NAME

# Compress backup
docker exec openwatch-mongodb-primary tar -czf /data/backup/$BACKUP_NAME.tar.gz /data/backup/$BACKUP_NAME

# Copy to host
docker cp openwatch-mongodb-primary:/data/backup/$BACKUP_NAME.tar.gz $BACKUP_DIR/

# Clean up container backup
docker exec openwatch-mongodb-primary rm -rf /data/backup/$BACKUP_NAME*

# Keep only last 7 days of backups
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete

echo "Backup completed: $BACKUP_DIR/$BACKUP_NAME.tar.gz"
```

### 2. Schedule Backups

Add to crontab:

```bash
# Daily MongoDB backups at 2 AM
0 2 * * * /home/openwatch/scripts/backup_mongodb.sh >> /var/log/mongodb_backup.log 2>&1
```

## Troubleshooting Guide

### Common Issues and Solutions

1. **MongoDB Won't Start**
   ```bash
   # Check logs
   docker logs openwatch-mongodb

   # Check disk space
   df -h | grep mongodb

   # Check permissions
   ls -la security/certs/mongodb/
   ```

2. **Authentication Failures**
   ```bash
   # Reset password
   docker exec -it openwatch-mongodb mongosh

   # Switch to admin db
   use admin

   # Update password
   db.changeUserPassword("openwatch", "new_secure_password")
   ```

3. **Connection Timeouts**
   ```bash
   # Check network
   docker network inspect openwatch-network

   # Test connectivity
   docker exec openwatch-backend ping mongodb
   ```

4. **Replica Set Issues**
   ```bash
   # Force reconfiguration
   rs.reconfig(rs.conf(), {force: true})

   # Step down primary
   rs.stepDown()

   # Remove unhealthy member
   rs.remove("mongodb-secondary2:27017")
   ```

## Performance Optimization

### 1. Index Optimization

```javascript
// Connect to MongoDB
docker exec -it openwatch-mongodb-primary mongosh -u openwatch -p $MONGO_PASS --authenticationDatabase admin openwatch_rules

// Create performance indexes
db.compliance_rules.createIndex({ "rule_id": 1 }, { unique: true })
db.compliance_rules.createIndex({ "platform_implementations": 1, "severity": -1 })
db.compliance_rules.createIndex({ "frameworks.nist": 1 })
db.compliance_rules.createIndex({ "frameworks.cis": 1 })
db.compliance_rules.createIndex({ "tags": 1 })
db.compliance_rules.createIndex({ "category": 1, "severity": -1 })

// Analyze index usage
db.compliance_rules.aggregate([{ $indexStats: {} }])
```

### 2. Connection Pool Configuration

Update backend configuration:

```python
# backend/app/config.py
MONGODB_MIN_POOL_SIZE = 10
MONGODB_MAX_POOL_SIZE = 100
MONGODB_MAX_IDLE_TIME_MS = 30000
```

## Disaster Recovery

### 1. Point-in-Time Recovery

Enable oplog for point-in-time recovery:

```javascript
// Check oplog size
db.getReplicationInfo()

// Increase oplog size if needed
db.adminCommand({replSetResizeOplog: 1, size: 10240})
```

### 2. Restore Procedure

```bash
# Stop application
docker-compose stop backend worker

# Restore from backup
docker exec -i openwatch-mongodb-primary mongorestore \
  -u openwatch -p ${MONGO_ROOT_PASSWORD} \
  --authenticationDatabase admin \
  --drop \
  --db openwatch_rules \
  /data/backup/openwatch_rules_backup_20250912_020000

# Restart application
docker-compose start backend worker
```

## Security Hardening

### 1. Enable Audit Logging

Add to MongoDB command:

```yaml
command: >
  mongod
  --auditDestination file
  --auditFormat JSON
  --auditPath /var/log/mongodb/audit.json
```

### 2. Network Isolation

```yaml
networks:
  mongodb-internal:
    driver: bridge
    internal: true
  openwatch-network:
    driver: bridge
```

### 3. Regular Security Updates

```bash
# Check for updates
docker pull mongo:7.0.15-jammy

# Update with zero downtime
docker-compose up -d --no-deps --build mongodb-secondary1
# Wait for sync
docker-compose up -d --no-deps --build mongodb-secondary2
# Step down primary
docker exec openwatch-mongodb-primary mongosh --eval "rs.stepDown()"
# Update former primary
docker-compose up -d --no-deps --build mongodb-primary
```

## Monitoring Alerts

### Key Metrics to Monitor

1. **Availability**
   - Primary node status
   - Replica set health
   - Connection count

2. **Performance**
   - Query execution time
   - Index hit ratio
   - Lock percentage

3. **Resources**
   - Memory usage
   - Disk I/O
   - Network latency

4. **Security**
   - Failed authentication attempts
   - Unusual query patterns
   - Backup success rate

## Support Resources

- MongoDB Documentation: https://docs.mongodb.com/
- OpenWatch Issues: https://github.com/Hanalyx/OpenWatch/issues
- Community Support: https://github.com/Hanalyx/OpenWatch/discussions

---
Last updated: 2025-09-12