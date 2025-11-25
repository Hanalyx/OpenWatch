# OpenWatch Systemd Integration

Enterprise systemd service units for OpenWatch container orchestration and lifecycle management.

## Service Architecture

OpenWatch uses a multi-service architecture managed by systemd:

```
openwatch.target
├── openwatch-db.service      (PostgreSQL database)
├── openwatch-redis.service   (Redis cache)
├── openwatch-worker.service  (Celery background workers)
├── openwatch-frontend.service (Nginx + React frontend)
└── openwatch.service         (Main application orchestrator)
```

## Core Services

### Main Orchestrator: `openwatch.service`

The primary service that coordinates all OpenWatch components:

- **Type**: `notify` (systemd-aware service)
- **Dependencies**: Database, Redis services
- **Security**: Full systemd hardening enabled
- **Monitoring**: Watchdog and health checks
- **Resource Limits**: Controlled memory and process limits

**Key Features**:
- Configuration validation before startup
- Graceful shutdown handling
- Automatic restart on failure
- Security sandboxing

### Database Service: `openwatch-db.service`

Manages the PostgreSQL database container:

- **Startup Time**: 120 seconds (database initialization)
- **Health Checks**: Post-start validation
- **Data Persistence**: `/var/lib/openwatch/postgresql`
- **Backup Integration**: Works with backup timer

### Cache Service: `openwatch-redis.service`

Manages the Redis cache container:

- **Startup Time**: 60 seconds
- **Memory Management**: Configured with LRU eviction
- **Persistence**: Optional (configurable)

### Worker Service: `openwatch-worker.service`

Manages Celery background workers for scanning:

- **Capabilities**: Extended for SSH scanning operations
- **Network Access**: Required for remote host scanning
- **Resource Limits**: Higher limits for scan processing

### Frontend Service: `openwatch-frontend.service`

Manages the web interface container:

- **Port Binding**: Requires `CAP_NET_BIND_SERVICE`
- **SSL/TLS**: Integrated certificate management
- **Static Assets**: Nginx-based serving

## Service Target: `openwatch.target`

Systemd target for managing all OpenWatch services collectively:

```bash
# Start all services
sudo systemctl start openwatch.target

# Stop all services
sudo systemctl stop openwatch.target

# Check status of all services
sudo systemctl status openwatch.target
```

## Maintenance Services

### Automated Backup: `openwatch-backup.service` + Timer

Daily database backup with encryption and compression:

- **Schedule**: Daily at 2 AM (randomized ±5 minutes)
- **Retention**: 30 days (configurable)
- **Encryption**: AES-256-GCM
- **Compression**: gzip with verification

```bash
# Enable automatic backups
sudo systemctl enable openwatch-backup.timer
sudo systemctl start openwatch-backup.timer

# Manual backup
sudo systemctl start openwatch-backup.service

# Check backup status
sudo systemctl status openwatch-backup.timer
```

### System Maintenance: `openwatch-maintenance.service` + Timer

Weekly maintenance tasks:

- **Database**: VACUUM, ANALYZE operations
- **Logs**: Rotation and cleanup
- **Results**: Compression and archival
- **Schedule**: Sundays at 3 AM

```bash
# Enable maintenance
sudo systemctl enable openwatch-maintenance.timer
sudo systemctl start openwatch-maintenance.timer

# Manual maintenance
sudo systemctl start openwatch-maintenance.service
```

## Security Hardening

All services implement comprehensive systemd security features:

### Mandatory Security Options
```ini
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
LockPersonality=true
PrivateTmp=true
```

### File System Protection
- **Read-Write**: Only necessary directories (`/var/lib/openwatch`, `/var/log/openwatch`)
- **Read-Only**: Configuration and shared files
- **Inaccessible**: Sensitive system paths (`/proc/kcore`, `/proc/keys`)

### Network Restrictions
- **Address Families**: Only Unix, IPv4, IPv6
- **Private Network**: Disabled (containers need network)

### Resource Limits
Per-service resource controls:
- File descriptors: 4096-65536 depending on service
- Process count: 256-4096 depending on service
- Task limits: Prevent fork bombs

## Service Management

### Individual Service Control

```bash
# Database operations
sudo systemctl start openwatch-db.service
sudo systemctl status openwatch-db.service
journalctl -u openwatch-db.service -f

# Worker operations
sudo systemctl restart openwatch-worker.service
sudo systemctl reload openwatch-worker.service

# Frontend operations
sudo systemctl stop openwatch-frontend.service
```

### Bulk Operations

```bash
# Start all OpenWatch services
sudo systemctl start openwatch.target

# Restart entire platform
sudo systemctl restart openwatch.target

# Check all service statuses
sudo systemctl list-dependencies openwatch.target
```

### Service Dependencies

Services start in proper order automatically:
1. `openwatch-db.service` (database first)
2. `openwatch-redis.service` (cache second)
3. `openwatch-worker.service` (workers after data services)
4. `openwatch.service` (main orchestrator)
5. `openwatch-frontend.service` (frontend last)

## Health Monitoring

### Systemd Integration

Services support systemd's native monitoring:

- **Watchdog**: Services send heartbeats to systemd
- **Notify**: Services report startup completion
- **Health Checks**: Post-start validation

### Manual Health Checks

```bash
# Check service health
owadm health-check --service database --wait 60
owadm health-check --service redis --wait 30
owadm health-check --all

# Validate configuration
owadm validate-config --database-only
owadm validate-config
```

## Log Management

### Service Logs

All services log to systemd journal:

```bash
# View service logs
journalctl -u openwatch.service -f
journalctl -u openwatch-db.service --since "1 hour ago"
journalctl -u openwatch.target --all

# Export logs
journalctl -u openwatch.service --since yesterday --no-pager > openwatch.log
```

### Application Logs

Additional logging to files:
- Application: `/var/log/openwatch/openwatch.log`
- Audit: `/var/log/openwatch/audit.log`
- Access: `/var/log/openwatch/access.log`

## Troubleshooting

### Service Start Failures

1. **Check systemd status**:
   ```bash
   sudo systemctl status openwatch.service
   journalctl -u openwatch.service --lines 50
   ```

2. **Validate configuration**:
   ```bash
   owadm validate-config
   ```

3. **Check dependencies**:
   ```bash
   sudo systemctl list-dependencies openwatch.service --failed
   ```

### Performance Issues

1. **Check resource usage**:
   ```bash
   systemctl show openwatch.service --property CPUUsageNSec,MemoryUsage
   ```

2. **Analyze startup time**:
   ```bash
   systemd-analyze blame
   systemd-analyze critical-chain openwatch.target
   ```

### Security Violations

1. **Check for SELinux denials** (RHEL/CentOS):
   ```bash
   sudo ausearch -m AVC -ts recent
   sudo sealert -a /var/log/audit/audit.log
   ```

2. **Check for AppArmor violations** (Ubuntu):
   ```bash
   sudo dmesg | grep -i apparmor
   journalctl -f | grep -i apparmor
   ```

## Advanced Configuration

### Custom Service Overrides

Create drop-in configuration files:

```bash
# Create override directory
sudo mkdir -p /etc/systemd/system/openwatch.service.d/

# Create custom configuration
sudo tee /etc/systemd/system/openwatch.service.d/custom.conf << EOF
[Service]
# Custom resource limits
LimitNOFILE=131072
TasksMax=8192

# Custom environment
Environment=OPENWATCH_DEBUG=true
EOF

# Reload systemd
sudo systemctl daemon-reload
sudo systemctl restart openwatch.service
```

### Development Mode

Disable security restrictions for development:

```bash
sudo tee /etc/systemd/system/openwatch.service.d/development.conf << EOF
[Service]
# Disable security hardening for development
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
PrivateTmp=false
EOF
```

**Warning**: Only use development overrides on non-production systems.

---

*Last updated: 2025-08-31*
