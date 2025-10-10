# OpenWatch Podman Deployment Guide

## Executive Summary

This guide provides comprehensive instructions for deploying OpenWatch using Podman with rootless containers for enhanced security. OpenWatch supports both Docker and Podman, with automatic runtime detection and environment-specific configurations.

## 🚀 Quick Start

### Prerequisites

**Ubuntu 24.04 LTS (Tested)**:
```bash
# Install Podman and podman-compose
sudo apt update
sudo apt install -y podman podman-compose openssl curl jq

# Verify installation
podman --version
podman-compose --version
```

**Other Linux Distributions**:
- RHEL/CentOS/Fedora: `dnf install podman podman-compose`
- Arch Linux: `pacman -S podman podman-compose`

### Deployment Options

#### Option 1: Using the owadm CLI (Recommended)
```bash
# Build the OpenWatch Admin CLI
cd cmd/owadm
go build -o ../../owadm .

# Start OpenWatch (auto-detects Podman)
./owadm start

# Check status
./owadm status

# View logs
./owadm logs backend --follow

# Stop services
./owadm stop
```

#### Option 2: Using Shell Scripts
```bash
# Development mode
./start-podman.sh --dev

# Production mode (default)
./start-podman.sh

# Stop services
./stop-podman.sh
```

## 📋 Detailed Deployment

### 1. Environment Configuration

#### Automatic Configuration (Recommended)
OpenWatch automatically creates secure environment files:
```bash
./owadm start  # Creates .env with secure random values
```

#### Manual Configuration
Create `.env` file with custom values:
```bash
# Application Settings
APP_ENV=production
DEBUG=false

# Security Keys (generate with: openssl rand -hex 32)
SECRET_KEY=your-secure-secret-key-here
JWT_SECRET=your-jwt-secret-here

# Database Configuration
POSTGRES_PASSWORD=your-secure-db-password
POSTGRES_USER=openwatch
POSTGRES_DB=openwatch
DATABASE_URL=postgresql://openwatch:your-secure-db-password@database:5432/openwatch

# Redis Configuration
REDIS_PASSWORD=your-redis-password
REDIS_URL=redis://:your-redis-password@redis:6379/0
```

### 2. Runtime Selection

#### Automatic Detection (Default)
```bash
# Automatically prefers Podman over Docker
./owadm start
```

#### Explicit Runtime Selection
```bash
# Force Podman usage
./owadm start --runtime podman

# Force Docker usage (if available)
./owadm start --runtime docker
```

### 3. Environment Modes

#### Development Mode
```bash
# Uses podman-compose.dev.yml
./owadm start --env dev
# OR
./start-podman.sh --dev
```

**Development Mode Features**:
- Hot reload enabled
- Debug logging
- Additional development tools
- Port 3001 for frontend

#### Production Mode
```bash
# Uses podman-compose.yml (default)
./owadm start
```

**Production Mode Features**:
- Rootless containers
- FIPS mode enabled
- Enhanced security settings
- Ports 8080/8443 for web access
- Read-only filesystems
- Security contexts enabled

## 🔒 Security Features

### Rootless Containers
Podman runs containers without root privileges:
```bash
# Verify rootless operation
podman info --format json | jq '.host.security.rootless'
```

### FIPS Compliance
Production Podman deployment includes:
- AES-256-GCM encryption
- RSA-2048 with PSS padding
- SHA-256/384/512 hash functions
- PBKDF2 key derivation

### SELinux Integration
Automatic SELinux labels for volume mounts:
```yaml
# Volumes use :Z suffix for automatic labeling
volumes:
  - ./data:/app/data:Z
  - ./logs:/app/logs:Z
```

### Container Security
- `no-new-privileges` enabled
- Read-only root filesystems where possible
- Tmpfs mounts for temporary data
- Dropped capabilities

## 📊 Resource Management

### System Requirements

**Minimum Requirements**:
- 2 CPU cores
- 4GB RAM
- 20GB disk space

**Recommended Requirements**:
- 4+ CPU cores
- 8GB+ RAM
- 50GB+ disk space

### Resource Monitoring

#### Using owadm
```bash
# Check container status
./owadm status

# View resource usage (planned feature)
./owadm stats
```

#### Using Podman directly
```bash
# Container resource usage
podman stats --no-stream

# System resource usage
podman system df

# Pod statistics (if using pods)
podman pod stats
```

### Performance Comparison

Based on testing, Podman typically shows:
- **Memory Usage**: 5-10% lower than Docker
- **CPU Efficiency**: Comparable to Docker
- **Startup Time**: 15-30% faster (rootless)
- **Security**: Enhanced due to rootless operation

## 🛠 Troubleshooting

### Common Issues

#### 1. Port Binding Issues (Rootless)
**Problem**: Cannot bind to ports < 1024
**Solution**: Use high ports (8080/8443) or configure port forwarding:
```bash
# Check Podman port configuration
cat /proc/sys/net/ipv4/ip_unprivileged_port_start
```

#### 2. Volume Permission Issues
**Problem**: Permission denied accessing volumes
**Solution**: Use proper ownership or podman unshare:
```bash
# Fix volume permissions
podman unshare chown -R 1000:1000 ./data
```

#### 3. Storage Driver Issues
**Problem**: Different behavior between systems
**Solution**: Explicitly set storage driver:
```bash
# Check current storage driver
podman info --format json | jq '.store.graphDriverName'

# Use overlay if available
echo 'driver = "overlay"' >> ~/.config/containers/storage.conf
```

#### 4. Container Not Starting
**Problem**: Containers fail to start
**Solutions**:
```bash
# Check container logs
./owadm logs <service>

# Verify compose file syntax
podman-compose -f podman-compose.yml config

# Reset containers
./owadm stop --remove-volumes
./owadm start --build
```

### Diagnostic Commands

```bash
# System information
podman info

# Container processes
podman top <container>

# Resource usage
podman stats <container>

# Network configuration
podman network ls
podman network inspect <network>

# Volume information
podman volume ls
podman volume inspect <volume>
```

## 🔧 Advanced Configuration

### Custom Compose Files

#### Create Custom Environment
```yaml
# podman-compose.custom.yml
version: '3.8'
services:
  backend:
    environment:
      - CUSTOM_SETTING=value
```

```bash
# Use custom compose file
COMPOSE_FILE=podman-compose.custom.yml ./owadm start
```

### Systemd Integration

#### Service File
```ini
# /etc/systemd/system/openwatch.service
[Unit]
Description=OpenWatch SCAP Scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=openwatch
Group=openwatch
WorkingDirectory=/opt/openwatch
ExecStart=/usr/local/bin/owadm start --runtime podman
ExecStop=/usr/local/bin/owadm stop --timeout 30
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### Enable Service
```bash
# Create dedicated user
sudo useradd -r -s /bin/bash openwatch
sudo loginctl enable-linger openwatch

# Install and enable service
sudo systemctl enable --now openwatch.service
sudo systemctl status openwatch.service
```

### Network Configuration

#### Custom Networks
```bash
# Create custom network
podman network create openwatch-net --subnet 172.20.0.0/16

# Use in compose file
networks:
  default:
    external:
      name: openwatch-net
```

#### Firewall Configuration
```bash
# Allow Podman ports (if using firewall)
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

## 📈 Monitoring and Logging

### Log Management

#### Centralized Logging
```bash
# Configure podman logging
echo 'log_driver = "k8s-file"' >> ~/.config/containers/containers.conf
echo 'log_size_max = "10m"' >> ~/.config/containers/containers.conf
```

#### Log Rotation
```bash
# Setup logrotate for container logs
sudo tee /etc/logrotate.d/openwatch << EOF
/var/log/openwatch/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 openwatch openwatch
}
EOF
```

### Health Monitoring

#### Built-in Health Checks
```bash
# Check service health
./owadm status

# Monitor continuously
watch -n 10 './owladm status'
```

#### External Monitoring
```bash
# Prometheus metrics (if enabled)
curl http://localhost:8000/metrics

# Health endpoint
curl http://localhost:8000/health
```

## 🔄 Backup and Recovery

### Data Backup

#### Automated Backup Script
```bash
#!/bin/bash
# backup-openwatch.sh

BACKUP_DIR="/backup/openwatch"
DATE=$(date +%Y%m%d_%H%M%S)

# Stop services gracefully
./owladm stop

# Backup volumes
podman volume export openwatch_postgres_data - | gzip > "$BACKUP_DIR/postgres_$DATE.tar.gz"
podman volume export openwatch_redis_data - | gzip > "$BACKUP_DIR/redis_$DATE.tar.gz"

# Backup configuration
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" .env docker-compose*.yml podman-compose*.yml

# Restart services
./owadm start
```

### Data Recovery

```bash
#!/bin/bash
# restore-openwatch.sh

BACKUP_FILE=$1

# Stop services
./owadm stop --remove-volumes

# Restore volumes
gunzip -c postgres_backup.tar.gz | podman volume import openwatch_postgres_data -
gunzip -c redis_backup.tar.gz | podman volume import openwatch_redis_data -

# Restore configuration
tar -xzf config_backup.tar.gz

# Start services
./owladm start
```

## 📚 Additional Resources

### Testing
- **Test Suite**: `tests/podman/startup_test.sh`
- **Resource Monitoring**: `tests/comparison/resource_monitor.sh`
- **Performance Comparison**: See generated reports in `tests/*/results/`

### Configuration Files
- **Production**: `podman-compose.yml`
- **Development**: `podman-compose.dev.yml`
- **Shell Scripts**: `start-podman.sh`, `stop-podman.sh`

### Command Reference

```bash
# owadm Commands
./owadm start [--env dev] [--runtime podman] [--build]
./owadm stop [--force] [--remove-volumes]
./owadm status
./owadm logs <service> [--follow] [--tail 100]
./owadm exec <service> <command>

# Direct Podman Commands
podman-compose -f podman-compose.yml up -d
podman-compose -f podman-compose.yml down
podman-compose -f podman-compose.yml logs -f <service>
podman-compose -f podman-compose.yml exec <service> bash
```

## 🚨 Security Recommendations

### Production Deployment
1. **Use Rootless Podman**: Always run containers as non-root user
2. **Enable FIPS Mode**: Use FIPS-compliant cryptographic modules
3. **Configure SELinux**: Enable appropriate security contexts
4. **Network Segmentation**: Use dedicated container networks
5. **Regular Updates**: Keep Podman and images updated
6. **Monitoring**: Implement comprehensive logging and monitoring
7. **Backup Strategy**: Regular automated backups with tested recovery

### Access Control
1. **Limit SSH Access**: Use key-based authentication only
2. **Firewall Rules**: Restrict access to necessary ports only
3. **User Permissions**: Follow principle of least privilege
4. **Audit Logging**: Enable comprehensive audit trails

---

## ⚡ Performance Optimization Tips

1. **Storage Driver**: Use `overlay` for better performance
2. **Memory Limits**: Set appropriate container memory limits
3. **CPU Affinity**: Pin containers to specific CPU cores in high-load scenarios
4. **Network Optimization**: Use host networking for high-throughput scenarios (where security permits)
5. **Volume Optimization**: Use tmpfs for temporary data to reduce I/O

---

*For additional support and updates, see the [main documentation](README.md) and [testing reports](tests/)*