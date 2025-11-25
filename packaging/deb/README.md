# OpenWatch DEB Packaging

Enterprise DEB packages for Ubuntu 24.04 LTS and newer distributions.

## Building DEB Packages

### Prerequisites

Install build dependencies:
```bash
# Ubuntu 24.04+
sudo apt update
sudo apt install build-essential golang git fakeroot

# Optional: Package validation
sudo apt install lintian
```

### Build Process

```bash
# Build DEB package
cd /home/rracine/hanalyx/openwatch/packaging/deb
./build-deb.sh
```

This creates:
- `openwatch_{version}_amd64.deb` - Main package

### Installation

```bash
# Install OpenWatch
sudo apt install ./dist/openwatch_*.deb

# Configure
sudo nano /etc/openwatch/ow.yml

# Start services
sudo systemctl start openwatch
```

## Package Contents

### Installed Files

| Path | Purpose | Permissions |
|------|---------|-------------|
| `/usr/bin/owadm` | CLI management tool | 755 |
| `/etc/openwatch/ow.yml` | Main configuration | 640 (openwatch:openwatch) |
| `/etc/openwatch/secrets.env` | Sensitive configuration | 600 (openwatch:openwatch) |
| `/usr/share/openwatch/systemd/` | Service unit templates | 644 |
| `/usr/share/openwatch/compose/` | Container orchestration files | 644 |
| `/var/lib/openwatch/` | Application data directory | 755 (openwatch:openwatch) |
| `/var/log/openwatch/` | Log directory | 755 (openwatch:openwatch) |

### System Integration

- **User Account**: Creates `openwatch` system user
- **Groups**: Adds to `docker` group (if available)
- **AppArmor**: Configures security profile (complain mode)
- **Systemd**: Installs service units with security hardening
- **Secrets**: Auto-generates secure passwords and JWT keys
- **Logging**: Configures logrotate for automatic rotation

### Default Configuration

- **Runtime**: Docker (Ubuntu default)
- **Security**: AppArmor integration, secure defaults
- **Network**: Port 3001 (configurable)
- **SSL**: Disabled by default (enable in production)

## Container Runtime Support

The package supports both Docker and Podman:

- **Docker** (default): Recommended for Ubuntu environments
- **Podman**: Alternative runtime option
- **Auto-detection**: Runtime automatically detected if set to "auto"

Configure in `/etc/openwatch/ow.yml`:
```yaml
runtime:
  engine: "docker"    # docker, podman, auto
  rootless: false     # Docker typically runs as root
```

## Security Features

### AppArmor Integration
Ubuntu-specific security enhancement:
```bash
# Check AppArmor status
sudo aa-status | grep openwatch

# Switch to enforce mode (after testing)
sudo aa-enforce /etc/apparmor.d/openwatch-containers
```

### UFW Firewall
If using Ubuntu Firewall:
```bash
# Allow OpenWatch web interface
sudo ufw allow 3001/tcp comment 'OpenWatch Web UI'

# Allow from specific network only
sudo ufw allow from 192.168.1.0/24 to any port 3001
```

### Secret Management
- Auto-generated secure passwords
- JWT RSA-2048 key pairs
- Proper file permissions (600)
- Separation from main configuration

## Package Management

### Update Package
```bash
# Install new version (preserves config)
sudo apt install ./openwatch_new_version.deb
```

### Remove Package
```bash
# Remove package (keeps config and data)
sudo apt remove openwatch

# Purge package (removes config, keeps data)
sudo apt purge openwatch

# Complete removal including data
OPENWATCH_PURGE_DATA=yes sudo apt purge openwatch
```

### Package Information
```bash
# Show installed version
dpkg -l openwatch

# Show package contents
dpkg -L openwatch

# Show package details
apt show openwatch
```

## Troubleshooting

### Common Issues

**Docker Not Found**
```bash
# Install Docker
sudo apt update
sudo apt install docker.io docker-compose-plugin

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

**Permission Denied**
```bash
# Check AppArmor status
sudo aa-status

# Temporarily disable for testing
sudo aa-complain /etc/apparmor.d/openwatch-containers
```

**Service Won't Start**
```bash
# Check configuration
owadm validate-config

# Check logs
journalctl -u openwatch.service -f
sudo tail -f /var/log/openwatch/openwatch.log
```

### Debugging

Enable verbose mode:
```bash
owadm start --verbose
owadm status --verbose
```

Check service dependencies:
```bash
systemctl list-dependencies openwatch.service
systemctl status openwatch-db.service
```

## Development

### Testing DEB Package

Test in clean environment:
```bash
# Create test container
docker run -it --rm ubuntu:24.04 bash

# Inside container
apt update
apt install ./openwatch-*.deb

# Test functionality
owadm --help
systemctl status openwatch
```

### Building Custom Packages

Modify package before building:
```bash
# Edit control files
nano DEBIAN/control
nano DEBIAN/postinst

# Rebuild
./build-deb.sh
```

### Package Validation

```bash
# Validate package structure
dpkg-deb --info openwatch_*.deb
dpkg-deb --contents openwatch_*.deb

# Check with lintian
lintian --info openwatch_*.deb
```

---

*Last updated: 2025-08-31*
