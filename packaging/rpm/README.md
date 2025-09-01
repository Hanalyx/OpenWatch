# OpenWatch RPM Packaging

Enterprise RPM packages for RHEL 8+, Oracle Linux 8+, and compatible distributions.

## Building RPM Packages

### Prerequisites

Install build dependencies:
```bash
# RHEL/Oracle Linux/Rocky Linux
sudo dnf install rpm-build rpmdevtools golang git

# CentOS Stream
sudo dnf install rpm-build rpmdevtools golang git
```

### Build Process

```bash
# Build RPM packages
cd /home/rracine/hanalyx/openwatch/packaging/rpm
./build-rpm.sh
```

This creates:
- `openwatch-{version}.x86_64.rpm` - Main package
- `openwatch-{version}.src.rpm` - Source package

### Installation

```bash
# Install OpenWatch
sudo dnf install ./dist/openwatch-*.rpm

# Configure
sudo vi /etc/openwatch/ow.yml

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
| `/etc/systemd/system/openwatch.service` | Main service unit | 644 |
| `/etc/systemd/system/openwatch-db.service` | Database service unit | 644 |
| `/usr/share/openwatch/compose/` | Container orchestration files | 644 |
| `/var/lib/openwatch/` | Application data directory | 755 (openwatch:openwatch) |
| `/var/log/openwatch/` | Log directory | 755 (openwatch:openwatch) |

### System Integration

- **User Account**: Creates `openwatch` system user
- **Groups**: Adds to `podman`/`docker` groups if available
- **SELinux**: Configures contexts for enforcing mode
- **Systemd**: Installs service units with security hardening
- **Secrets**: Auto-generates secure passwords and JWT keys

### Default Configuration

- **Runtime**: Podman (RHEL/Oracle Linux default)
- **Security**: Rootless containers, FIPS-ready
- **Network**: Port 3001 (configurable)
- **SSL**: Disabled by default (enable in production)

## Container Runtime Support

The package supports both Podman and Docker:

- **Podman** (default): Recommended for RHEL/Oracle environments
- **Docker**: Alternative runtime option
- **Auto-detection**: Runtime automatically detected if set to "auto"

Configure in `/etc/openwatch/ow.yml`:
```yaml
runtime:
  engine: "podman"    # podman, docker, auto
  rootless: true      # Use rootless containers
```

## Security Features

### FIPS Compliance
Ready for FIPS 140-2 environments:
```yaml
security:
  fips_mode: true
```

### SELinux Integration
- Automatic context configuration
- Compatible with enforcing mode
- Container access policies included

### Secret Management
- Auto-generated secure passwords
- JWT RSA-2048 key pairs
- Proper file permissions (600)
- Separation from main configuration

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Check SELinux contexts
ls -Z /etc/openwatch/
sudo restorecon -R /etc/openwatch/
```

**Container Runtime Not Found**
```bash
# Install Podman (recommended)
sudo dnf install podman podman-compose

# Or install Docker
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
sudo dnf install docker-ce docker-compose-plugin
```

**Service Won't Start**
```bash
# Check configuration
owadm validate-config

# Check logs
journalctl -u openwatch.service -f
```

### Debugging

Enable verbose mode:
```bash
owadm start --verbose
owadm status --verbose
```

Check service status:
```bash
systemctl status openwatch
systemctl status openwatch-db
```

## Development

### Testing RPM

Test in clean environment:
```bash
# Create test container
podman run -it --rm registry.redhat.io/rhel8/rhel:latest bash

# Install package
dnf install ./openwatch-*.rpm

# Test functionality
owadm --help
systemctl status openwatch
```

### Package Validation

```bash
# Check package contents
rpm -qlp openwatch-*.rpm

# Verify dependencies
rpm -qRp openwatch-*.rpm

# Check file permissions
rpm -qlvp openwatch-*.rpm
```

---

*Last updated: 2025-08-31*