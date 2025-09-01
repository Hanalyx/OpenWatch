# OpenWatch Configuration System

Comprehensive configuration management for OpenWatch deployment across enterprise Linux distributions.

## Overview

The OpenWatch configuration system provides:
- **Unified configuration** via `/etc/openwatch/ow.yml`
- **Secure secrets management** via `/etc/openwatch/secrets.env`
- **Runtime abstraction** for Docker/Podman
- **Environment variable substitution**
- **Schema validation** for configuration integrity
- **Platform-specific defaults** for RHEL/Ubuntu

## Configuration Files

### Main Configuration: `ow.yml`

The primary configuration file located at `/etc/openwatch/ow.yml` controls all aspects of OpenWatch:

```yaml
runtime:
  engine: "auto"        # auto-detect, docker, or podman
  rootless: true        # enhanced security

database:
  host: "localhost"
  port: 5432
  ssl_mode: "require"   # enforce encryption

web:
  port: 3001
  ssl:
    enabled: true
    cert_path: "/etc/ssl/certs/openwatch.crt"
```

### Secrets File: `secrets.env`

Sensitive values are stored separately in `/etc/openwatch/secrets.env`:

```bash
# Database credentials
POSTGRES_PASSWORD=secure_password_here

# Application secrets
SECRET_KEY=64_character_secret_key
MASTER_KEY=32_character_master_key

# JWT keys (auto-generated)
JWT_PRIVATE_KEY_PATH=/etc/openwatch/jwt_private.pem
JWT_PUBLIC_KEY_PATH=/etc/openwatch/jwt_public.pem
```

**Security Requirements**:
- File permissions: `600` (read/write owner only)
- Owner: `openwatch:openwatch`
- Never commit to version control

## Configuration Validation

### Using owadm

Validate configuration before starting services:

```bash
# Full validation
owadm validate-config

# Database only
owadm validate-config --database-only

# Custom config path
owadm validate-config --config /path/to/ow.yml
```

### Validation Checks

The validator performs these checks:

1. **Syntax validation**: Valid YAML structure
2. **Schema compliance**: Required fields present
3. **Runtime availability**: Docker/Podman installed
4. **File permissions**: Secure secrets.env
5. **SSL certificates**: Files exist if SSL enabled
6. **Port conflicts**: Valid port ranges
7. **Default passwords**: No CHANGEME values

## Environment Variables

### Variable Substitution

Configuration supports environment variable expansion:

```yaml
database:
  host: "${DB_HOST:-localhost}"
  port: ${DB_PORT:-5432}
```

### Runtime Environment

Set via systemd service files or container environment:

```bash
# Override database host
DB_HOST=db.example.com

# Override web port
WEB_PORT=8443

# Enable development mode
DEV_MODE=true
```

## Platform-Specific Configuration

### RHEL/Oracle Linux

Default configuration for RHEL-based systems:

```yaml
runtime:
  engine: "podman"      # Podman is default
  rootless: true        # SELinux compatible

rhel:
  selinux_enabled: true
  fips_crypto: false    # Enable for FIPS compliance
```

### Ubuntu

Default configuration for Ubuntu systems:

```yaml
runtime:
  engine: "docker"      # Docker is default
  rootless: false       # Docker typically runs as root

ubuntu:
  apparmor_enabled: true
  ufw_integration: false
```

## Advanced Configuration

### High Availability

Configure for HA deployments:

```yaml
database:
  host: "pgpool.example.com"
  pool:
    max_connections: 50
    min_connections: 10

redis:
  sentinel:
    enabled: true
    master_name: "mymaster"
    nodes:
      - "sentinel1.example.com:26379"
      - "sentinel2.example.com:26379"
      - "sentinel3.example.com:26379"
```

### LDAP Integration

Enable enterprise authentication:

```yaml
integrations:
  ldap:
    enabled: true
    host: "ldap.example.com"
    port: 636
    use_tls: true
    bind_dn: "cn=openwatch,ou=services,dc=example,dc=com"
    base_dn: "ou=users,dc=example,dc=com"
    user_filter: "(uid={username})"
```

### Monitoring

Enable Prometheus metrics and tracing:

```yaml
monitoring:
  metrics:
    enabled: true
    port: 9090
    detailed_histograms: true
    
  tracing:
    enabled: true
    endpoint: "http://jaeger:4318"
    sample_rate: 0.1
```

## Configuration Management

### Initial Setup

During package installation:

1. Default `ow.yml` created with platform defaults
2. `secrets.env` generated with secure random values
3. JWT key pair generated
4. File permissions set appropriately

### Updates

Modify configuration:

```bash
# Edit configuration
sudo vi /etc/openwatch/ow.yml

# Validate changes
owadm validate-config

# Restart services
sudo systemctl restart openwatch
```

### Backup

Important files to backup:

```bash
/etc/openwatch/ow.yml
/etc/openwatch/secrets.env
/etc/openwatch/jwt_private.pem
/etc/openwatch/jwt_public.pem
/etc/openwatch/ssh/
```

## Troubleshooting

### Common Issues

**Invalid configuration**:
```bash
owadm validate-config
# Shows specific validation errors
```

**Permission denied**:
```bash
ls -la /etc/openwatch/
# Check ownership and permissions
sudo chown -R openwatch:openwatch /etc/openwatch/
sudo chmod 600 /etc/openwatch/secrets.env
```

**Runtime not found**:
```bash
# Install runtime
sudo dnf install podman podman-compose  # RHEL
sudo apt install docker.io docker-compose-plugin  # Ubuntu
```

### Debug Mode

Enable verbose logging:

```yaml
logging:
  level: "DEBUG"
  include_caller: true
  include_stacktrace: true
```

### Configuration Dumps

Export effective configuration:

```bash
# Show computed configuration
owadm config show

# Export with defaults
owadm config export --with-defaults > config-full.yml
```

## Security Best Practices

1. **Secrets Management**:
   - Use strong, unique passwords
   - Rotate secrets regularly
   - Never store secrets in main config
   - Use external secret managers in production

2. **File Permissions**:
   - `ow.yml`: 640 (openwatch:openwatch)
   - `secrets.env`: 600 (openwatch:openwatch)
   - SSH keys: 600 (openwatch:openwatch)

3. **Network Security**:
   - Enable SSL for web interface
   - Use database SSL connections
   - Implement firewall rules
   - Bind to specific interfaces

4. **Runtime Security**:
   - Prefer rootless containers
   - Enable SELinux/AppArmor
   - Use FIPS mode if required
   - Regular security updates

---

*Last updated: 2025-08-31*