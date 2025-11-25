# OpenWatch SELinux Integration

SELinux policy modules for secure OpenWatch deployment on RHEL 8+, Oracle Linux 8+, and compatible distributions.

## Overview

The OpenWatch SELinux policy provides:
- **Container Runtime Support**: Podman and Docker integration
- **Rootless Operation**: Enhanced security for containerized workloads
- **File System Protection**: Proper contexts for all OpenWatch files
- **Network Access Control**: Scanning and web interface permissions
- **Audit Integration**: Comprehensive access logging

## Policy Components

### Core Files

| File | Purpose |
|------|---------|
| `openwatch.te` | Type enforcement rules and permissions |
| `openwatch.fc` | File context definitions |
| `openwatch.if` | Interface definitions for other modules |
| `build-policy.sh` | Policy compilation and installation |
| `openwatch-troubleshooting.sh` | Diagnostic and repair tools |

### Security Domains

The policy defines these SELinux types:

- **`openwatch_t`**: Main OpenWatch process domain
- **`openwatch_conf_t`**: Configuration files
- **`openwatch_secret_t`**: Sensitive files (secrets, keys)
- **`openwatch_var_lib_t`**: Data directories
- **`openwatch_log_t`**: Log files
- **`openwatch_ssh_key_t`**: SSH keys for scanning
- **`openwatch_scap_content_t`**: SCAP content files

## Installation

### Automatic Installation

SELinux policy is automatically installed with RPM packages:

```bash
# Install OpenWatch (includes SELinux policy)
sudo dnf install openwatch

# Policy is automatically installed and activated
```

### Manual Installation

For development or custom installations:

```bash
# Build and install policy
cd packaging/selinux
sudo ./build-policy.sh install

# Verify installation
sudo ./build-policy.sh info
```

## Policy Management

### Basic Operations

```bash
# Check policy status
sudo ./openwatch-troubleshooting.sh status

# Test functionality
sudo ./openwatch-troubleshooting.sh test

# Check for denials
sudo ./openwatch-troubleshooting.sh denials

# Fix context issues
sudo ./openwatch-troubleshooting.sh fix
```

### Advanced Operations

```bash
# Uninstall policy
sudo ./build-policy.sh uninstall

# Reinstall policy
sudo ./build-policy.sh install

# Setup development environment
sudo ./build-policy.sh dev
```

## Troubleshooting

### Common Issues

#### 1. Service Won't Start

**Symptoms**: OpenWatch services fail to start with "Permission denied"

**Diagnosis**:
```bash
sudo ./openwatch-troubleshooting.sh status
sudo ausearch -m AVC -ts recent | grep openwatch
```

**Solutions**:
```bash
# Fix file contexts
sudo restorecon -R /etc/openwatch/ /usr/bin/owadm

# Check for missing policy
sudo semodule -l | grep openwatch

# Reinstall if missing
sudo ./build-policy.sh install
```

#### 2. Container Operations Fail

**Symptoms**: Container start/stop operations denied by SELinux

**Diagnosis**:
```bash
sudo ./openwatch-troubleshooting.sh test
journalctl -u openwatch.service | grep -i selinux
```

**Solutions**:
```bash
# Check container runtime contexts
sudo ps -eZ | grep -E "(podman|docker)"

# Ensure container runtime access
sudo setsebool -P container_manage_cgroup on
```

#### 3. SSH Scanning Fails

**Symptoms**: Remote host scanning fails with access denied

**Diagnosis**:
```bash
ls -Z /etc/openwatch/ssh/
sudo ausearch -m AVC -ts recent | grep ssh
```

**Solutions**:
```bash
# Fix SSH key contexts
sudo chcon -R -t openwatch_ssh_key_t /etc/openwatch/ssh/

# Verify SSH permissions
sudo -u openwatch ssh-keygen -t rsa -f /etc/openwatch/ssh/test_key -N ""
```

#### 4. Log Access Denied

**Symptoms**: Cannot write to log files

**Solutions**:
```bash
# Fix log directory contexts
sudo restorecon -R /var/log/openwatch/

# Ensure proper ownership
sudo chown -R openwatch:openwatch /var/log/openwatch/
```

### Denial Analysis

#### View Recent Denials
```bash
# Show all recent denials
sudo ausearch -m AVC -ts recent

# OpenWatch-specific denials
sudo ausearch -m AVC -ts recent | grep openwatch

# Pretty format with sealert
sudo sealert -a /var/log/audit/audit.log
```

#### Generate Policy Fixes
```bash
# Analyze denials and suggest fixes
sudo ./openwatch-troubleshooting.sh analyze

# Generate policy rules
sudo audit2allow -a | grep -A 10 -B 5 openwatch

# Create local policy module for quick fixes
sudo audit2allow -a -M openwatch_local
sudo semodule -i openwatch_local.pp
```

### Development Mode

For development environments, enable permissive mode:

```bash
# Enable development mode (makes OpenWatch domain permissive)
sudo ./openwatch-troubleshooting.sh dev-enable

# Disable development mode (restore enforcement)
sudo ./openwatch-troubleshooting.sh dev-disable
```

**Warning**: Development mode reduces security. Never use in production.

## Policy Customization

### Adding Custom Rules

To add custom SELinux rules:

1. **Edit Policy**: Modify `openwatch.te`
2. **Rebuild**: Run `sudo ./build-policy.sh install`
3. **Test**: Check with `sudo ./openwatch-troubleshooting.sh test`

Example custom rule:
```selinux
# Allow OpenWatch to read custom config directory
allow openwatch_t custom_config_t:file read;
```

### Platform-Specific Rules

The policy includes conditional rules for different distributions:

```selinux
# RHEL/Oracle Linux specific
ifdef(`distro_rhel',`
    # Podman rootless containers
    allow openwatch_t self:user_namespace create;
')

# Ubuntu specific (if needed)
ifdef(`distro_ubuntu',`
    # Docker daemon socket access
    allow openwatch_t container_var_run_t:sock_file rw_file_perms;
')
```

### Custom File Contexts

Add custom file contexts to `openwatch.fc`:

```
# Custom SCAP content location
/opt/scap-content(/.*)?    gen_context(system_u:object_r:openwatch_scap_content_t,s0)

# Custom certificate location
/etc/openwatch/certs(/.*)?    gen_context(system_u:object_r:cert_t,s0)
```

## Security Considerations

### Principle of Least Privilege

The policy grants minimal permissions required for operation:

- **File Access**: Only necessary directories accessible
- **Network Access**: Limited to scanning and web ports
- **Process Capabilities**: Minimal capability set
- **Container Access**: Controlled runtime interaction

### Security Boundaries

Strong security boundaries enforced:

```selinux
# Explicitly deny dangerous operations
neverallow openwatch_t { security_t selinux_config_t }:file write;
neverallow openwatch_t shadow_t:file { read write };
neverallow openwatch_t kernel_module_t:system module_load;
```

### Audit Trail

All OpenWatch operations are audited through SELinux:
- File access events
- Network connections
- Process executions
- Container operations

## Performance Considerations

### Policy Size

The OpenWatch policy is designed for minimal performance impact:
- Focused rule set (no broad allow rules)
- Efficient type transitions
- Minimal boolean conditions

### Optimization

For high-performance environments:

```bash
# Disable unnecessary audit logging
sudo semodule -d auditadm

# Optimize policy compilation
sudo semodule -B
```

## Integration with Other Security Tools

### Container Security

Works with container security tools:
- **Podman**: Full rootless support
- **Docker**: Secure daemon integration
- **CRI-O**: Compatible with Kubernetes deployments

### System Security

Integrates with RHEL/Oracle Linux security features:
- **FIPS Mode**: Compatible with FIPS 140-2
- **System Crypto Policy**: Respects system-wide crypto settings
- **Audit Framework**: Full auditd integration

---

*Last updated: 2025-08-31*
