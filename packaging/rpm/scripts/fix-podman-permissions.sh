#!/bin/bash
# OpenWatch Podman Permission Fix Script
# Resolves container build failures due to permission issues

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Detect SELinux status
check_selinux() {
    if command -v getenforce &> /dev/null; then
        local selinux_status=$(getenforce 2>/dev/null || echo "Disabled")
        log_info "SELinux status: $selinux_status"
        echo "$selinux_status"
    else
        log_info "SELinux not installed"
        echo "Not Installed"
    fi
}

# Fix Podman storage issues
fix_podman_storage() {
    log_info "Fixing Podman storage configuration..."

    # Stop all OpenWatch services first
    log_info "Stopping OpenWatch services..."
    systemctl stop openwatch.target 2>/dev/null || true

    # Reset Podman storage if it exists
    if [[ -d /var/lib/containers/storage ]]; then
        log_warning "Resetting Podman storage (this will remove all containers/images)"
        read -p "Continue? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            podman system reset --force
            log_success "Podman storage reset complete"
        else
            log_info "Skipping Podman storage reset"
        fi
    fi

    # Create proper storage directories
    log_info "Creating Podman storage directories..."
    mkdir -p /var/lib/containers/storage
    mkdir -p /var/lib/containers/storage/tmp

    # Set permissions for openwatch user
    if id "openwatch" &>/dev/null; then
        chown -R openwatch:openwatch /var/lib/containers
        log_success "Storage permissions set for openwatch user"
    fi
}

# Configure SELinux contexts
configure_selinux() {
    local selinux_status="$1"

    if [[ "$selinux_status" == "Enforcing" ]] || [[ "$selinux_status" == "Permissive" ]]; then
        log_info "Configuring SELinux contexts for containers..."

        # Set container storage contexts
        semanage fcontext -a -t container_file_t "/var/lib/containers(/.*)?" 2>/dev/null || \
            semanage fcontext -m -t container_file_t "/var/lib/containers(/.*)?" 2>/dev/null || \
            log_warning "Failed to set SELinux context (may already exist)"

        # Apply contexts
        restorecon -Rv /var/lib/containers

        # Allow container operations
        setsebool -P container_manage_cgroup true 2>/dev/null || true

        log_success "SELinux contexts configured"
    else
        log_info "SELinux not active, skipping context configuration"
    fi
}

# Configure sysctl for unprivileged containers
configure_sysctl() {
    log_info "Configuring kernel parameters for containers..."

    # Enable unprivileged user namespaces
    echo "kernel.unprivileged_userns_clone=1" > /etc/sysctl.d/99-openwatch-containers.conf

    # Set max user namespaces
    echo "user.max_user_namespaces=28633" >> /etc/sysctl.d/99-openwatch-containers.conf

    # Apply settings
    sysctl -p /etc/sysctl.d/99-openwatch-containers.conf

    log_success "Kernel parameters configured"
}

# Update systemd service files
update_systemd_services() {
    log_info "Updating systemd service permissions..."

    # Create override directory
    mkdir -p /etc/systemd/system/openwatch-db.service.d

    # Create override for database service
    cat > /etc/systemd/system/openwatch-db.service.d/container-permissions.conf << 'EOF'
# Override for container permissions
[Service]
# Run as root for container operations
User=root
Group=root

# Relax security restrictions for containers
ProtectSystem=false
PrivateDevices=no
DevicePolicy=auto
NoNewPrivileges=false

# Additional capabilities for container operations
AmbientCapabilities=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_NET_ADMIN CAP_NET_RAW

# Allow system calls needed for containers
SystemCallFilter=@system-service @mount @chown
SystemCallErrorNumber=EPERM

# Storage access
ReadWritePaths=/var/lib/containers /var/lib/openwatch /var/log/openwatch /run/containers
EOF

    # Create similar overrides for other services
    for service in frontend worker redis; do
        mkdir -p "/etc/systemd/system/openwatch-${service}.service.d"
        cp /etc/systemd/system/openwatch-db.service.d/container-permissions.conf \
           "/etc/systemd/system/openwatch-${service}.service.d/"
    done

    # Reload systemd
    systemctl daemon-reload

    log_success "Systemd services updated"
}

# Configure Podman for the openwatch user (alternative approach)
configure_podman_rootless() {
    log_info "Configuring rootless Podman for openwatch user..."

    if id "openwatch" &>/dev/null; then
        # Enable lingering for the user
        loginctl enable-linger openwatch

        # Set subuid/subgid mappings
        if ! grep -q "^openwatch:" /etc/subuid; then
            echo "openwatch:100000:65536" >> /etc/subuid
        fi

        if ! grep -q "^openwatch:" /etc/subgid; then
            echo "openwatch:100000:65536" >> /etc/subgid
        fi

        # Create XDG runtime directory
        mkdir -p /run/user/$(id -u openwatch)
        chown openwatch:openwatch /run/user/$(id -u openwatch)

        log_success "Rootless Podman configured"
    else
        log_warning "openwatch user not found, skipping rootless configuration"
    fi
}

# Create Podman storage configuration
create_storage_conf() {
    log_info "Creating Podman storage configuration..."

    mkdir -p /etc/containers

    # Create storage.conf with vfs driver (most compatible)
    cat > /etc/containers/storage.conf << 'EOF'
[storage]
driver = "vfs"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"

[storage.options]
pull_options = {enable_partial_images = "true", use_hard_links = "false", ostree_repos=""}

[storage.options.vfs]
ignore_chown_errors = "true"
EOF

    log_success "Storage configuration created"
}

# Main execution
main() {
    log_info "OpenWatch Podman Permission Fix Script"
    log_info "======================================"

    check_root

    # Check SELinux status
    selinux_status=$(check_selinux)

    # Apply fixes
    fix_podman_storage
    configure_selinux "$selinux_status"
    configure_sysctl
    create_storage_conf
    update_systemd_services
    configure_podman_rootless

    log_success "Podman permission fixes applied!"
    log_info ""
    log_info "Next steps:"
    log_info "1. Start OpenWatch: systemctl start openwatch"
    log_info "2. Check status: systemctl status openwatch-db"
    log_info "3. View logs: journalctl -u openwatch-db -f"
    log_info ""
    log_warning "Note: If issues persist, try running owadm as root directly:"
    log_info "   sudo /usr/bin/owadm start"
}

# Run main function
main "$@"
