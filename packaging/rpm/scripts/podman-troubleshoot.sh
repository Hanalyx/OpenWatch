#!/bin/bash
# OpenWatch Podman Troubleshooting Script
# Diagnoses and fixes common Podman container build issues

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

echo "OpenWatch Podman Troubleshooting"
echo "================================"
echo ""

# Function to detect issues
detect_issues() {
    local issues=()

    # Check Podman version
    if command -v podman &>/dev/null; then
        local podman_version=$(podman version --format '{{.Client.Version}}')
        log_info "Podman version: $podman_version"
    else
        issues+=("Podman not installed")
    fi

    # Check SELinux
    if command -v getenforce &>/dev/null; then
        local selinux_status=$(getenforce 2>/dev/null || echo "Unknown")
        log_info "SELinux status: $selinux_status"

        if [[ "$selinux_status" == "Enforcing" ]]; then
            # Check container contexts
            if ! semanage fcontext -l | grep -q container_file_t; then
                issues+=("SELinux container contexts not configured")
            fi
        fi
    fi

    # Check storage driver
    if [[ -f /etc/containers/storage.conf ]]; then
        local storage_driver=$(grep "^driver" /etc/containers/storage.conf | cut -d'"' -f2)
        log_info "Storage driver: $storage_driver"

        if [[ "$storage_driver" != "vfs" ]]; then
            log_warning "Non-VFS storage driver may cause permission issues"
        fi
    else
        issues+=("Podman storage not configured")
    fi

    # Check kernel parameters
    if [[ -f /proc/sys/kernel/unprivileged_userns_clone ]]; then
        local userns_clone=$(cat /proc/sys/kernel/unprivileged_userns_clone)
        if [[ "$userns_clone" == "0" ]]; then
            issues+=("Unprivileged user namespaces disabled")
        fi
    fi

    # Check systemd service overrides
    if [[ -d /etc/systemd/system/openwatch-db.service.d ]]; then
        log_info "Systemd overrides detected"
    else
        log_warning "No systemd overrides for container permissions"
    fi

    # Return issues
    if [[ ${#issues[@]} -eq 0 ]]; then
        log_success "No issues detected"
        return 0
    else
        log_warning "Issues detected:"
        for issue in "${issues[@]}"; do
            echo "  - $issue"
        done
        return 1
    fi
}

# Quick fix function
quick_fix() {
    log_info "Applying quick fixes..."

    # 1. Enable user namespaces
    if [[ -f /proc/sys/kernel/unprivileged_userns_clone ]]; then
        echo 1 > /proc/sys/kernel/unprivileged_userns_clone
        log_success "Enabled unprivileged user namespaces"
    fi

    # 2. Configure VFS storage driver
    mkdir -p /etc/containers
    cat > /etc/containers/storage.conf << 'EOF'
[storage]
driver = "vfs"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"

[storage.options.vfs]
ignore_chown_errors = "true"
EOF
    log_success "Configured VFS storage driver"

    # 3. Reset Podman storage
    log_warning "Resetting Podman storage..."
    podman system reset -f

    # 4. Create systemd overrides
    mkdir -p /etc/systemd/system/openwatch-db.service.d
    cat > /etc/systemd/system/openwatch-db.service.d/podman-fix.conf << 'EOF'
[Service]
# Allow container operations
ProtectSystem=false
PrivateDevices=no
NoNewPrivileges=no
User=root
Group=root
EOF

    # Apply to all services
    for svc in frontend worker redis; do
        mkdir -p /etc/systemd/system/openwatch-${svc}.service.d
        cp /etc/systemd/system/openwatch-db.service.d/podman-fix.conf \
           /etc/systemd/system/openwatch-${svc}.service.d/
    done

    systemctl daemon-reload
    log_success "Updated systemd service configurations"

    # 5. SELinux fixes (if applicable)
    if command -v getenforce &>/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
        semanage fcontext -a -t container_file_t "/var/lib/containers(/.*)?" 2>/dev/null || true
        restorecon -Rv /var/lib/containers
        log_success "SELinux contexts configured"
    fi
}

# Main menu
echo "Choose an option:"
echo "1. Detect issues"
echo "2. Apply quick fixes"
echo "3. Full diagnostic report"
echo "4. Exit"
echo ""

read -p "Enter your choice (1-4): " choice

case $choice in
    1)
        detect_issues
        ;;
    2)
        quick_fix
        echo ""
        log_success "Quick fixes applied!"
        log_info "Try running: systemctl restart openwatch"
        ;;
    3)
        log_info "Generating diagnostic report..."
        {
            echo "=== OpenWatch Podman Diagnostic Report ==="
            echo "Generated: $(date)"
            echo ""
            echo "=== System Information ==="
            uname -a
            echo ""
            echo "=== Podman Version ==="
            podman version || echo "Podman not installed"
            echo ""
            echo "=== Storage Configuration ==="
            cat /etc/containers/storage.conf 2>/dev/null || echo "No storage config"
            echo ""
            echo "=== SELinux Status ==="
            getenforce 2>/dev/null || echo "SELinux not available"
            echo ""
            echo "=== Kernel Parameters ==="
            sysctl kernel.unprivileged_userns_clone 2>/dev/null || echo "Not set"
            sysctl user.max_user_namespaces 2>/dev/null || echo "Not set"
            echo ""
            echo "=== Recent Podman Errors ==="
            journalctl -u openwatch-db -n 50 | grep -i "error\|failed" | tail -20
        } > /tmp/openwatch-podman-diagnostic.txt
        log_success "Report saved to: /tmp/openwatch-podman-diagnostic.txt"
        ;;
    4)
        exit 0
        ;;
    *)
        log_error "Invalid choice"
        exit 1
        ;;
esac
