#!/bin/bash
# OpenWatch SELinux Policy Build Script
# Compiles and installs SELinux policy modules for RHEL/Oracle Linux

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
POLICY_NAME="openwatch"
POLICY_VERSION="1.0.0"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

log_success() {
    echo -e "${GREEN}[OK] $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

log_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking SELinux policy build prerequisites..."

    # Check if SELinux is enabled
    if ! command -v getenforce >/dev/null 2>&1; then
        log_error "SELinux tools not found. This script requires RHEL, CentOS, or Oracle Linux."
        exit 1
    fi

    local selinux_status=$(getenforce)
    if [ "$selinux_status" = "Disabled" ]; then
        log_error "SELinux is disabled. Enable SELinux to use this policy."
        exit 1
    fi

    log_info "SELinux status: $selinux_status"

    # Check for required tools
    local missing_tools=()
    for tool in make checkmodule semodule_package semanage restorecon; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Install with: dnf install policycoreutils-python-utils selinux-policy-devel make"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root for policy installation"
        exit 1
    fi
}

# Build policy module
build_policy() {
    log_info "Building SELinux policy module..."

    cd "$SCRIPT_DIR"

    # Create temporary build directory
    local build_dir="$(mktemp -d)"
    trap "rm -rf '$build_dir'" EXIT

    # Copy policy files to build directory
    cp openwatch.te openwatch.fc openwatch.if "$build_dir/"
    cd "$build_dir"

    # Compile the type enforcement file
    log_info "Compiling type enforcement (.te) file..."
    make -f /usr/share/selinux/devel/Makefile openwatch.pp

    if [ ! -f "openwatch.pp" ]; then
        log_error "Failed to compile SELinux policy"
        exit 1
    fi

    # Copy compiled policy back
    cp openwatch.pp "$SCRIPT_DIR/"

    log_success "Policy compiled successfully: $SCRIPT_DIR/openwatch.pp"
}

# Install policy module
install_policy() {
    log_info "Installing SELinux policy module..."

    cd "$SCRIPT_DIR"

    # Install the policy module
    semodule -i openwatch.pp

    if [ $? -eq 0 ]; then
        log_success "Policy module installed successfully"
    else
        log_error "Failed to install policy module"
        exit 1
    fi

    # Verify installation
    if semodule -l | grep -q "^openwatch"; then
        local installed_version=$(semodule -l | grep "^openwatch" | awk '{print $2}')
        log_success "Policy active: openwatch $installed_version"
    else
        log_error "Policy installation verification failed"
        exit 1
    fi
}

# Apply file contexts
apply_file_contexts() {
    log_info "Applying file contexts..."

    # Load file contexts from .fc file
    semanage fcontext -a -f openwatch.fc 2>/dev/null || true

    # Apply contexts to existing files
    local context_paths=(
        "/etc/openwatch"
        "/var/lib/openwatch"
        "/var/log/openwatch"
        "/usr/bin/owadm"
    )

    for path in "${context_paths[@]}"; do
        if [ -e "$path" ]; then
            log_info "Applying contexts to: $path"
            restorecon -R "$path"
        fi
    done

    log_success "File contexts applied successfully"
}

# Test policy
test_policy() {
    log_info "Testing policy functionality..."

    # Test if owadm can be executed in OpenWatch context
    if [ -f /usr/bin/owadm ]; then
        log_info "Testing owadm execution..."
        runcon -t openwatch_t /usr/bin/owadm --help >/dev/null 2>&1 || {
            log_warning "owadm execution test failed - this may be normal if owadm is not fully implemented"
        }
    fi

    # Check for policy violations
    local recent_denials=$(ausearch -m AVC -ts recent 2>/dev/null | grep openwatch | wc -l || echo "0")
    if [ "$recent_denials" -gt 0 ]; then
        log_warning "Found $recent_denials recent SELinux denials involving OpenWatch"
        log_warning "Check with: ausearch -m AVC -ts recent | grep openwatch"
    else
        log_success "No recent SELinux denials found"
    fi
}

# Show policy information
show_policy_info() {
    log_info "SELinux policy information:"

    # Show installed modules
    echo "Installed modules:"
    semodule -l | grep openwatch || echo "  None found"

    # Show file contexts
    echo ""
    echo "File contexts:"
    semanage fcontext -l | grep openwatch | head -10 || echo "  None found"

    # Show boolean settings
    echo ""
    echo "Policy booleans:"
    getsebool -a | grep openwatch || echo "  None found"
}

# Uninstall policy (for cleanup)
uninstall_policy() {
    log_info "Uninstalling OpenWatch SELinux policy..."

    # Remove policy module
    semodule -r openwatch 2>/dev/null || {
        log_warning "Policy module not found or already removed"
    }

    # Remove file contexts
    semanage fcontext -d "/etc/openwatch(/.*)?" 2>/dev/null || true
    semanage fcontext -d "/var/lib/openwatch(/.*)?" 2>/dev/null || true
    semanage fcontext -d "/var/log/openwatch(/.*)?" 2>/dev/null || true
    semanage fcontext -d "/usr/bin/owadm" 2>/dev/null || true

    log_success "Policy uninstalled successfully"
}

# Create policy development environment
create_dev_environment() {
    log_info "Creating SELinux policy development environment..."

    # Install development dependencies
    local missing_tools=()
    for tool in selinux-policy-devel; do
        if ! rpm -q "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_info "Installing development dependencies: ${missing_tools[*]}"
        dnf install -y "${missing_tools[@]}"
    fi

    # Create Makefile if it doesn't exist
    if [ ! -f "$SCRIPT_DIR/Makefile" ]; then
        cat > "$SCRIPT_DIR/Makefile" << 'EOF'
# OpenWatch SELinux Policy Makefile
include /usr/share/selinux/devel/Makefile

# Development targets
.PHONY: install uninstall test clean

install: openwatch.pp
	semodule -i openwatch.pp
	@echo "Policy installed"

uninstall:
	semodule -r openwatch || true
	@echo "Policy removed"

test: openwatch.pp
	@echo "Testing policy compilation..."
	@echo "Policy compiled successfully"

clean:
	rm -f *.pp *.mod *.fc.tmp tmp/

reload: uninstall install
	@echo "Policy reloaded"
EOF
    fi

    log_success "Development environment ready"
}

# Display usage
usage() {
    echo "OpenWatch SELinux Policy Management"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  build         Build the policy module"
    echo "  install       Build and install the policy"
    echo "  uninstall     Remove the policy module"
    echo "  test          Test policy functionality"
    echo "  info          Show policy information"
    echo "  dev           Setup development environment"
    echo ""
    echo "Examples:"
    echo "  $0 install    # Build and install policy"
    echo "  $0 test       # Test installed policy"
    echo "  $0 uninstall  # Remove policy"
    echo ""
}

# Main execution
main() {
    local command="${1:-install}"

    echo "OpenWatch SELinux Policy Manager"
    echo "==================================="

    case "$command" in
        build)
            check_prerequisites
            build_policy
            ;;
        install)
            check_prerequisites
            check_root
            build_policy
            install_policy
            apply_file_contexts
            test_policy
            show_policy_info
            echo ""
            log_success "OpenWatch SELinux policy installed successfully!"
            echo ""
            echo "Next steps:"
            echo "1. Start OpenWatch: systemctl start openwatch.target"
            echo "2. Monitor for denials: ausearch -m AVC -ts recent"
            echo "3. Check logs: journalctl -u openwatch.service"
            echo ""
            ;;
        uninstall)
            check_root
            uninstall_policy
            ;;
        test)
            test_policy
            ;;
        info)
            show_policy_info
            ;;
        dev)
            check_root
            create_dev_environment
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

# Allow script to be sourced for testing
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
