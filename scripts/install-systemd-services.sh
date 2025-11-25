#!/bin/bash
# OpenWatch Systemd Service Installation Script
# Install and configure systemd service units

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SYSTEMD_SOURCE_DIR="$PROJECT_ROOT/packaging/systemd"
SYSTEMD_TARGET_DIR="/etc/systemd/system"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO] $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

log_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Install service files
install_service_files() {
    log_info "Installing systemd service files..."

    # Copy service files
    for service_file in "$SYSTEMD_SOURCE_DIR"/*.service "$SYSTEMD_SOURCE_DIR"/*.target "$SYSTEMD_SOURCE_DIR"/*.timer; do
        if [ -f "$service_file" ]; then
            local basename=$(basename "$service_file")
            log_info "Installing $basename"
            cp "$service_file" "$SYSTEMD_TARGET_DIR/"
            chmod 644 "$SYSTEMD_TARGET_DIR/$basename"
        fi
    done

    log_info "Service files installed successfully"
}

# Reload systemd
reload_systemd() {
    log_info "Reloading systemd daemon..."
    systemctl daemon-reload
    log_info "Systemd daemon reloaded"
}

# Enable services
enable_services() {
    log_info "Enabling OpenWatch services..."

    # Enable target and main services
    systemctl enable openwatch.target
    systemctl enable openwatch.service
    systemctl enable openwatch-db.service
    systemctl enable openwatch-redis.service
    systemctl enable openwatch-worker.service
    systemctl enable openwatch-frontend.service

    # Enable timers
    systemctl enable openwatch-backup.timer
    systemctl enable openwatch-maintenance.timer

    log_info "Services enabled successfully"
}

# Validate installation
validate_installation() {
    log_info "Validating service installation..."

    local services=(
        "openwatch.target"
        "openwatch.service"
        "openwatch-db.service"
        "openwatch-redis.service"
        "openwatch-worker.service"
        "openwatch-frontend.service"
        "openwatch-backup.service"
        "openwatch-backup.timer"
        "openwatch-maintenance.service"
        "openwatch-maintenance.timer"
    )

    local failed_services=()

    for service in "${services[@]}"; do
        if ! systemctl is-enabled "$service" >/dev/null 2>&1; then
            failed_services+=("$service")
        fi
    done

    if [ ${#failed_services[@]} -eq 0 ]; then
        log_info "All services validated successfully"
    else
        log_error "Failed to enable services: ${failed_services[*]}"
        return 1
    fi
}

# Show next steps
show_next_steps() {
    echo ""
    log_info "OpenWatch systemd services installed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Configure OpenWatch: /etc/openwatch/ow.yml"
    echo "2. Start services: systemctl start openwatch.target"
    echo "3. Check status: systemctl status openwatch.target"
    echo "4. View logs: journalctl -u openwatch.service -f"
    echo ""
    echo "Service management commands:"
    echo "  Start all:    systemctl start openwatch.target"
    echo "  Stop all:     systemctl stop openwatch.target"
    echo "  Restart all:  systemctl restart openwatch.target"
    echo "  Status:       systemctl status openwatch.target"
    echo ""
    echo "Individual services:"
    echo "  Database:     systemctl start openwatch-db.service"
    echo "  Redis:        systemctl start openwatch-redis.service"
    echo "  Workers:      systemctl start openwatch-worker.service"
    echo "  Frontend:     systemctl start openwatch-frontend.service"
    echo ""
    echo "Maintenance:"
    echo "  Backup now:   systemctl start openwatch-backup.service"
    echo "  Maintenance:  systemctl start openwatch-maintenance.service"
    echo ""
}

# Main execution
main() {
    echo "OpenWatch Systemd Installation"
    echo "=================================="

    check_root
    install_service_files
    reload_systemd
    enable_services
    validate_installation
    show_next_steps
}

# Run main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
