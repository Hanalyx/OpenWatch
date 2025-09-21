#!/bin/bash
# OpenWatch Complete Cleanup Script
# Comprehensive removal of all OpenWatch files, containers, and data
# Usage: cleanup-openwatch.sh [--backup] [--force] [--dry-run]

set -euo pipefail

# Script configuration
SCRIPT_NAME="OpenWatch Cleanup"
BACKUP_DIR="/tmp/openwatch-backup-$(date +%Y%m%d_%H%M%S)"
DRY_RUN=false
FORCE_CLEANUP=false
CREATE_BACKUP=false
VERBOSE=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}INFO: $1${NC}"
}

log_success() {
    echo -e "${GREEN}SUCCESS: $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
}

log_error() {
    echo -e "${RED}ERROR: $1${NC}"
}

log_verbose() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}VERBOSE: $1${NC}"
    fi
}

# Help function
show_help() {
    cat << EOF
OpenWatch Complete Cleanup Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --backup           Create backup of important data before cleanup
    --force            Force cleanup without confirmation prompts
    --dry-run          Show what would be cleaned up without doing it
    --verbose          Enable verbose output
    -h, --help         Show this help message

DESCRIPTION:
    This script performs complete cleanup of OpenWatch installation including:
    - Container images, volumes, and networks
    - Application data and configuration files
    - Generated keys, certificates, and secrets
    - Log files and cache data
    - Systemd services and user accounts

BACKUP LOCATIONS (when --backup is used):
    - Configuration: /etc/openwatch/
    - Data: /var/lib/openwatch/
    - Logs: /var/log/openwatch/
    - Keys: SSH and JWT key pairs

EXAMPLES:
    $0 --dry-run              # Preview cleanup actions
    $0 --backup --force       # Backup data and cleanup without prompts
    $0 --verbose              # Cleanup with detailed output

WARNING: This operation is irreversible without backup!
EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --backup)
                CREATE_BACKUP=true
                shift
                ;;
            --force)
                FORCE_CLEANUP=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Execute command with dry-run support
execute_cmd() {
    local cmd="$1"
    local description="$2"
    
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY-RUN] $description: $cmd"
    else
        log_verbose "Executing: $cmd"
        eval "$cmd" || {
            log_warning "Command failed: $cmd"
            return 1
        }
    fi
}

# Create backup of important data
create_backup() {
    if [ "$CREATE_BACKUP" != true ]; then
        return 0
    fi
    
    log_info "Creating backup in $BACKUP_DIR..."
    
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY-RUN] Would create backup in $BACKUP_DIR"
        return 0
    fi
    
    mkdir -p "$BACKUP_DIR"
    
    # Backup configuration files
    if [ -d "/etc/openwatch" ]; then
        log_verbose "Backing up configuration files"
        cp -r /etc/openwatch "$BACKUP_DIR/config" || true
    fi
    
    # Backup application data
    if [ -d "/var/lib/openwatch" ]; then
        log_verbose "Backing up application data"
        cp -r /var/lib/openwatch "$BACKUP_DIR/data" || true
    fi
    
    # Backup logs (last 7 days only to save space)
    if [ -d "/var/log/openwatch" ]; then
        log_verbose "Backing up recent logs"
        mkdir -p "$BACKUP_DIR/logs"
        find /var/log/openwatch -type f -mtime -7 -exec cp {} "$BACKUP_DIR/logs/" \; || true
    fi
    
    # Create backup manifest
    cat > "$BACKUP_DIR/manifest.txt" << EOF
OpenWatch Backup Created: $(date)
Backup Location: $BACKUP_DIR
Cleanup Script Version: 1.0

Contents:
- config/: Configuration files from /etc/openwatch
- data/: Application data from /var/lib/openwatch  
- logs/: Recent log files (last 7 days)

Restore Instructions:
1. Reinstall OpenWatch RPM package
2. Stop OpenWatch services: systemctl stop openwatch
3. Restore files: cp -r $BACKUP_DIR/config/* /etc/openwatch/
4. Restore data: cp -r $BACKUP_DIR/data/* /var/lib/openwatch/
5. Fix permissions: chown -R openwatch:openwatch /var/lib/openwatch
6. Start services: systemctl start openwatch
EOF
    
    # Compress backup for space efficiency
    tar -czf "$BACKUP_DIR.tar.gz" -C "$(dirname "$BACKUP_DIR")" "$(basename "$BACKUP_DIR")" && rm -rf "$BACKUP_DIR"
    
    log_success "Backup created: $BACKUP_DIR.tar.gz"
}

# Stop all OpenWatch services
stop_services() {
    log_info "Stopping OpenWatch services..."
    
    local services=(
        "openwatch.service"
        "openwatch-db.service"
        "openwatch-frontend.service"
        "openwatch-worker.service"
        "openwatch-redis.service"
    )
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            execute_cmd "systemctl stop $service" "Stop $service"
        fi
        
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            execute_cmd "systemctl disable $service" "Disable $service"
        fi
    done
}

# Clean up containers, images, and volumes
cleanup_containers() {
    log_info "Cleaning up containers and images..."
    
    # Detect container runtime
    local runtime=""
    if command -v podman >/dev/null 2>&1; then
        runtime="podman"
    elif command -v docker >/dev/null 2>&1; then
        runtime="docker"
    else
        log_warning "No container runtime found"
        return 0
    fi
    
    log_verbose "Using container runtime: $runtime"
    
    # Stop and remove OpenWatch containers
    local containers
    containers=$($runtime ps -a --filter "label=project=openwatch" --format "{{.Names}}" 2>/dev/null || true)
    if [ -n "$containers" ]; then
        for container in $containers; do
            execute_cmd "$runtime stop $container" "Stop container $container"
            execute_cmd "$runtime rm $container" "Remove container $container"
        done
    fi
    
    # Remove OpenWatch images
    local images
    images=$($runtime images --filter "reference=openwatch*" --format "{{.Repository}}:{{.Tag}}" 2>/dev/null || true)
    if [ -n "$images" ]; then
        for image in $images; do
            execute_cmd "$runtime rmi $image" "Remove image $image"
        done
    fi
    
    # Clean up OpenWatch volumes
    local volumes
    volumes=$($runtime volume ls --filter "label=project=openwatch" --format "{{.Name}}" 2>/dev/null || true)
    if [ -n "$volumes" ]; then
        for volume in $volumes; do
            execute_cmd "$runtime volume rm $volume" "Remove volume $volume"
        done
    fi
    
    # Clean up OpenWatch networks
    local networks
    networks=$($runtime network ls --filter "label=project=openwatch" --format "{{.Name}}" 2>/dev/null || true)
    if [ -n "$networks" ]; then
        for network in $networks; do
            if [ "$network" != "bridge" ] && [ "$network" != "host" ] && [ "$network" != "none" ]; then
                execute_cmd "$runtime network rm $network" "Remove network $network"
            fi
        done
    fi
}

# Remove application files and directories
cleanup_files() {
    log_info "Cleaning up application files..."
    
    local directories=(
        "/etc/openwatch"
        "/var/lib/openwatch" 
        "/var/log/openwatch"
        "/var/cache/openwatch"
        "/usr/share/openwatch"
    )
    
    for dir in "${directories[@]}"; do
        if [ -d "$dir" ]; then
            execute_cmd "rm -rf $dir" "Remove directory $dir"
        fi
    done
    
    # Remove systemd service files
    local service_files=(
        "/lib/systemd/system/openwatch.service"
        "/lib/systemd/system/openwatch-db.service"
        "/lib/systemd/system/openwatch-frontend.service"
        "/lib/systemd/system/openwatch-worker.service"
        "/lib/systemd/system/openwatch-redis.service"
    )
    
    for service_file in "${service_files[@]}"; do
        if [ -f "$service_file" ]; then
            execute_cmd "rm $service_file" "Remove service file $service_file"
        fi
    done
    
    execute_cmd "systemctl daemon-reload" "Reload systemd daemon"
}

# Remove user and group
cleanup_user() {
    log_info "Cleaning up user accounts..."
    
    if id "openwatch" &>/dev/null; then
        execute_cmd "userdel openwatch" "Remove openwatch user"
    fi
    
    if getent group "openwatch" &>/dev/null; then
        execute_cmd "groupdel openwatch" "Remove openwatch group"
    fi
}

# Remove SELinux policies
cleanup_selinux() {
    log_info "Cleaning up SELinux policies..."
    
    if command -v semodule >/dev/null 2>&1; then
        if semodule -l | grep -q "openwatch"; then
            execute_cmd "semodule -r openwatch" "Remove OpenWatch SELinux policy"
        fi
    fi
}

# Remove fapolicyd rules
cleanup_fapolicyd() {
    log_info "Cleaning up fapolicyd rules..."
    
    local fapolicyd_rules="/etc/fapolicyd/rules.d/90-openwatch.rules"
    if [ -f "$fapolicyd_rules" ]; then
        execute_cmd "rm $fapolicyd_rules" "Remove fapolicyd rules"
        
        if systemctl is-active --quiet fapolicyd; then
            execute_cmd "systemctl restart fapolicyd" "Restart fapolicyd"
        fi
    fi
}

# Confirmation prompt
confirm_cleanup() {
    if [ "$FORCE_CLEANUP" = true ] || [ "$DRY_RUN" = true ]; then
        return 0
    fi
    
    echo ""
    log_warning "This will completely remove OpenWatch and all its data!"
    echo ""
    echo "The following will be cleaned up:"
    echo "  - All containers, images, volumes, and networks"
    echo "  - Configuration files (/etc/openwatch)"
    echo "  - Application data (/var/lib/openwatch)"
    echo "  - Log files (/var/log/openwatch)"
    echo "  - Cache data (/var/cache/openwatch)"
    echo "  - User accounts and systemd services"
    echo "  - SELinux policies and fapolicyd rules"
    echo ""
    
    if [ "$CREATE_BACKUP" = true ]; then
        echo "A backup will be created at: $BACKUP_DIR.tar.gz"
        echo ""
    fi
    
    read -p "Are you sure you want to continue? (y/N): " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Cleanup cancelled by user"
        exit 0
    fi
}

# Main cleanup function
main() {
    echo ""
    echo "=================================="
    echo "   $SCRIPT_NAME"
    echo "=================================="
    echo ""
    
    parse_arguments "$@"
    check_root
    
    if [ "$DRY_RUN" = true ]; then
        log_info "DRY RUN MODE - No changes will be made"
        echo ""
    fi
    
    confirm_cleanup
    
    # Create backup before cleanup
    create_backup
    
    # Perform cleanup steps
    stop_services
    cleanup_containers
    cleanup_files
    cleanup_user
    cleanup_selinux
    cleanup_fapolicyd
    
    echo ""
    if [ "$DRY_RUN" = true ]; then
        log_info "Dry run completed - no changes were made"
    else
        log_success "OpenWatch cleanup completed successfully!"
        
        if [ "$CREATE_BACKUP" = true ]; then
            echo ""
            log_info "Backup available at: $BACKUP_DIR.tar.gz"
        fi
    fi
    echo ""
}

# Run main function with all arguments
main "$@"