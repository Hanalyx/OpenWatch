#!/bin/bash
# OpenWatch Container-to-Native Migration Script
# Migrates an existing container-based OpenWatch installation to native systemd services
#
# Prerequisites:
# - openwatch (native) RPM package installed
# - Existing container-based installation (openwatch-po or Docker)
# - PostgreSQL 15+ and Redis 6+ installed and running

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/var/backups/openwatch-migration-$(date +%Y%m%d_%H%M%S)}"
DRY_RUN="${DRY_RUN:-false}"

usage() {
    cat << EOF
OpenWatch Container-to-Native Migration Script

Usage: $0 [OPTIONS]

Options:
  --dry-run         Show what would be done without making changes
  --backup-dir DIR  Directory for backups (default: /var/backups/openwatch-migration-TIMESTAMP)
  --skip-backup     Skip database backup (not recommended)
  --force           Force migration even if checks fail
  -h, --help        Show this help message

Environment Variables:
  DRY_RUN           Set to 'true' for dry-run mode
  BACKUP_DIR        Override backup directory

Example:
  $0 --dry-run                  # Preview migration steps
  $0                            # Run full migration
  $0 --backup-dir /tmp/backup   # Use custom backup directory
EOF
    exit 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_prerequisites() {
    log_step "Checking prerequisites..."

    # Check for native package
    if ! rpm -q openwatch >/dev/null 2>&1; then
        log_error "Native OpenWatch package not installed"
        log_info "Install with: dnf install openwatch-2.0.0-*.rpm"
        exit 1
    fi

    # Check for container package
    if rpm -q openwatch-po >/dev/null 2>&1; then
        log_info "Found container package: openwatch-po"
        CONTAINER_PKG="openwatch-po"
    elif command -v docker >/dev/null 2>&1; then
        log_info "Docker detected - assuming Docker-based installation"
        CONTAINER_PKG="docker"
    elif command -v podman >/dev/null 2>&1; then
        log_info "Podman detected - assuming Podman-based installation"
        CONTAINER_PKG="podman"
    else
        log_error "No container installation detected"
        exit 1
    fi

    # Check for required services
    for service in postgresql redis; do
        if ! systemctl is-active --quiet "$service" 2>/dev/null; then
            log_warn "$service is not running"
            log_info "Start with: systemctl start $service"
        fi
    done

    log_info "Prerequisites check passed"
}

stop_container_services() {
    log_step "Stopping container services..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would stop container services"
        return
    fi

    # Stop systemd-managed container services
    if systemctl is-active --quiet openwatch 2>/dev/null; then
        systemctl stop openwatch || true
    fi

    # Stop docker/podman containers
    if command -v podman >/dev/null 2>&1; then
        podman stop $(podman ps -q --filter name=openwatch) 2>/dev/null || true
    fi

    if command -v docker >/dev/null 2>&1; then
        docker stop $(docker ps -q --filter name=openwatch) 2>/dev/null || true
    fi

    log_info "Container services stopped"
}

backup_database() {
    log_step "Backing up database..."

    if [[ "$SKIP_BACKUP" == "true" ]]; then
        log_warn "Skipping database backup (not recommended)"
        return
    fi

    mkdir -p "$BACKUP_DIR"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would backup database to $BACKUP_DIR/openwatch.sql"
        return
    fi

    # Get database credentials from container or config
    if [[ -f /etc/openwatch/secrets.env ]]; then
        source /etc/openwatch/secrets.env
        DB_PASSWORD="${POSTGRES_PASSWORD:-${OPENWATCH_DATABASE_PASSWORD:-}}"
    fi

    # Dump from container database
    if command -v podman >/dev/null 2>&1 && podman ps -a --filter name=openwatch-db | grep -q openwatch; then
        log_info "Dumping from Podman container database..."
        podman exec openwatch-db pg_dump -U openwatch openwatch > "$BACKUP_DIR/openwatch.sql"
    elif command -v docker >/dev/null 2>&1 && docker ps -a --filter name=openwatch-db | grep -q openwatch; then
        log_info "Dumping from Docker container database..."
        docker exec openwatch-db pg_dump -U openwatch openwatch > "$BACKUP_DIR/openwatch.sql"
    else
        log_warn "Could not find container database, attempting direct connection..."
        PGPASSWORD="$DB_PASSWORD" pg_dump -h localhost -U openwatch openwatch > "$BACKUP_DIR/openwatch.sql" || true
    fi

    # Backup configuration
    if [[ -d /etc/openwatch ]]; then
        cp -a /etc/openwatch "$BACKUP_DIR/etc_openwatch"
    fi

    log_info "Backup completed: $BACKUP_DIR"
}

migrate_database() {
    log_step "Migrating database to system PostgreSQL..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would restore database to system PostgreSQL"
        return
    fi

    # Create database user and database if not exists
    sudo -u postgres psql -c "CREATE USER openwatch WITH PASSWORD '${OPENWATCH_DATABASE_PASSWORD:-changeme}';" 2>/dev/null || true
    sudo -u postgres psql -c "CREATE DATABASE openwatch OWNER openwatch;" 2>/dev/null || true

    # Restore backup
    if [[ -f "$BACKUP_DIR/openwatch.sql" ]]; then
        log_info "Restoring database from backup..."
        sudo -u postgres psql openwatch < "$BACKUP_DIR/openwatch.sql"
    fi

    log_info "Database migration completed"
}

migrate_configuration() {
    log_step "Migrating configuration..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would update /etc/openwatch/ow.yml for native mode"
        return
    fi

    # Update configuration for native mode
    if [[ -f /etc/openwatch/ow.yml ]]; then
        # Backup existing config
        cp /etc/openwatch/ow.yml /etc/openwatch/ow.yml.container.bak

        # Update runtime mode
        sed -i 's/mode: container/mode: native/' /etc/openwatch/ow.yml
        sed -i 's/engine: "podman"/engine: "native"/' /etc/openwatch/ow.yml
        sed -i 's/engine: "docker"/engine: "native"/' /etc/openwatch/ow.yml

        log_info "Configuration updated for native mode"
    fi
}

run_migrations() {
    log_step "Running database migrations..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would run Alembic migrations"
        return
    fi

    # Run Alembic migrations
    cd /opt/openwatch/backend
    source /opt/openwatch/venv/bin/activate
    alembic upgrade head
    deactivate

    log_info "Database migrations completed"
}

start_native_services() {
    log_step "Starting native services..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would start openwatch.target via systemctl"
        return
    fi

    # Enable and start services
    systemctl daemon-reload
    systemctl enable openwatch.target
    systemctl start openwatch.target

    # Check status
    sleep 5
    systemctl status openwatch-api --no-pager || true

    log_info "Native services started"
}

cleanup_containers() {
    log_step "Cleaning up container artifacts..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would remove container images and volumes"
        return
    fi

    read -p "Remove container images and volumes? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if command -v podman >/dev/null 2>&1; then
            podman rm -f $(podman ps -aq --filter name=openwatch) 2>/dev/null || true
            podman volume rm $(podman volume ls -q --filter name=openwatch) 2>/dev/null || true
        fi

        if command -v docker >/dev/null 2>&1; then
            docker rm -f $(docker ps -aq --filter name=openwatch) 2>/dev/null || true
            docker volume rm $(docker volume ls -q --filter name=openwatch) 2>/dev/null || true
        fi

        log_info "Container artifacts cleaned up"
    else
        log_info "Keeping container artifacts"
    fi
}

verify_migration() {
    log_step "Verifying migration..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would verify services and health endpoint"
        return
    fi

    # Check services
    echo ""
    echo "Service Status:"
    systemctl status openwatch-api --no-pager -l 2>&1 | head -10 || true
    systemctl status openwatch-worker@1 --no-pager -l 2>&1 | head -10 || true

    # Check health endpoint
    echo ""
    echo "Health Check:"
    curl -s http://localhost:8000/health || echo "Health endpoint not responding yet"

    echo ""
    log_info "Migration verification complete"
}

# Parse arguments
SKIP_BACKUP=false
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --backup-dir)
            BACKUP_DIR="$2"
            shift 2
            ;;
        --skip-backup)
            SKIP_BACKUP=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Main execution
echo "=============================================="
echo "OpenWatch Container-to-Native Migration"
echo "=============================================="
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "DRY-RUN MODE - No changes will be made"
    echo ""
fi

check_root
check_prerequisites
stop_container_services
backup_database
migrate_database
migrate_configuration
run_migrations
start_native_services
cleanup_containers
verify_migration

echo ""
echo "=============================================="
echo "Migration Complete!"
echo "=============================================="
echo ""
echo "Backup location: $BACKUP_DIR"
echo ""
echo "Next steps:"
echo "  1. Verify application: curl https://localhost/health"
echo "  2. Check logs: journalctl -u openwatch-api -f"
echo "  3. If issues, restore: cp $BACKUP_DIR/etc_openwatch/* /etc/openwatch/"
echo ""
