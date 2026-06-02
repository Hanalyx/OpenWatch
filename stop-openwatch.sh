#!/bin/bash

# OpenWatch Stop Script
# Compatible with both Docker and Podman runtimes
# Development-focused: Performs complete cleanup for fast iteration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
PROJECT_NAME="openwatch"
RUNTIME=""
COMPOSE_FILE=""
# Default: SAFE stop — preserves all named volumes (hosts, credentials,
# scan results, SSH known_hosts, app logs).
# Destructive modes (--clean-data, --deep-clean, OPENWATCH_CLEAN_STOP)
# now require explicit confirmation via --yes / OPENWATCH_CONFIRM_DESTROY=yes
# to prevent accidental data loss from a stale env var or muscle-memory flag.
CLEAN_MODE=false
ASSUME_YES=false

# Data-bearing named volumes managed by docker-compose. Deleting any of
# these wipes the corresponding OpenWatch state.
DATA_VOLUMES=(
    "openwatch_postgres_data"
    "openwatch_app_data"
    "openwatch_app_logs"
    "openwatch_ssh_known_hosts"
)

# Container names (matching actual docker-compose service names)
CONTAINER_NAMES=(
    "openwatch-frontend"
    "openwatch-backend"
    "openwatch-worker"
    "openwatch-db"
)

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

# list_existing_data_volumes prints (one per line) any named volume from
# DATA_VOLUMES that currently exists. Used by the safe-stop summary and
# the destructive-action preview.
list_existing_data_volumes() {
    local existing
    existing=$(docker volume ls --format "{{.Name}}" 2>/dev/null) || return 0
    local v
    for v in "${DATA_VOLUMES[@]}"; do
        if grep -qx "$v" <<<"$existing"; then
            echo "$v"
        fi
    done
}

# confirm_destroy is the single chokepoint for any operation that deletes
# user data. Prints exactly which volumes will be wiped, then requires
# either --yes/-y on the command line, OPENWATCH_CONFIRM_DESTROY=yes in
# the environment, or an interactive "yes" typed on stdin. Anything else
# aborts. Returns 0 to proceed, exits 1 to refuse.
confirm_destroy() {
    local action="$1"
    log_warning "About to perform: ${action}"
    log_warning "This will DELETE the following data volumes (if present):"
    local found_any=false
    local v
    for v in "${DATA_VOLUMES[@]}"; do
        if docker volume ls --format "{{.Name}}" 2>/dev/null | grep -qx "$v"; then
            echo -e "  - ${RED}${v}${NC} (contains user data)"
            found_any=true
        else
            echo -e "  - ${v} (does not exist; nothing to delete)"
        fi
    done
    if [ "$found_any" = false ]; then
        log_info "No OpenWatch data volumes present — nothing to lose."
        return 0
    fi

    if [ "$ASSUME_YES" = true ]; then
        log_warning "--yes / -y supplied; proceeding without prompt."
        return 0
    fi
    if [ "${OPENWATCH_CONFIRM_DESTROY:-}" = "yes" ]; then
        log_warning "OPENWATCH_CONFIRM_DESTROY=yes set; proceeding without prompt."
        return 0
    fi
    if [ ! -t 0 ]; then
        log_error "Refusing to delete volumes non-interactively without --yes or OPENWATCH_CONFIRM_DESTROY=yes."
        log_error "Re-run with --yes to confirm, or attach a terminal."
        exit 1
    fi
    echo ""
    read -r -p "Type 'yes' to confirm destruction, anything else aborts: " confirm
    if [ "$confirm" != "yes" ]; then
        log_info "Aborted — no data was deleted."
        exit 0
    fi
    return 0
}

# Detect runtime and compose file based on what's actually running
detect_runtime() {
    local podman_available=false
    local docker_available=false
    local docker_running=false
    local podman_running=false

    # Check for Podman
    if command -v podman &> /dev/null; then
        podman_available=true
        # Check if any openwatch containers are running in podman
        if podman ps --format "{{.Names}}" 2>/dev/null | grep -q openwatch; then
            podman_running=true
        fi
    fi

    # Check for Docker
    if command -v docker &> /dev/null; then
        docker_available=true
        # Check if any openwatch containers are running in docker
        if docker ps --format "{{.Names}}" 2>/dev/null | grep -q openwatch; then
            docker_running=true
        fi
    fi

    # Determine runtime based on what's actually running
    if [ "$docker_running" = true ]; then
        # Docker containers are running, use docker
        if command -v docker-compose &> /dev/null; then
            RUNTIME="docker-compose"
        else
            RUNTIME="docker"
        fi
        COMPOSE_FILE="docker-compose.yml"
        log_info "Detected running Docker containers"
    elif [ "$podman_running" = true ]; then
        # Podman containers are running, use podman
        RUNTIME="podman-compose"
        if [ -f "$SCRIPT_DIR/podman-compose.yml" ]; then
            COMPOSE_FILE="podman-compose.yml"
        else
            COMPOSE_FILE="docker-compose.yml"  # Fallback
        fi
        log_info "Detected running Podman containers"
    else
        # No containers running, detect based on available tools
        if command -v podman-compose &> /dev/null && [ "$podman_available" = true ]; then
            RUNTIME="podman-compose"
            if [ -f "$SCRIPT_DIR/podman-compose.yml" ]; then
                COMPOSE_FILE="podman-compose.yml"
            else
                COMPOSE_FILE="docker-compose.yml"  # Fallback
            fi
        elif command -v docker-compose &> /dev/null && [ "$docker_available" = true ]; then
            RUNTIME="docker-compose"
            COMPOSE_FILE="docker-compose.yml"
        elif [ "$docker_available" = true ] && docker compose version &> /dev/null 2>&1; then
            RUNTIME="docker"
            COMPOSE_FILE="docker-compose.yml"
        else
            log_error "No suitable container runtime found!"
            log_error "Please install Docker or Podman with compose support."
            exit 1
        fi
        log_info "No containers running, using preferred runtime"
    fi

    log_info "Using runtime: $RUNTIME"
    log_info "Using compose file: $COMPOSE_FILE"
}

# Stop containers individually if compose fails
stop_containers_individually() {
    log_warning "Attempting to stop containers individually..."

    for container in "${CONTAINER_NAMES[@]}"; do
        case "$RUNTIME" in
            "podman-compose")
                if podman ps --format "{{.Names}}" | grep -q "^${container}$" 2>/dev/null; then
                    log_info "Stopping container: $container"
                    podman stop "$container" 2>/dev/null || true
                    podman rm "$container" 2>/dev/null || true
                fi
                ;;
            "docker-compose"|"docker")
                if docker ps --format "{{.Names}}" | grep -q "^${container}$" 2>/dev/null; then
                    log_info "Stopping container: $container"
                    docker stop "$container" 2>/dev/null || true
                    docker rm "$container" 2>/dev/null || true
                fi
                ;;
        esac
    done
}

# Stop services with complete cleanup for development
stop_services() {
    log_info "Stopping OpenWatch services..."

    cd "$SCRIPT_DIR"

    local compose_down_flags="--remove-orphans"  # Always remove orphans
    if [ "$CLEAN_MODE" = true ]; then
        confirm_destroy "compose down --volumes (wipes named data volumes)"
        compose_down_flags="--volumes --remove-orphans"
        log_warning "CLEAN MODE: Will DELETE ALL DATA (volumes will be removed)"
        log_warning "This includes hosts, credentials, scan results, and SCAP content"
    else
        log_info "Safe mode: Stopping containers but preserving data volumes"
    fi

    case "$RUNTIME" in
        "podman-compose")
            if [ -f "$COMPOSE_FILE" ]; then
                log_info "Using podman-compose with file: $COMPOSE_FILE"
                podman-compose -f "$COMPOSE_FILE" down $compose_down_flags || {
                    log_warning "Podman-compose down failed, trying individual container stop"
                    stop_containers_individually
                }
            else
                log_warning "Compose file $COMPOSE_FILE not found"
                stop_containers_individually
            fi
            ;;
        "docker-compose")
            if [ -f "$COMPOSE_FILE" ]; then
                log_info "Using docker-compose with file: $COMPOSE_FILE"
                docker-compose -f "$COMPOSE_FILE" down $compose_down_flags || {
                    log_warning "Docker-compose down failed, trying individual container stop"
                    stop_containers_individually
                }
            else
                log_warning "Compose file $COMPOSE_FILE not found"
                stop_containers_individually
            fi
            ;;
        "docker")
            if [ -f "$COMPOSE_FILE" ]; then
                log_info "Using docker compose with file: $COMPOSE_FILE"
                docker compose -f "$COMPOSE_FILE" down $compose_down_flags || {
                    log_warning "Docker compose down failed, trying individual container stop"
                    stop_containers_individually
                }
            else
                log_warning "Compose file $COMPOSE_FILE not found"
                stop_containers_individually
            fi
            ;;
    esac

    log_success "OpenWatch services stopped"

    # On a non-destructive stop, list what survived so the operator can
    # confirm at a glance that hosts + credentials + scan results are
    # still on disk and the next `start-openwatch.sh` will resume against
    # them.
    if [ "$CLEAN_MODE" != true ]; then
        local preserved
        preserved=$(list_existing_data_volumes)
        if [ -n "$preserved" ]; then
            log_info "Data preserved in these named volumes:"
            while IFS= read -r v; do
                echo -e "  ${GREEN}✓${NC} $v"
            done <<<"$preserved"
            log_info "Re-run ./start-openwatch.sh to resume against the same data."
        fi
    fi
}

# Development cleanup: Remove everything for clean state
development_cleanup() {
    log_info "Performing development cleanup..."
    log_warning "This will remove ALL OpenWatch containers, volumes, networks, and images!"
    confirm_destroy "deep clean: remove containers + volumes + networks + images"

    # Stop and remove all containers first
    CLEAN_MODE=false  # confirm_destroy already gated this; avoid double-prompt inside stop_services
    stop_services

    # Additional cleanup for development - check both docker and podman
    log_info "Cleaning up any remaining OpenWatch resources..."

    # Clean up Docker resources
    if command -v docker &> /dev/null; then
        # Remove any remaining containers with openwatch in the name
        docker ps -a --format "{{.Names}}" 2>/dev/null | grep openwatch | xargs -r docker rm -f 2>/dev/null || true

        # Remove volumes (including dev volumes)
        docker volume ls --format "{{.Name}}" 2>/dev/null | grep openwatch | xargs -r docker volume rm -f 2>/dev/null || true

        # Remove networks
        docker network ls --format "{{.Name}}" 2>/dev/null | grep openwatch | xargs -r docker network rm 2>/dev/null || true

        # Remove images (openwatch and hanalyx prefixes)
        log_info "Removing OpenWatch Docker images..."
        docker images --format "{{.Repository}}:{{.Tag}}\t{{.ID}}" 2>/dev/null | \
            grep -E "openwatch|hanalyx" | \
            awk '{print $2}' | \
            xargs -r docker rmi -f 2>/dev/null || true

        log_info "Docker cleanup completed"
    fi

    # Clean up Podman resources
    if command -v podman &> /dev/null; then
        # Remove any remaining containers with openwatch in the name
        podman ps -a --format "{{.Names}}" 2>/dev/null | grep openwatch | xargs -r podman rm -f 2>/dev/null || true

        # Remove volumes
        podman volume ls --format "{{.Name}}" 2>/dev/null | grep openwatch | xargs -r podman volume rm -f 2>/dev/null || true

        # Remove networks
        podman network ls --format "{{.Name}}" 2>/dev/null | grep openwatch | xargs -r podman network rm 2>/dev/null || true

        # Clean up pods if any
        podman pod ls --format "{{.Name}}" 2>/dev/null | grep openwatch | xargs -r podman pod rm -f 2>/dev/null || true

        # Remove images (openwatch and hanalyx prefixes)
        log_info "Removing OpenWatch Podman images..."
        podman images --format "{{.Repository}}:{{.Tag}}\t{{.ID}}" 2>/dev/null | \
            grep -E "openwatch|hanalyx" | \
            awk '{print $2}' | \
            xargs -r podman rmi -f 2>/dev/null || true

        log_info "Podman cleanup completed"
    fi

    log_success "Development cleanup complete"
    log_info "Next startup will be completely fresh - perfect for testing changes!"
}

# Main execution
main() {
    log_info "OpenWatch Stop Script"
    log_info "===================="

    detect_runtime

    # Honor OPENWATCH_CLEAN_STOP only when paired with the explicit
    # confirmation companion. Previously a stale env var (e.g. left over
    # in a shell rc from prior debugging) would silently wipe data on
    # every stop. That foot-gun is now closed.
    if [ "${OPENWATCH_CLEAN_STOP:-}" = "true" ]; then
        if [ "${OPENWATCH_CONFIRM_DESTROY:-}" = "yes" ] || [ "$ASSUME_YES" = true ]; then
            CLEAN_MODE=true
        else
            log_warning "OPENWATCH_CLEAN_STOP=true is set but OPENWATCH_CONFIRM_DESTROY=yes is not."
            log_warning "Ignoring CLEAN_STOP — data will be preserved. To actually delete, also"
            log_warning "export OPENWATCH_CONFIRM_DESTROY=yes (or pass --yes / --clean-data)."
        fi
    fi

    case "$MODE" in
        "deep-clean")
            development_cleanup
            ;;
        "clean-data")
            CLEAN_MODE=true
            stop_services
            ;;
        "safe"|"")
            if [ "$CLEAN_MODE" = true ]; then
                log_warning "CLEAN MODE active via env vars (CLEAN_STOP + CONFIRM_DESTROY)."
                log_warning "Volumes WILL be removed. Use ./stop-openwatch.sh (no flags) to preserve data."
            else
                log_info "Safe mode: containers stop, data volumes are preserved."
                log_info "Use --clean-data to drop the named volumes (requires confirmation)."
            fi
            stop_services
            ;;
        *)
            log_error "Unknown mode: $MODE"
            exit 1
            ;;
    esac

    log_success "Done!"

    # Show next steps
    if [ "$CLEAN_MODE" = true ] || [ "$MODE" = "deep-clean" ]; then
        log_info ""
        log_info "Next steps:"
        log_info "  ./start-openwatch.sh    # Start fresh OpenWatch stack"
        log_info "  docker system df        # Check disk space usage"
    fi
}

print_help() {
    cat <<'EOF'
OpenWatch Stop Script
=====================

Stops the OpenWatch container stack. SAFE BY DEFAULT — data lives on named
docker volumes that are preserved across stop/start cycles.

Usage: ./stop-openwatch.sh [OPTIONS]

Options:
  (no options)        Safe stop. Containers down, volumes preserved.
                      Hosts, credentials, scan results, and SSH known_hosts
                      survive and are visible again after start-openwatch.sh.

  --simple            Alias for the default safe stop.
  --keep-data         Alias for the default safe stop.

  --clean-data        Stop and DELETE the named data volumes:
                        openwatch_postgres_data    (hosts, credentials, scans)
                        openwatch_app_data         (app working state)
                        openwatch_app_logs         (logs)
                        openwatch_ssh_known_hosts  (SSH host-key trust db)
                      Requires confirmation: --yes, OPENWATCH_CONFIRM_DESTROY=yes,
                      or an interactive 'yes' on stdin.

  --deep-clean        Everything in --clean-data PLUS: remove all OpenWatch /
  --dev-clean         hanalyx images, the docker network, and any leftover
                      containers. Requires the same confirmation gate.

  --yes, -y           Skip the interactive prompt. Required when running
                      destructive modes non-interactively (CI, scripts).

  --help, -h          Print this help.

Environment variables:
  OPENWATCH_CLEAN_STOP=true       Enable destructive mode from env. Now ALSO
                                  requires OPENWATCH_CONFIRM_DESTROY=yes to
                                  actually delete (prevents accidental wipes
                                  from stale rc-file exports).
  OPENWATCH_CONFIRM_DESTROY=yes   Companion to --yes. Confirms destruction
                                  without an interactive prompt.

Examples:
  ./stop-openwatch.sh                                  # Safe; data preserved
  ./stop-openwatch.sh --clean-data                     # Prompts before wipe
  ./stop-openwatch.sh --clean-data --yes               # No prompt; wipes data
  ./stop-openwatch.sh --deep-clean --yes               # Nuclear, scripted

What is preserved on a safe stop:
  - hosts table, credentials table, scans, host_system_info, etc.
  - SSH known_hosts trust database
  - app_data and app_logs
EOF
}

# Parse arguments — supports any order, multiple flags. Sets MODE +
# ASSUME_YES then dispatches to main.
MODE=""
while [ $# -gt 0 ]; do
    case "$1" in
        "--help"|"-h")
            print_help
            exit 0
            ;;
        "--yes"|"-y")
            ASSUME_YES=true
            shift
            ;;
        "--deep-clean"|"--dev-clean")
            MODE="deep-clean"
            shift
            ;;
        "--clean-data")
            MODE="clean-data"
            shift
            ;;
        "--simple"|"--keep-data")
            MODE="safe"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            log_error "Run ./stop-openwatch.sh --help for usage."
            exit 1
            ;;
    esac
done

main
