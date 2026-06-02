#!/bin/bash

# OpenWatch Startup Script
# Compatible with both Docker and Podman runtimes

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
COMPOSE_FILE=""
RUNTIME=""
FORCE_RUNTIME=""
DEV_MODE=false
BUILD_IMAGES=false
FORCE_BUILD=false
RESET_DATA=false
ASSUME_YES=false

# Data-bearing named volumes — kept in sync with stop-openwatch.sh.
# Used by preflight_data_check (informational) and reset_data_volumes
# (destructive, gated). Editing this list in one place must be mirrored
# in the stop script.
DATA_VOLUMES=(
    "openwatch_postgres_data"
    "openwatch_app_data"
    "openwatch_app_logs"
    "openwatch_ssh_known_hosts"
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

# preflight_data_check prints a one-line summary of whether existing
# OpenWatch data volumes will be reused. This makes "am I about to lose
# my hosts and credentials?" an answerable question BEFORE start, not
# after the dashboard comes up empty. Read-only — does not touch anything.
preflight_data_check() {
    if ! command -v docker &> /dev/null; then
        return 0  # podman-compose path; named volume name may differ
    fi
    local existing="" v
    for v in "${DATA_VOLUMES[@]}"; do
        if docker volume ls --format "{{.Name}}" 2>/dev/null | grep -qx "$v"; then
            existing+="$v "
        fi
    done
    if [ -n "$existing" ]; then
        log_info "Found existing data volumes — start will RESUME against them:"
        for v in $existing; do
            echo -e "  ${GREEN}✓${NC} $v"
        done
        log_info "To start from a clean slate instead, run: ./start-openwatch.sh --reset-data"
    else
        log_info "No prior OpenWatch data volumes detected — first-time setup."
    fi
}

# reset_data_volumes is the single explicit way to wipe data on START.
# Refuses to run without --yes or OPENWATCH_CONFIRM_DESTROY=yes; lists
# volumes that will go BEFORE deleting; will not touch any volume that
# isn't in DATA_VOLUMES (so an unrelated openwatch-pg-fresh standalone
# volume is safe).
reset_data_volumes() {
    log_warning "--reset-data requested. This will DELETE the following volumes (if present):"
    local found_any=false v
    for v in "${DATA_VOLUMES[@]}"; do
        if docker volume ls --format "{{.Name}}" 2>/dev/null | grep -qx "$v"; then
            echo -e "  - ${RED}${v}${NC}"
            found_any=true
        else
            echo -e "  - ${v} (does not exist; nothing to do)"
        fi
    done
    if [ "$found_any" = false ]; then
        log_info "Nothing to reset."
        return 0
    fi

    if [ "$ASSUME_YES" != true ] && [ "${OPENWATCH_CONFIRM_DESTROY:-}" != "yes" ]; then
        if [ ! -t 0 ]; then
            log_error "Refusing to delete volumes non-interactively without --yes / OPENWATCH_CONFIRM_DESTROY=yes."
            exit 1
        fi
        echo ""
        read -r -p "Type 'yes' to confirm destruction, anything else aborts: " confirm
        if [ "$confirm" != "yes" ]; then
            log_info "Aborted — start canceled, no data deleted."
            exit 0
        fi
    fi

    # Make sure no container is holding the volume open before delete.
    log_info "Bringing the stack down (containers only) so volumes can be removed..."
    cd "$SCRIPT_DIR"
    docker compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null \
      || docker-compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null \
      || true

    for v in "${DATA_VOLUMES[@]}"; do
        docker volume rm -f "$v" 2>/dev/null || true
    done
    log_success "Data volumes removed. Next start will initialize a fresh database."
}

# preflight_port_check refuses to start the compose stack if something
# else is already bound to the postgres host port (127.0.0.1:5432).
#
# Why this exists: two postgres containers on the same host fighting for
# port 5432 silently confuse the operator. The serve binary connects to
# whichever container *won* the bind, and the dashboard shows whatever
# data is on THAT container's volume. Restart the loser later and your
# hosts + credentials appear to vanish — they didn't, they're in the
# other container's volume.
#
# Common collision: a manually-run `openwatch-pg` container left over
# from earlier debugging. We detect it specifically and explain how to
# resolve. Anything else bound to 5432 still fails the check, just with
# a more generic message.
preflight_port_check() {
    if ! command -v docker &> /dev/null; then
        return 0  # podman path; skip for now
    fi

    # Anything in the compose stack we'd be starting? If the compose db
    # is already up under our compose project name, that's fine — `up`
    # is idempotent. Only foreign binders are a problem.
    local own_db
    own_db=$(docker ps --filter "name=openwatch-db" --format "{{.Names}}" 2>/dev/null)

    # Find every container exposing host port 5432. `docker ps --filter
    # publish=5432` matches both 0.0.0.0 and 127.0.0.1 bindings.
    local binders
    binders=$(docker ps --filter "publish=5432" --format "{{.Names}}" 2>/dev/null \
              | grep -v "^${own_db}$" || true)

    if [ -z "$binders" ]; then
        return 0
    fi

    log_error "Port 127.0.0.1:5432 is already bound by another container:"
    while IFS= read -r c; do
        [ -z "$c" ] && continue
        local image
        image=$(docker inspect --format '{{.Config.Image}}' "$c" 2>/dev/null || echo "?")
        local volumes
        volumes=$(docker inspect --format '{{range .Mounts}}{{.Name}} {{end}}' "$c" 2>/dev/null)
        echo -e "  - ${RED}${c}${NC} (image ${image})"
        if [ -n "$volumes" ]; then
            echo -e "    Data lives on volume(s): ${volumes}"
        fi
    done <<<"$binders"

    log_error ""
    log_error "Starting compose now would either fail to bind 5432, or worse,"
    log_error "start a SECOND database on a different volume so your hosts +"
    log_error "credentials would appear to vanish until the original container"
    log_error "is brought back up."
    log_error ""
    log_error "Resolve one of these ways before re-running:"
    log_error "  1. Use the existing container — point the binary at it and"
    log_error "     skip start-openwatch.sh entirely. Recommended if its volume"
    log_error "     holds the data you want to keep."
    log_error "  2. Stop the existing container:"
    log_error "       docker stop $(echo "$binders" | tr '\n' ' ')"
    log_error "     Then re-run ./start-openwatch.sh. The compose DB will get"
    log_error "     5432 and use volume openwatch_postgres_data."
    log_error "  3. Migrate data into the compose volume:"
    log_error "       docker exec $(echo "$binders" | head -1) pg_dumpall -U openwatch > /tmp/ow-dump.sql"
    log_error "     ...then stop, start compose, and restore from /tmp/ow-dump.sql."
    exit 1
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if runtime was forced by user
    if [ -n "$FORCE_RUNTIME" ]; then
        case "$FORCE_RUNTIME" in
            "podman")
                if command -v podman &> /dev/null && command -v podman-compose &> /dev/null; then
                    RUNTIME="podman-compose"
                    if [ "$DEV_MODE" = true ]; then
                        COMPOSE_FILE="podman-compose.dev.yml"
                    else
                        COMPOSE_FILE="podman-compose.yml"
                    fi
                    log_info "Using forced Podman runtime"
                else
                    log_error "Podman or podman-compose not found!"
                    log_error "Please install: sudo apt install podman podman-compose"
                    exit 1
                fi
                ;;
            "docker")
                if command -v docker &> /dev/null && (command -v docker-compose &> /dev/null || docker compose version &> /dev/null); then
                    RUNTIME="docker"
                    if [ "$DEV_MODE" = true ]; then
                        COMPOSE_FILE="docker-compose.dev.yml"
                    else
                        COMPOSE_FILE="docker-compose.yml"
                    fi
                    log_info "Using forced Docker runtime"
                else
                    log_error "Docker or docker-compose not found!"
                    log_error "Please install: sudo apt install docker.io docker-compose"
                    exit 1
                fi
                ;;
            *)
                log_error "Invalid runtime specified: $FORCE_RUNTIME"
                log_error "Valid options: docker, podman"
                exit 1
                ;;
        esac
    else
        # Auto-detect runtime (existing logic)
        if command -v podman &> /dev/null; then
            if command -v podman-compose &> /dev/null; then
                RUNTIME="podman-compose"
                if [ "$DEV_MODE" = true ]; then
                    COMPOSE_FILE="podman-compose.dev.yml"
                else
                    COMPOSE_FILE="podman-compose.yml"
                fi
                log_info "Auto-detected Podman runtime"
            else
                log_warning "Podman found but podman-compose not available"
            fi
        fi

        if command -v docker &> /dev/null && [ -z "$RUNTIME" ]; then
            if command -v docker-compose &> /dev/null || docker compose version &> /dev/null; then
                RUNTIME="docker"
                if [ "$DEV_MODE" = true ]; then
                    COMPOSE_FILE="docker-compose.dev.yml"
                else
                    COMPOSE_FILE="docker-compose.yml"
                fi
                log_info "Auto-detected Docker runtime"
            else
                log_warning "Docker found but Docker Compose not available"
            fi
        fi

        if [ -z "$RUNTIME" ]; then
            log_error "No suitable container runtime found!"
            log_error "Please install one of the following:"
            log_error "  - Podman: sudo apt install podman podman-compose"
            log_error "  - Docker: sudo apt install docker.io docker-compose"
            log_error "Or specify runtime with: --runtime docker|podman"
            exit 1
        fi
    fi

    # Check for required files
    if [ ! -f "$SCRIPT_DIR/$COMPOSE_FILE" ]; then
        log_error "Compose file not found: $COMPOSE_FILE"
        exit 1
    fi

    if [ "$DEV_MODE" = true ]; then
        log_info "Running in DEVELOPMENT mode"
    else
        log_info "Running in PRODUCTION mode"
    fi
}

# Environment setup
setup_environment() {
    log_info "Setting up environment..."

    # Check for .env file
    if [ ! -f "$SCRIPT_DIR/.env" ]; then
        log_warning ".env file not found"
        if [ -f "$SCRIPT_DIR/backend/.env.example" ]; then
            log_info "Creating .env from backend/.env.example..."
            cp "$SCRIPT_DIR/backend/.env.example" "$SCRIPT_DIR/.env"

            # Generate secure keys if they're still default values
            if ! grep -q "your-secret-key-here" "$SCRIPT_DIR/.env" 2>/dev/null; then
                SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | base64)
                MASTER_KEY=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | base64)

                sed -i "s/your-secret-key-here-must-be-at-least-32-characters-long/$SECRET_KEY/" "$SCRIPT_DIR/.env"
                sed -i "s/your-master-key-here-must-be-at-least-32-characters-long/$MASTER_KEY/" "$SCRIPT_DIR/.env"

                log_success "Generated secure keys in .env file"
            fi
        else
            log_info "Creating basic .env file..."
            cat > "$SCRIPT_DIR/.env" << EOF
# OpenWatch Environment Configuration
SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | base64)
MASTER_KEY=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | base64)
POSTGRES_PASSWORD=openwatch_dev_password
REDIS_PASSWORD=redis_dev_password
DATABASE_URL=postgresql://openwatch:openwatch_dev_password@localhost:5432/openwatch
EOF
        fi
    fi

    # Source environment variables
    if [ -f "$SCRIPT_DIR/.env" ]; then
        export $(grep -v '^#' "$SCRIPT_DIR/.env" | xargs)
    fi

    # Create required directories
    mkdir -p "$SCRIPT_DIR/data/scap" "$SCRIPT_DIR/data/results" "$SCRIPT_DIR/logs" 2>/dev/null || true
    mkdir -p "$SCRIPT_DIR/security/certs" "$SCRIPT_DIR/security/keys" 2>/dev/null || true

    log_success "Environment setup complete"
}

# Check if images exist
check_images() {
    log_info "Checking for existing container images..."

    local missing_images=false

    case "$RUNTIME" in
        "podman-compose")
            # Check if any openwatch images exist
            if ! podman images | grep -q "openwatch"; then
                missing_images=true
            fi
            ;;
        "docker")
            # Check if any openwatch images exist
            if ! docker images | grep -q "openwatch"; then
                missing_images=true
            fi
            ;;
    esac

    if [ "$missing_images" = true ]; then
        log_warning "No OpenWatch container images found"
        log_info "You may want to run with --build flag to build images first"
        log_info "Example: $0 --build"
    fi
}

# Build images if needed
build_images() {
    log_info "Building container images..."

    cd "$SCRIPT_DIR"

    case "$RUNTIME" in
        "podman-compose")
            if [ "$FORCE_BUILD" = true ]; then
                podman-compose -f "$COMPOSE_FILE" build --no-cache
            else
                podman-compose -f "$COMPOSE_FILE" build
            fi
            ;;
        "docker")
            if command -v docker-compose &> /dev/null; then
                if [ "$FORCE_BUILD" = true ]; then
                    docker-compose -f "$COMPOSE_FILE" build --no-cache
                else
                    docker-compose -f "$COMPOSE_FILE" build
                fi
            else
                if [ "$FORCE_BUILD" = true ]; then
                    docker compose -f "$COMPOSE_FILE" build --no-cache
                else
                    docker compose -f "$COMPOSE_FILE" build
                fi
            fi
            ;;
    esac

    if [ $? -eq 0 ]; then
        log_success "Container images built successfully!"
    else
        log_error "Failed to build container images"
        exit 1
    fi
}

# Start services
start_services() {
    log_info "Starting OpenWatch services with $RUNTIME..."

    cd "$SCRIPT_DIR"

    # Determine if we need to build
    local compose_args="-d"
    if [ "$BUILD_IMAGES" = true ]; then
        compose_args="--build -d"
    fi

    case "$RUNTIME" in
        "podman-compose")
            podman-compose -f "$COMPOSE_FILE" up $compose_args
            ;;
        "docker")
            if command -v docker-compose &> /dev/null; then
                docker-compose -f "$COMPOSE_FILE" up $compose_args
            else
                docker compose -f "$COMPOSE_FILE" up $compose_args
            fi
            ;;
    esac

    if [ $? -eq 0 ]; then
        log_success "OpenWatch services started successfully!"
        log_info ""
        log_info "Access points:"
        if [ "$RUNTIME" = "podman-compose" ] && [ "$DEV_MODE" = false ]; then
            log_info "  Frontend: http://localhost:8080 (HTTPS: https://localhost:8443)"
            log_info "  Backend API: http://localhost:8000"
        else
            log_info "  Frontend: http://localhost:3000"
            log_info "  Backend API: http://localhost:8000"
        fi
        log_info "  API Docs: http://localhost:8000/docs"
        log_info ""
        log_info "To stop services, run:"
        case "$RUNTIME" in
            "podman-compose")
                log_info "  podman-compose -f $COMPOSE_FILE down"
                ;;
            "docker")
                log_info "  docker-compose -f $COMPOSE_FILE down"
                ;;
        esac
    else
        log_error "Failed to start services"
        exit 1
    fi
}

# Health check
check_health() {
    log_info "Performing health check..."

    sleep 30  # Give services time to start

    # Check backend
    if curl -f -s http://localhost:8000/health &> /dev/null; then
        log_success "Backend is healthy"
    else
        log_warning "Backend health check failed - may still be starting"
    fi

    # Check frontend
    if curl -f -s http://localhost:3000 &> /dev/null; then
        log_success "Frontend is healthy"
    else
        log_warning "Frontend health check failed - may still be starting"
    fi
}

# Main execution
main() {
    log_info "OpenWatch Startup Script"
    log_info "======================================="

    check_prerequisites
    setup_environment
    start_services

    if [ "$1" != "--no-health-check" ]; then
        check_health
    fi

    log_success "OpenWatch startup complete!"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dev|-d)
            DEV_MODE=true
            shift
            ;;
        --build|-b)
            BUILD_IMAGES=true
            FORCE_BUILD=true  # Always use --no-cache with --build for fresh builds
            shift
            ;;
        --force-build)
            BUILD_IMAGES=true
            FORCE_BUILD=true
            shift
            ;;
        --runtime|-r)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --runtime requires an argument (docker|podman)"
                exit 1
            fi
            FORCE_RUNTIME="$2"
            shift 2
            ;;
        --help|-h)
            cat <<'EOF'
OpenWatch Startup Script

Usage: ./start-openwatch.sh [OPTIONS]

Options:
  --dev, -d              Run in development mode
  --build, -b            Build container images before starting (no cache)
  --force-build          Alias for --build
  --runtime, -r RUNTIME  Force container runtime (docker|podman)
  --no-health-check      Skip the post-start health check
  --reset-data           Delete existing OpenWatch data volumes BEFORE
                         starting (hosts, credentials, scans, logs).
                         Gated on --yes / OPENWATCH_CONFIRM_DESTROY=yes
                         / interactive 'yes' on stdin.
  --yes, -y              Skip confirmation prompts. Required when running
                         --reset-data non-interactively.
  --help, -h             Show this help message

Data persistence (this is the durable model):
  Hosts, credentials, scan results, and SSH known_hosts live in named
  docker volumes (openwatch_postgres_data, openwatch_app_data,
  openwatch_app_logs, openwatch_ssh_known_hosts). They survive:
    - container restarts
    - stop-openwatch.sh (any mode except --clean-data / --deep-clean)
    - start-openwatch.sh (any mode except --reset-data)
    - --build / --force-build (images and volumes are independent)
  They are wiped only by:
    - ./start-openwatch.sh --reset-data
    - ./stop-openwatch.sh --clean-data
    - ./stop-openwatch.sh --deep-clean
    - manual `docker volume rm` / `docker compose down -v`

Runtime selection:
  Auto-detect picks whatever container runtime is installed. Use
  --runtime docker to pin Docker (Debian/Ubuntu), --runtime podman
  for Podman (RHEL/Fedora).

Environment variables:
  OPENWATCH_ENV=development      Equivalent to --dev
  OPENWATCH_CONFIRM_DESTROY=yes  Companion to --yes for --reset-data in
                                 non-interactive contexts.

Examples:
  ./start-openwatch.sh                          # Resume against existing data
  ./start-openwatch.sh --runtime docker --build # Rebuild images, keep data
  ./start-openwatch.sh --reset-data             # Prompts before wipe + start
  ./start-openwatch.sh --reset-data --yes       # Scripted fresh start
EOF
            exit 0
            ;;
        --no-health-check)
            NO_HEALTH_CHECK=true
            shift
            ;;
        --reset-data)
            # Explicit opt-in to wipe DB / app data BEFORE starting.
            # Gated on --yes / OPENWATCH_CONFIRM_DESTROY=yes / interactive
            # confirm inside reset_data_volumes.
            RESET_DATA=true
            shift
            ;;
        --yes|-y)
            ASSUME_YES=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check environment variable for dev mode
if [ "$OPENWATCH_ENV" = "development" ]; then
    DEV_MODE=true
fi

# Main execution
main() {
    log_info "OpenWatch Startup Script"
    log_info "======================================="

    check_prerequisites
    setup_environment

    # Data-volume preflight runs BEFORE we touch any containers. If
    # --reset-data was requested, drop volumes here (gated by confirm);
    # otherwise just report what will be reused so the operator can see
    # at a glance that hosts/credentials/scans will survive.
    if [ "$RESET_DATA" = true ]; then
        reset_data_volumes
    else
        preflight_data_check
    fi

    # Refuse to start if a foreign container is squatting on 5432.
    # Skipped after --reset-data because the compose down inside the
    # reset already cleared any same-project containers.
    preflight_port_check

    # Check if images exist (only if not building)
    if [ "$BUILD_IMAGES" != true ]; then
        check_images
    fi

    # Build images if requested and not using --build flag with up
    if [ "$BUILD_IMAGES" = true ] && [ "$FORCE_BUILD" = true ]; then
        build_images
        BUILD_IMAGES=false  # Don't use --build with up since we already built
    fi

    start_services

    if [ "$NO_HEALTH_CHECK" != true ]; then
        check_health
    fi

    log_success "OpenWatch startup complete!"
}

main
