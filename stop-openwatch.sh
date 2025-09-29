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
CLEAN_MODE=${OPENWATCH_CLEAN_STOP:-true}  # Default to clean stop for development

# Container names (matching actual docker-compose service names)
CONTAINER_NAMES=(
    "openwatch-frontend"
    "openwatch-backend" 
    "openwatch-worker"
    "openwatch-db"
    "openwatch-redis"
    "openwatch-mongodb"
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
    
    local compose_down_flags=""
    if [ "$CLEAN_MODE" = true ]; then
        compose_down_flags="--volumes --remove-orphans"
        log_info "Development mode: Will remove volumes and orphaned containers"
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
}

# Development cleanup: Remove everything for clean state
development_cleanup() {
    log_info "Performing development cleanup..."
    log_warning "This will remove ALL OpenWatch containers, volumes, and networks!"
    
    # Stop and remove all containers first
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
        
        log_info "Podman cleanup completed"
    fi
    
    # Optional: Remove dangling images (commented out to preserve build cache)
    # log_info "Removing dangling images..."
    # docker image prune -f 2>/dev/null || true
    # podman image prune -f 2>/dev/null || true
    
    log_success "Development cleanup complete"
    log_info "Next startup will be completely fresh - perfect for testing changes!"
}

# Main execution
main() {
    log_info "OpenWatch Stop Script"
    log_info "===================="
    
    detect_runtime
    
    case "$1" in
        "--deep-clean"|"--dev-clean")
            development_cleanup
            ;;
        "--simple")
            CLEAN_MODE=false
            stop_services
            ;;
        *)
            # Default behavior: clean stop for development
            if [ "$CLEAN_MODE" = true ]; then
                log_info "Development mode: Performing clean stop (removes volumes and orphans)"
                log_info "Use --simple to stop without removing volumes"
            fi
            stop_services
            ;;
    esac
    
    log_success "Done!"
    
    # Show next steps
    if [ "$CLEAN_MODE" = true ] || [ "$1" = "--deep-clean" ] || [ "$1" = "--dev-clean" ]; then
        log_info ""
        log_info "Next steps:"
        log_info "  ./start-openwatch.sh    # Start fresh OpenWatch stack"
        log_info "  docker system df        # Check disk space usage"
    fi
}

# Handle script arguments
case "$1" in
    "--help"|"-h")
        echo "OpenWatch Stop Script - Development Focused"
        echo "=========================================="
        echo ""
        echo "This script stops OpenWatch services with development-friendly cleanup"
        echo "to ensure fast iteration and consistent state between runs."
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --help, -h        Show this help message"
        echo "  --simple          Simple stop without removing volumes (faster)"
        echo "  --deep-clean      Complete cleanup: containers + volumes + networks + orphans"
        echo "  --dev-clean       Alias for --deep-clean"
        echo ""
        echo "Default Behavior (no options):"
        echo "  Stops containers and removes volumes/orphans for clean development state"
        echo ""
        echo "Environment Variables:"
        echo "  OPENWATCH_CLEAN_STOP=false   Disable default clean mode"
        echo ""
        echo "Examples:"
        echo "  $0                    # Clean stop (default for development)"
        echo "  $0 --simple          # Quick stop, preserve volumes"
        echo "  $0 --deep-clean      # Nuclear option: remove everything"
        echo ""
        echo "For production environments, use --simple to preserve data."
        echo ""
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac