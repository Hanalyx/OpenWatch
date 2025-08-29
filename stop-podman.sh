#!/bin/bash

# OpenWatch Podman/Docker Stop Script
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
RUNTIME=""

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

# Detect runtime
detect_runtime() {
    if command -v podman-compose &> /dev/null; then
        RUNTIME="podman-compose"
        COMPOSE_FILE="podman-compose-fixed.yml"
    elif command -v docker-compose &> /dev/null; then
        RUNTIME="docker-compose"
        COMPOSE_FILE="docker-compose.yml"
    elif docker compose version &> /dev/null 2>&1; then
        RUNTIME="docker"
        COMPOSE_FILE="docker-compose.yml"
    else
        log_error "No suitable container runtime found!"
        exit 1
    fi
    
    # Fallback to original podman-compose.yml if fixed version doesn't exist
    if [ "$RUNTIME" = "podman-compose" ] && [ ! -f "$SCRIPT_DIR/$COMPOSE_FILE" ]; then
        COMPOSE_FILE="podman-compose.yml"
    fi
}

# Stop services
stop_services() {
    log_info "Stopping OpenWatch services..."
    
    cd "$SCRIPT_DIR"
    
    case "$RUNTIME" in
        "podman-compose")
            if [ -f "$COMPOSE_FILE" ]; then
                podman-compose -f "$COMPOSE_FILE" down
            else
                log_warning "Compose file not found, trying to stop containers by name"
                podman stop openwatch-frontend openwatch-backend openwatch-worker openwatch-redis openwatch-db 2>/dev/null || true
                podman rm openwatch-frontend openwatch-backend openwatch-worker openwatch-redis openwatch-db 2>/dev/null || true
            fi
            ;;
        "docker-compose")
            if [ -f "$COMPOSE_FILE" ]; then
                docker-compose -f "$COMPOSE_FILE" down
            else
                log_warning "Compose file not found, trying to stop containers by name"
                docker stop openwatch-frontend openwatch-backend openwatch-worker openwatch-redis openwatch-db 2>/dev/null || true
                docker rm openwatch-frontend openwatch-backend openwatch-worker openwatch-redis openwatch-db 2>/dev/null || true
            fi
            ;;
        "docker")
            if [ -f "$COMPOSE_FILE" ]; then
                docker compose -f "$COMPOSE_FILE" down
            else
                log_warning "Compose file not found, trying to stop containers by name"
                docker stop openwatch-frontend openwatch-backend openwatch-worker openwatch-redis openwatch-db 2>/dev/null || true
                docker rm openwatch-frontend openwatch-backend openwatch-worker openwatch-redis openwatch-db 2>/dev/null || true
            fi
            ;;
    esac
    
    log_success "OpenWatch services stopped"
}

# Clean up (optional)
cleanup() {
    log_info "Cleaning up resources..."
    
    case "$RUNTIME" in
        "podman-compose")
            if [ -f "$COMPOSE_FILE" ]; then
                podman-compose -f "$COMPOSE_FILE" down -v
            fi
            ;;
        "docker-compose")
            if [ -f "$COMPOSE_FILE" ]; then
                docker-compose -f "$COMPOSE_FILE" down -v
            fi
            ;;
        "docker")
            if [ -f "$COMPOSE_FILE" ]; then
                docker compose -f "$COMPOSE_FILE" down -v
            fi
            ;;
    esac
    
    log_success "Cleanup complete"
}

# Main execution
main() {
    log_info "OpenWatch Stop Script"
    log_info "===================="
    
    detect_runtime
    
    case "$1" in
        "--clean")
            cleanup
            ;;
        *)
            stop_services
            ;;
    esac
    
    log_success "Done!"
}

# Handle script arguments
case "$1" in
    "--help"|"-h")
        echo "OpenWatch Stop Script"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --help, -h    Show this help message"
        echo "  --clean       Stop services and remove volumes (data loss warning!)"
        echo ""
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac