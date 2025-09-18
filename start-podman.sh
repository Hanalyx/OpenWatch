#!/bin/bash

# OpenWatch Podman Startup Script
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
DEV_MODE=false

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

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check for container runtimes
    if command -v podman &> /dev/null; then
        if command -v podman-compose &> /dev/null; then
            RUNTIME="podman-compose"
            if [ "$DEV_MODE" = true ]; then
                COMPOSE_FILE="podman-compose.dev.yml"
            else
                COMPOSE_FILE="podman-compose.yml"
            fi
            log_info "Found podman-compose, using Podman runtime"
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
            log_info "Found Docker Compose, using Docker runtime"
        else
            log_warning "Docker found but Docker Compose not available"
        fi
    fi
    
    if [ -z "$RUNTIME" ]; then
        log_error "No suitable container runtime found!"
        log_error "Please install one of the following:"
        log_error "  - Podman with podman-compose"
        log_error "  - Docker with docker-compose or Docker Compose plugin"
        exit 1
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

# Start services
start_services() {
    log_info "Starting OpenWatch services with $RUNTIME..."
    
    cd "$SCRIPT_DIR"
    
    case "$RUNTIME" in
        "podman-compose")
            podman-compose -f "$COMPOSE_FILE" up -d
            ;;
        "docker")
            if command -v docker-compose &> /dev/null; then
                docker-compose -f "$COMPOSE_FILE" up -d
            else
                docker compose -f "$COMPOSE_FILE" up -d
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
            log_info "  Frontend: http://localhost:3001"
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
    if curl -f -s http://localhost:3001 &> /dev/null; then
        log_success "Frontend is healthy"
    else
        log_warning "Frontend health check failed - may still be starting"
    fi
}

# Main execution
main() {
    log_info "OpenWatch Podman/Docker Startup Script"
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
        --help|-h)
            echo "OpenWatch Startup Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --dev, -d            Run in development mode"
            echo "  --help, -h           Show this help message"
            echo "  --no-health-check    Skip health check after startup"
            echo ""
            echo "Environment variables:"
            echo "  OPENWATCH_ENV        Set to 'development' for dev mode"
            echo ""
            echo "This script will:"
            echo "  1. Detect available container runtime (Podman or Docker)"
            echo "  2. Set up environment variables"
            echo "  3. Start OpenWatch services"
            echo "  4. Perform basic health checks"
            exit 0
            ;;
        --no-health-check)
            NO_HEALTH_CHECK=true
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
    log_info "OpenWatch Podman/Docker Startup Script"
    log_info "======================================="
    
    check_prerequisites
    setup_environment
    start_services
    
    if [ "$NO_HEALTH_CHECK" != true ]; then
        check_health
    fi
    
    log_success "OpenWatch startup complete!"
}

main