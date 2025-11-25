#!/bin/bash

# SecureOps Monitoring Stack Startup Script
# Author: Noah Chen - nc9010@hanalyx.com
# Last Updated: 2025-08-18

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MONITORING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$MONITORING_DIR/docker-compose.monitoring.yml"
ENV_FILE="$MONITORING_DIR/.env"

echo -e "${BLUE}===================================${NC}"
echo -e "${BLUE}  SecureOps Monitoring Stack${NC}"
echo -e "${BLUE}===================================${NC}"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker/Podman is available
check_container_runtime() {
    if command -v podman-compose &> /dev/null; then
        COMPOSE_CMD="podman-compose"
        print_status "Using Podman for container runtime"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
        print_status "Using Docker for container runtime"
    else
        print_error "Neither podman-compose nor docker-compose found!"
        exit 1
    fi
}

# Create environment file if it doesn't exist
create_env_file() {
    if [ ! -f "$ENV_FILE" ]; then
        print_status "Creating environment file..."
        cat > "$ENV_FILE" << EOF
# SecureOps Monitoring Environment Variables
# Generated on $(date)

# Grafana Configuration
GRAFANA_ADMIN_PASSWORD=secureops_grafana_$(openssl rand -hex 8)

# PostgreSQL Configuration (if needed)
POSTGRES_PASSWORD=monitoring_postgres_$(openssl rand -hex 8)

# Redis Configuration (if needed)
REDIS_PASSWORD=monitoring_redis_$(openssl rand -hex 8)

# Alert Configuration
SMTP_PASSWORD=
SLACK_WEBHOOK_URL=

# Prometheus Configuration
PROMETHEUS_RETENTION_TIME=30d
PROMETHEUS_RETENTION_SIZE=50GB

# Jaeger Configuration
JAEGER_STORAGE_TYPE=memory
JAEGER_MEMORY_MAX_TRACES=50000
EOF
        print_status "Environment file created at $ENV_FILE"
        print_warning "Please review and update the environment variables as needed"
    fi
}

# Create required directories
create_directories() {
    print_status "Creating required directories..."

    mkdir -p "$MONITORING_DIR/data/prometheus"
    mkdir -p "$MONITORING_DIR/data/grafana"
    mkdir -p "$MONITORING_DIR/data/alertmanager"
    mkdir -p "$MONITORING_DIR/logs"
    mkdir -p "$MONITORING_DIR/config/grafana/dashboards/secureops"
    mkdir -p "$MONITORING_DIR/config/grafana/dashboards/infrastructure"
    mkdir -p "$MONITORING_DIR/config/grafana/dashboards/business"

    # Set appropriate permissions
    chmod 777 "$MONITORING_DIR/data/grafana" 2>/dev/null || true
    chmod 777 "$MONITORING_DIR/data/prometheus" 2>/dev/null || true

    print_status "Directories created successfully"
}

# Validate configuration files
validate_config() {
    print_status "Validating configuration files..."

    # Check if required config files exist
    if [ ! -f "$MONITORING_DIR/config/prometheus.yml" ]; then
        print_error "Prometheus configuration file not found!"
        exit 1
    fi

    if [ ! -f "$MONITORING_DIR/config/alertmanager.yml" ]; then
        print_error "Alertmanager configuration file not found!"
        exit 1
    fi

    # Validate Prometheus config
    if command -v promtool &> /dev/null; then
        if promtool check config "$MONITORING_DIR/config/prometheus.yml"; then
            print_status "Prometheus configuration is valid"
        else
            print_error "Prometheus configuration validation failed!"
            exit 1
        fi
    else
        print_warning "promtool not found, skipping Prometheus config validation"
    fi

    print_status "Configuration validation completed"
}

# Start monitoring services
start_monitoring() {
    print_status "Starting monitoring stack..."

    cd "$MONITORING_DIR"

    # Pull latest images
    print_status "Pulling latest container images..."
    $COMPOSE_CMD -f "$COMPOSE_FILE" --env-file "$ENV_FILE" pull

    # Start services
    print_status "Starting monitoring services..."
    $COMPOSE_CMD -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d

    # Wait for services to be ready
    print_status "Waiting for services to be ready..."
    sleep 30

    # Check service health
    check_service_health
}

# Check service health
check_service_health() {
    print_status "Checking service health..."

    local services=("prometheus:9090" "grafana:3001" "jaeger:16686" "alertmanager:9093")
    local healthy_services=0

    for service in "${services[@]}"; do
        local name=$(echo $service | cut -d: -f1)
        local port=$(echo $service | cut -d: -f2)

        if curl -sf "http://localhost:$port" > /dev/null 2>&1; then
            print_status "$name is healthy (port $port)"
            ((healthy_services++))
        else
            print_warning "$name is not responding (port $port)"
        fi
    done

    print_status "$healthy_services/${#services[@]} services are healthy"

    if [ $healthy_services -eq ${#services[@]} ]; then
        print_status "All monitoring services are running successfully!"
        show_service_urls
    else
        print_warning "Some services may need more time to start"
        print_status "You can check service logs with: $COMPOSE_CMD -f $COMPOSE_FILE logs -f"
    fi
}

# Show service URLs
show_service_urls() {
    echo ""
    echo -e "${BLUE}=== Service URLs ===${NC}"
    echo -e "Grafana Dashboard:    ${GREEN}http://localhost:3001${NC}"
    echo -e "Prometheus:           ${GREEN}http://localhost:9090${NC}"
    echo -e "Jaeger Tracing:       ${GREEN}http://localhost:16686${NC}"
    echo -e "Alertmanager:         ${GREEN}http://localhost:9093${NC}"
    echo ""
    echo -e "${YELLOW}Default Grafana credentials:${NC}"
    echo -e "Username: admin"
    echo -e "Password: $(grep GRAFANA_ADMIN_PASSWORD "$ENV_FILE" | cut -d= -f2)"
    echo ""
}

# Stop monitoring services
stop_monitoring() {
    print_status "Stopping monitoring stack..."
    cd "$MONITORING_DIR"
    $COMPOSE_CMD -f "$COMPOSE_FILE" --env-file "$ENV_FILE" down
    print_status "Monitoring stack stopped"
}

# Show logs
show_logs() {
    cd "$MONITORING_DIR"
    $COMPOSE_CMD -f "$COMPOSE_FILE" --env-file "$ENV_FILE" logs -f "${2:-}"
}

# Show service status
show_status() {
    cd "$MONITORING_DIR"
    $COMPOSE_CMD -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps
}

# Backup monitoring data
backup_data() {
    local backup_dir="$MONITORING_DIR/backups/$(date +%Y%m%d_%H%M%S)"
    print_status "Creating backup in $backup_dir..."

    mkdir -p "$backup_dir"

    # Backup Prometheus data
    if [ -d "$MONITORING_DIR/data/prometheus" ]; then
        tar -czf "$backup_dir/prometheus_data.tar.gz" -C "$MONITORING_DIR/data" prometheus/
        print_status "Prometheus data backed up"
    fi

    # Backup Grafana data
    if [ -d "$MONITORING_DIR/data/grafana" ]; then
        tar -czf "$backup_dir/grafana_data.tar.gz" -C "$MONITORING_DIR/data" grafana/
        print_status "Grafana data backed up"
    fi

    # Backup configuration
    tar -czf "$backup_dir/config.tar.gz" -C "$MONITORING_DIR" config/
    print_status "Configuration backed up"

    print_status "Backup completed: $backup_dir"
}

# Main execution
main() {
    case "${1:-start}" in
        start)
            check_container_runtime
            create_env_file
            create_directories
            validate_config
            start_monitoring
            ;;
        stop)
            check_container_runtime
            stop_monitoring
            ;;
        restart)
            check_container_runtime
            stop_monitoring
            sleep 5
            start_monitoring
            ;;
        logs)
            check_container_runtime
            show_logs "$@"
            ;;
        status)
            check_container_runtime
            show_status
            ;;
        backup)
            backup_data
            ;;
        urls)
            show_service_urls
            ;;
        *)
            echo "Usage: $0 {start|stop|restart|logs [service]|status|backup|urls}"
            echo ""
            echo "Commands:"
            echo "  start    - Start the monitoring stack"
            echo "  stop     - Stop the monitoring stack"
            echo "  restart  - Restart the monitoring stack"
            echo "  logs     - Show logs (optionally for specific service)"
            echo "  status   - Show service status"
            echo "  backup   - Backup monitoring data"
            echo "  urls     - Show service URLs"
            exit 1
            ;;
    esac
}

main "$@"
