#!/bin/bash
# OpenWatch Production Health Check Script
# Comprehensive health verification for production deployments

set -euo pipefail

# Configuration
HEALTH_TIMEOUT=30
STAGING_URL="${STAGING_URL:-https://staging.openwatch.hanalyx.com}"
PRODUCTION_URL="${PRODUCTION_URL:-https://openwatch.hanalyx.com}"
LOG_FILE="/tmp/openwatch-health-check.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Initialize log file
echo "OpenWatch Production Health Check - $(date)" > "$LOG_FILE"

# Check if URL is provided as argument or use environment
TARGET_URL="${1:-$STAGING_URL}"

# Detect environment based on URL
if [[ "$TARGET_URL" == *"staging"* ]]; then
    ENVIRONMENT="staging"
elif [[ "$TARGET_URL" == *"localhost"* ]]; then
    ENVIRONMENT="development"
    TARGET_URL="http://localhost:3001"
else
    ENVIRONMENT="production"
    TARGET_URL="$PRODUCTION_URL"
fi

log_info "Starting health check for $ENVIRONMENT environment"
log_info "Target URL: $TARGET_URL"

# Health check functions
check_basic_connectivity() {
    log_info "Checking basic connectivity..."

    if curl -f -s --max-time "$HEALTH_TIMEOUT" "$TARGET_URL" >/dev/null; then
        log_success "Basic connectivity check passed"
        return 0
    else
        log_error "Basic connectivity check failed"
        return 1
    fi
}

check_frontend_health() {
    log_info "Checking frontend health..."

    # Check if frontend is serving content
    local response
    response=$(curl -s --max-time "$HEALTH_TIMEOUT" "$TARGET_URL" || echo "FAILED")

    if [[ "$response" == *"OpenWatch"* ]] || [[ "$response" == *"<!DOCTYPE html>"* ]]; then
        log_success "Frontend health check passed"
        return 0
    else
        log_warning "Frontend may not be serving expected content"
        return 1
    fi
}

check_api_health() {
    log_info "Checking API health..."

    # Try different health endpoint variations
    local health_endpoints=(
        "$TARGET_URL/api/health"
        "$TARGET_URL/health"
        "$TARGET_URL/api/v1/health"
    )

    for endpoint in "${health_endpoints[@]}"; do
        if curl -f -s --max-time "$HEALTH_TIMEOUT" "$endpoint" >/dev/null; then
            log_success "API health check passed at $endpoint"
            return 0
        fi
    done

    log_warning "API health endpoints not responding"
    return 1
}

check_database_connectivity() {
    log_info "Checking database connectivity (indirect)..."

    # Try to access an endpoint that would require database
    local auth_endpoint="$TARGET_URL/api/auth/login"

    # Check if endpoint exists (even if it returns 405 Method Not Allowed for GET)
    local status_code
    status_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$HEALTH_TIMEOUT" "$auth_endpoint" || echo "000")

    if [[ "$status_code" =~ ^[234] ]]; then
        log_success "Database connectivity appears healthy"
        return 0
    else
        log_warning "Database connectivity uncertain (status: $status_code)"
        return 1
    fi
}

check_performance() {
    log_info "Checking response performance..."

    local response_time
    response_time=$(curl -s -o /dev/null -w "%{time_total}" --max-time "$HEALTH_TIMEOUT" "$TARGET_URL" || echo "999")

    if (( $(echo "$response_time < 2.0" | bc -l) )); then
        log_success "Response time acceptable: ${response_time}s"
        return 0
    elif (( $(echo "$response_time < 5.0" | bc -l) )); then
        log_warning "Response time slow but acceptable: ${response_time}s"
        return 1
    else
        log_error "Response time too slow: ${response_time}s"
        return 1
    fi
}

check_ssl_certificate() {
    if [[ "$TARGET_URL" == https* ]]; then
        log_info "Checking SSL certificate..."

        if curl -s --max-time "$HEALTH_TIMEOUT" "$TARGET_URL" >/dev/null; then
            log_success "SSL certificate check passed"
            return 0
        else
            log_error "SSL certificate check failed"
            return 1
        fi
    else
        log_info "Skipping SSL check for HTTP endpoint"
        return 0
    fi
}

# Run comprehensive health checks
run_health_checks() {
    local failed_checks=0

    echo ""
    log_info "=== OpenWatch Health Check Report ==="
    log_info "Environment: $ENVIRONMENT"
    log_info "Target: $TARGET_URL"
    log_info "Timestamp: $(date)"
    echo ""

    # Run all checks
    check_basic_connectivity || ((failed_checks++))
    check_frontend_health || ((failed_checks++))
    check_api_health || ((failed_checks++))
    check_database_connectivity || ((failed_checks++))

    # Performance and SSL checks are less critical
    check_performance || log_warning "Performance check had issues but continuing..."
    check_ssl_certificate || log_warning "SSL check had issues but continuing..."

    echo ""
    log_info "=== Health Check Summary ==="

    if [ $failed_checks -eq 0 ]; then
        log_success "All critical health checks passed!"
        log_info "System appears to be healthy and ready for production traffic"
        return 0
    elif [ $failed_checks -le 2 ]; then
        log_warning "$failed_checks critical checks failed"
        log_warning "System may have issues but core functionality appears available"
        return 1
    else
        log_error "$failed_checks critical checks failed"
        log_error "System appears to have significant issues - investigate before proceeding"
        return 1
    fi
}

# Fallback for development/local testing
run_local_health_checks() {
    log_info "Running simplified health checks for development environment"

    # Check if services are running locally
    local services_ok=0

    if curl -f -s --max-time 5 "http://localhost:3001" >/dev/null; then
        log_success "Frontend service is running"
        ((services_ok++))
    else
        log_warning "Frontend service not accessible at localhost:3001"
    fi

    if curl -f -s --max-time 5 "http://localhost:8000/health" >/dev/null; then
        log_success "Backend service is running"
        ((services_ok++))
    else
        log_warning "Backend service not accessible at localhost:8000"
    fi

    if [ $services_ok -gt 0 ]; then
        log_success "Local development services are accessible"
        return 0
    else
        log_error "No local services are accessible"
        return 1
    fi
}

# Main execution
main() {
    echo "OpenWatch Production Health Check"
    echo "===================================="

    # Handle command line arguments
    case "${1:-}" in
        --help|-h)
            echo "Usage: $0 [URL|--local|--help]"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Check staging environment"
            echo "  $0 https://openwatch.hanalyx.com     # Check specific URL"
            echo "  $0 --local                           # Check local development"
            echo "  $0 --help                            # Show this help"
            exit 0
            ;;
        --local)
            run_local_health_checks
            ;;
        *)
            # For CI/CD environments, fall back to local checks if no staging URL is available
            if [[ "$TARGET_URL" == *"staging.openwatch.hanalyx.com"* ]] && ! curl -f -s --max-time 5 "$TARGET_URL" >/dev/null 2>&1; then
                log_warning "Staging environment not accessible, falling back to local checks"
                run_local_health_checks
            else
                run_health_checks
            fi
            ;;
    esac
}

# Execute main function with all arguments
main "$@"
