#!/bin/bash
################################################################################
# ComplianceAsCode Build and Conversion Script
#
# This script automates the process of building SCAP content from ComplianceAsCode
# and converting it to OpenWatch format (Solution 1 from JINJA2_RULES_HANDLING_STRATEGY.md)
#
# Prerequisites:
#   - ComplianceAsCode repository cloned at: /home/rracine/hanalyx/scap_content/content
#   - CMake, Python3, python3-jinja2, python3-yaml installed
#   - Docker containers running (for conversion step)
#
# Usage:
#   # Build and convert a single product
#   ./build_compliance_rules.sh rhel8
#
#   # Build and convert multiple products
#   ./build_compliance_rules.sh rhel8 rhel9 ubuntu2204
#
#   # Build all supported products
#   ./build_compliance_rules.sh all
#
################################################################################

set -euo pipefail

# Configuration
SCAP_DIR="/home/rracine/hanalyx/scap_content"
BUILD_DIR="${SCAP_DIR}/build"
OUTPUT_BASE_DIR="${SCAP_DIR}/build/openwatch_bundles"
BUNDLE_VERSION="1.0.0"
CONVERTER_SCRIPT="/app/backend/app/cli/scap_json_to_openwatch_converter.py"

# Signature configuration
SIGN_BUNDLES="${SIGN_BUNDLES:-false}"
PRIVATE_KEY_PATH="${PRIVATE_KEY_PATH:-/home/rracine/hanalyx/backend/security/signing_keys/complianceascode_private.pem}"
SIGNER_NAME="${SIGNER_NAME:-ComplianceAsCode Project}"

# Supported products (from ComplianceAsCode)
ALL_PRODUCTS=(
    "rhel8"
    "rhel9"
    "rhel10"
    "ubuntu2004"
    "ubuntu2204"
    "ol8"
    "ol9"
    "debian11"
    "debian12"
    "fedora"
)

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

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

    # Check if SCAP content directory exists
    if [ ! -d "${SCAP_DIR}/content" ]; then
        log_error "ComplianceAsCode content not found at ${SCAP_DIR}/content"
        log_info "Clone with: git clone https://github.com/ComplianceAsCode/content.git ${SCAP_DIR}/content"
        exit 1
    fi

    # Check if CMake is available
    if ! command -v cmake &> /dev/null; then
        log_error "cmake not found. Install with: sudo dnf install cmake"
        exit 1
    fi

    # Check if Docker is running
    if ! docker ps &> /dev/null; then
        log_error "Docker is not running or not accessible"
        exit 1
    fi

    # Check if OpenWatch backend container is running
    if ! docker ps --format '{{.Names}}' | grep -q "openwatch-backend"; then
        log_error "openwatch-backend container is not running"
        log_info "Start with: docker-compose up -d"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# Initialize CMake build
init_cmake_build() {
    log_info "Initializing CMake build..."

    # Create build directory if it doesn't exist
    mkdir -p "${BUILD_DIR}"
    cd "${BUILD_DIR}"

    # Run CMake configuration (only if not already configured)
    if [ ! -f "${BUILD_DIR}/CMakeCache.txt" ]; then
        log_info "Running CMake configuration..."
        cmake ../content
        log_success "CMake configured successfully"
    else
        log_info "CMake already configured (${BUILD_DIR}/CMakeCache.txt exists)"
    fi
}

# Build a single product
build_product() {
    local product="$1"

    log_info "Building SCAP content for ${product}..."

    cd "${BUILD_DIR}"

    # Build the product (this renders all Jinja2 templates)
    if make "${product}" 2>&1 | tee "/tmp/build_${product}.log"; then
        log_success "Build completed for ${product}"

        # Verify build output
        if [ -f "${BUILD_DIR}/ssg-${product}-ds.xml" ]; then
            local size=$(du -h "${BUILD_DIR}/ssg-${product}-ds.xml" | cut -f1)
            log_success "Generated data stream: ssg-${product}-ds.xml (${size})"
        fi

        # Count rendered rules
        if [ -d "${BUILD_DIR}/${product}/rules" ]; then
            local rule_count=$(find "${BUILD_DIR}/${product}/rules" -name "*.json" -type f | wc -l)
            log_success "Rendered ${rule_count} rule files"
        fi

        return 0
    else
        log_error "Build failed for ${product}"
        log_info "Check logs at: /tmp/build_${product}.log"
        return 1
    fi
}

# Convert rules to OpenWatch format
convert_rules() {
    local product="$1"
    local product_build_path="${BUILD_DIR}/${product}"
    local output_path="${OUTPUT_BASE_DIR}/${product}"
    local container_input_path="/app/data/scap_input_${product}"
    local container_output_path="/app/data/scap_output_${product}"

    log_info "Converting ${product} rules to OpenWatch format..."

    # Check if rules directory exists
    if [ ! -d "${product_build_path}/rules" ]; then
        log_error "Rules directory not found: ${product_build_path}/rules"
        return 1
    fi

    # Create output directory on host
    mkdir -p "${output_path}"

    # Copy converter script to container
    log_info "Updating converter in Docker container..."
    docker cp "${SCAP_DIR}/../backend/app/cli/scap_json_to_openwatch_converter.py" \
        openwatch-backend:/app/backend/app/cli/scap_json_to_openwatch_converter.py 2>/dev/null || true

    # Transfer rules to container via tar (faster and more reliable)
    log_info "Transferring rules to container..."
    cd "${product_build_path}"
    tar czf - rules/ | docker exec -i openwatch-backend bash -c "
        mkdir -p ${container_input_path} && \
        cd ${container_input_path} && \
        tar xzf - && \
        chown -R openwatch:openwatch ${container_input_path}
    "

    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        log_error "Failed to transfer rules to container"
        return 1
    fi

    # Run conversion inside Docker container
    log_info "Running converter in Docker container..."

    # Build converter command with optional signing
    local converter_cmd="cd /app/backend && python3 -m app.cli.scap_json_to_openwatch_converter convert \
            --build-path ${container_input_path} \
            --output-path ${container_output_path} \
            --product ${product} \
            --format bson \
            --create-bundle \
            --bundle-version ${BUNDLE_VERSION}"

    # Add signing options if enabled
    if [ "${SIGN_BUNDLES}" == "true" ]; then
        log_info "Bundle signing ENABLED"

        # Check if private key exists on host
        if [ ! -f "${PRIVATE_KEY_PATH}" ]; then
            log_error "Private key not found: ${PRIVATE_KEY_PATH}"
            log_info "Generate keypair with: python3 backend/security/generate_signing_keypair.py --name complianceascode --signer \"ComplianceAsCode Project\""
            return 1
        fi

        # Copy private key to container (temporary, will be deleted after conversion)
        local container_key_path="/tmp/signing_key.pem"
        docker cp "${PRIVATE_KEY_PATH}" "openwatch-backend:${container_key_path}"

        # Add signing parameters to command
        converter_cmd="${converter_cmd} --sign-bundle --private-key-path ${container_key_path} --signer \"${SIGNER_NAME}\""
    else
        log_info "Bundle signing DISABLED (set SIGN_BUNDLES=true to enable)"
    fi

    # Execute conversion
    docker exec openwatch-backend bash -c "${converter_cmd}" 2>&1 | tee "/tmp/convert_${product}.log"

    local conversion_status=${PIPESTATUS[0]}

    # Cleanup private key from container if signing was enabled
    if [ "${SIGN_BUNDLES}" == "true" ]; then
        docker exec openwatch-backend bash -c "rm -f ${container_key_path}" 2>/dev/null || true
    fi

    if [ ${conversion_status} -ne 0 ]; then
        log_error "Conversion failed for ${product}"
        log_info "Check logs at: /tmp/convert_${product}.log"

        # Cleanup container directories
        docker exec openwatch-backend bash -c "rm -rf ${container_input_path} ${container_output_path}" 2>/dev/null || true

        return 1
    fi

    # Extract bundle from container to host
    log_info "Extracting bundle from container..."

    # Find the bundle in the container
    local bundle_name=$(docker exec openwatch-backend bash -c "ls /app/data/openwatch-${product}-bundle_v*.tar.gz 2>/dev/null | head -1" | tr -d '\r')

    if [ -z "${bundle_name}" ]; then
        log_error "Bundle not found in container"
        docker exec openwatch-backend bash -c "rm -rf ${container_input_path} ${container_output_path}" 2>/dev/null || true
        return 1
    fi

    # Copy bundle to host
    docker cp "openwatch-backend:${bundle_name}" "${output_path}/" 2>&1 | tee -a "/tmp/convert_${product}.log"

    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        local bundle_file="${output_path}/$(basename ${bundle_name})"
        local bundle_size=$(du -h "${bundle_file}" | cut -f1)
        log_success "Conversion completed for ${product}"
        log_success "Bundle created: $(basename ${bundle_file}) (${bundle_size})"

        # Cleanup container directories
        docker exec openwatch-backend bash -c "rm -rf ${container_input_path} ${container_output_path} ${bundle_name}" 2>/dev/null || true

        return 0
    else
        log_error "Failed to extract bundle from container"
        docker exec openwatch-backend bash -c "rm -rf ${container_input_path} ${container_output_path}" 2>/dev/null || true
        return 1
    fi
}

# Process a single product (build + convert)
process_product() {
    local product="$1"

    echo ""
    log_info "=========================================="
    log_info "Processing product: ${product}"
    log_info "=========================================="

    # Build
    if ! build_product "${product}"; then
        log_warning "Skipping conversion for ${product} due to build failure"
        return 1
    fi

    # Convert
    if ! convert_rules "${product}"; then
        log_warning "Conversion failed for ${product}"
        return 1
    fi

    log_success "Successfully processed ${product}"
    return 0
}

# Main function
main() {
    local products=("$@")

    # If no arguments or "all" specified, use all products
    if [ ${#products[@]} -eq 0 ] || [ "${products[0]}" == "all" ]; then
        products=("${ALL_PRODUCTS[@]}")
    fi

    log_info "ComplianceAsCode Build and Conversion Script"
    log_info "Version: ${BUNDLE_VERSION}"
    log_info "Products to process: ${products[*]}"
    echo ""

    # Check prerequisites
    check_prerequisites

    # Initialize CMake build
    init_cmake_build

    # Create output directory
    mkdir -p "${OUTPUT_BASE_DIR}"

    # Track successes and failures
    local success_count=0
    local failure_count=0
    local failed_products=()

    # Process each product
    for product in "${products[@]}"; do
        if process_product "${product}"; then
            ((success_count++))
        else
            ((failure_count++))
            failed_products+=("${product}")
        fi
    done

    # Summary
    echo ""
    echo "=========================================="
    log_info "BUILD AND CONVERSION SUMMARY"
    echo "=========================================="
    log_info "Total products processed: ${#products[@]}"
    log_success "Successful: ${success_count}"

    if [ ${failure_count} -gt 0 ]; then
        log_error "Failed: ${failure_count}"
        log_error "Failed products: ${failed_products[*]}"
    fi

    log_info "Bundles location: ${OUTPUT_BASE_DIR}"
    log_info "Build logs: /tmp/build_*.log"
    log_info "Conversion logs: /tmp/convert_*.log"
    echo "=========================================="

    # Exit with error if any failures
    if [ ${failure_count} -gt 0 ]; then
        exit 1
    fi
}

# Show usage if --help is specified
if [ "${1:-}" == "--help" ] || [ "${1:-}" == "-h" ]; then
    cat << EOF
ComplianceAsCode Build and Conversion Script

Usage: $0 [product1] [product2] ... [productN]
       $0 all

Examples:
  # Basic usage - unsigned bundles
  $0 rhel8                    # Build and convert RHEL 8 only
  $0 rhel8 rhel9 ubuntu2204   # Build and convert multiple products
  $0 all                      # Build and convert all supported products

  # Advanced usage - signed bundles (production)
  SIGN_BUNDLES=true $0 rhel8
  SIGN_BUNDLES=true SIGNER_NAME="My Organization" $0 all

Environment Variables:
  SIGN_BUNDLES          Sign bundles with RSA key (default: false)
  PRIVATE_KEY_PATH      Path to RSA private key (default: backend/security/signing_keys/complianceascode_private.pem)
  SIGNER_NAME           Signer name for signature metadata (default: "ComplianceAsCode Project")

Supported products:
  ${ALL_PRODUCTS[*]}

Output:
  - SCAP data streams: ${BUILD_DIR}/ssg-<product>-ds.xml
  - Rendered rules: ${BUILD_DIR}/<product>/rules/*.json
  - OpenWatch bundles: ${OUTPUT_BASE_DIR}/openwatch-<product>-bundle_v*.tar.gz

Prerequisites:
  - ComplianceAsCode content at: ${SCAP_DIR}/content
  - Docker containers running: docker-compose up -d
  - CMake, Python3, Jinja2 installed
  - (Optional) RSA keypair for signing: python3 backend/security/generate_signing_keypair.py

Bundle Signing:
  Bundles can be cryptographically signed to ensure authenticity and integrity.
  To sign bundles:
    1. Generate keypair: python3 backend/security/generate_signing_keypair.py --name complianceascode --signer "ComplianceAsCode Project"
    2. Build with signing: SIGN_BUNDLES=true $0 rhel8
    3. Upload signed bundle to OpenWatch (production mode will verify signature)

Implements: Solution 1 from JINJA2_RULES_HANDLING_STRATEGY.md
EOF
    exit 0
fi

# Run main function
main "$@"
