#!/bin/bash
# OpenWatch owadm Build Script
# Builds owadm CLI for different deployment modes using Go build tags

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${PROJECT_ROOT}/bin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}INFO:${NC} $1"; }
log_warn() { echo -e "${YELLOW}WARN:${NC} $1"; }
log_error() { echo -e "${RED}ERROR:${NC} $1"; }

# Get version information
VERSION="${VERSION:-2.0.0}"
COMMIT=$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')

# Common build settings
export CGO_ENABLED=0
export GOOS=linux

# Detect architecture
case "$(uname -m)" in
    x86_64)  GOARCH=amd64 ;;
    aarch64) GOARCH=arm64 ;;
    *)       GOARCH=$(uname -m) ;;
esac
export GOARCH

LDFLAGS="-s -w \
    -X github.com/hanalyx/openwatch/internal/owadm/cmd.Version=${VERSION} \
    -X github.com/hanalyx/openwatch/internal/owadm/cmd.Commit=${COMMIT} \
    -X github.com/hanalyx/openwatch/internal/owadm/cmd.BuildTime=${BUILD_TIME}"

usage() {
    cat << EOF
Usage: $0 [OPTIONS] <build-type>

Build Types:
  native      Build for native deployment (no container commands)
  container   Build for container deployment (includes start/stop/logs)
  all         Build both native and container variants

Options:
  -o, --output DIR    Output directory (default: ${OUTPUT_DIR})
  -v, --version VER   Version string (default: ${VERSION})
  -h, --help          Show this help message

Examples:
  $0 native                    # Build native variant
  $0 container                 # Build container variant
  $0 all                       # Build all variants
  $0 -o /tmp/builds all        # Build to custom directory
EOF
    exit 0
}

build_native() {
    log_info "Building owadm (native)..."
    log_info "  Tags: (none - excludes container commands)"
    log_info "  Output: ${OUTPUT_DIR}/owadm-native"

    cd "$PROJECT_ROOT"
    go build \
        -ldflags "$LDFLAGS" \
        -o "${OUTPUT_DIR}/owadm-native" \
        ./cmd/owadm

    log_info "Native build complete: ${OUTPUT_DIR}/owadm-native"
}

build_container() {
    log_info "Building owadm (container)..."
    log_info "  Tags: container"
    log_info "  Output: ${OUTPUT_DIR}/owadm-container"

    cd "$PROJECT_ROOT"
    go build \
        -tags container \
        -ldflags "$LDFLAGS" \
        -o "${OUTPUT_DIR}/owadm-container" \
        ./cmd/owadm

    log_info "Container build complete: ${OUTPUT_DIR}/owadm-container"
}

verify_builds() {
    log_info "Verifying builds..."

    if [[ -f "${OUTPUT_DIR}/owadm-native" ]]; then
        log_info "Native build commands:"
        "${OUTPUT_DIR}/owadm-native" --help 2>&1 | grep -E "^\s+\w+" | head -15 || true
    fi

    if [[ -f "${OUTPUT_DIR}/owadm-container" ]]; then
        log_info "Container build commands:"
        "${OUTPUT_DIR}/owadm-container" --help 2>&1 | grep -E "^\s+\w+" | head -15 || true
    fi
}

# Parse arguments
BUILD_TYPE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        native|container|all)
            BUILD_TYPE="$1"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

if [[ -z "$BUILD_TYPE" ]]; then
    log_error "Build type required"
    usage
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Execute builds
case "$BUILD_TYPE" in
    native)
        build_native
        ;;
    container)
        build_container
        ;;
    all)
        build_native
        build_container
        verify_builds
        ;;
esac

log_info "Build complete!"
