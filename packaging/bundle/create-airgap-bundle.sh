#!/bin/bash
# OpenWatch Air-Gap Bundle Creator
# Creates a complete offline installation package

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration
BUNDLE_VERSION="1.2.1-8"
BUNDLE_NAME="openwatch-bundle-${BUNDLE_VERSION}"
WORK_DIR="/tmp/${BUNDLE_NAME}"
OUTPUT_DIR="$(pwd)/dist"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Required images for OpenWatch (with fallback registries)
REQUIRED_IMAGES=(
    "docker.io/postgres:15-alpine"
    "docker.io/redis:7-alpine"
    "registry.access.redhat.com/ubi9/ubi:latest"
    "docker.io/library/node:18-alpine"
    "docker.io/nginx:alpine"
)

# Alternative registries for fallback
FALLBACK_IMAGES=(
    "quay.io/postgres/postgres:15-alpine"
    "quay.io/redis/redis:7-alpine"
    "registry.access.redhat.com/ubi9/ubi:latest"
    "quay.io/nodejs/node:18-alpine"
    "quay.io/nginx/nginx:alpine"
)

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    local missing_tools=()
    for tool in podman tar gzip rpmbuild; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi

    # Check if we can build images
    if ! podman info >/dev/null 2>&1; then
        log_error "Podman is not properly configured"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# Create bundle directory structure
create_bundle_structure() {
    log_info "Creating bundle directory structure..."

    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"/{images,rpm/dependencies,scripts,configs,docs}
    mkdir -p "$OUTPUT_DIR"

    log_success "Bundle structure created at $WORK_DIR"
}

# Pull and save container images with fallback support
pull_and_save_images() {
    log_info "Pulling and saving container images..."

    local image_manifest="$WORK_DIR/images/image-manifest.json"
    echo '{"images": [' > "$image_manifest"
    local first=true
    local successful_pulls=0

    # Try primary images first
    for i in "${!REQUIRED_IMAGES[@]}"; do
        local image="${REQUIRED_IMAGES[$i]}"
        local fallback_image="${FALLBACK_IMAGES[$i]}"
        local image_name=$(basename "$image" | tr ':' '-')
        local image_file="$WORK_DIR/images/${image_name}.tar"
        local pulled_image=""

        log_info "Attempting to pull $image..."

        # Try primary image
        if timeout 300 podman pull "$image" 2>/dev/null; then
            pulled_image="$image"
            log_success "Successfully pulled $image"
        elif [[ "$fallback_image" != "$image" ]]; then
            # Try fallback image
            log_warning "Primary failed, trying fallback: $fallback_image"
            if timeout 300 podman pull "$fallback_image" 2>/dev/null; then
                pulled_image="$fallback_image"
                log_success "Successfully pulled fallback $fallback_image"
            fi
        fi

        # Save the successfully pulled image
        if [[ -n "$pulled_image" ]]; then
            log_info "Saving $pulled_image to ${image_name}.tar..."
            if podman save -o "$image_file" "$pulled_image"; then
                ((successful_pulls++))

                # Add to manifest
                if [[ "$first" = true ]]; then
                    first=false
                else
                    echo ',' >> "$image_manifest"
                fi

                cat >> "$image_manifest" << EOF
    {
      "original": "$image",
      "actual": "$pulled_image",
      "file": "${image_name}.tar",
      "size": $(stat -c%s "$image_file"),
      "sha256": "$(sha256sum "$image_file" | cut -d' ' -f1)"
    }
EOF

                log_success "Saved $pulled_image as ${image_name}.tar"
            else
                log_warning "Failed to save $pulled_image"
            fi
        else
            log_error "Failed to pull both primary and fallback images for $image"
        fi
    done

    echo ']' >> "$image_manifest"
    echo '}' >> "$image_manifest"

    if [[ $successful_pulls -eq 0 ]]; then
        log_error "Failed to pull any container images - likely due to rate limiting"
        log_info "Wait for Docker Hub rate limit to reset (6 hours) and try again"
        return 1
    elif [[ $successful_pulls -lt ${#REQUIRED_IMAGES[@]} ]]; then
        log_warning "Only pulled $successful_pulls out of ${#REQUIRED_IMAGES[@]} images"
        log_info "Bundle will still be created but may be incomplete"
    fi

    log_success "Container images saved ($successful_pulls successful)"
}

# Build custom OpenWatch images
build_custom_images() {
    log_info "Building custom OpenWatch images..."

    cd "$PROJECT_ROOT"

    # Build backend image
    if [[ -f "docker/Containerfile.backend" ]]; then
        log_info "Building OpenWatch backend image..."
        podman build -t openwatch-backend:${BUNDLE_VERSION} -f docker/Containerfile.backend .
        podman save -o "$WORK_DIR/images/openwatch-backend.tar" openwatch-backend:${BUNDLE_VERSION}
        log_success "Built OpenWatch backend image"
    fi

    # Build frontend image
    if [[ -f "docker/Containerfile.frontend" ]]; then
        log_info "Building OpenWatch frontend image..."
        podman build -t openwatch-frontend:${BUNDLE_VERSION} -f docker/Containerfile.frontend .
        podman save -o "$WORK_DIR/images/openwatch-frontend.tar" openwatch-frontend:${BUNDLE_VERSION}
        log_success "Built OpenWatch frontend image"
    fi
}

# Copy RPM and dependencies
copy_rpm_dependencies() {
    log_info "Copying RPM packages..."

    # Copy main OpenWatch RPM
    if [[ -f "$PROJECT_ROOT/packaging/rpm/dist/openwatch-${BUNDLE_VERSION}.x86_64.rpm" ]]; then
        cp "$PROJECT_ROOT/packaging/rpm/dist/openwatch-${BUNDLE_VERSION}.x86_64.rpm" "$WORK_DIR/rpm/"
        log_success "Copied OpenWatch RPM"
    else
        log_warning "OpenWatch RPM not found - you may need to build it first"
    fi

    # Create dependencies download script
    log_info "Creating dependencies download script..."
    cat > "$WORK_DIR/rpm/download-dependencies.sh" << 'DEPS_EOF'
#!/bin/bash
# Download RPM dependencies for air-gapped installation
# Run this script on a system with internet access

set -euo pipefail

# Core dependencies
DEPENDENCIES=(
    "podman"
    "podman-compose"
    "openscap-scanner"
    "openssh-clients"
    "python3"
    "python3-pip"
)

echo "Downloading RPM dependencies..."
mkdir -p dependencies

for dep in "${DEPENDENCIES[@]}"; do
    echo "Downloading $dep..."
    dnf download --downloadonly --downloaddir=dependencies "$dep" || \
        yum download --downloadonly --downloaddir=dependencies "$dep" || \
        echo "Failed to download $dep"
done

echo "Dependencies downloaded to dependencies/"
DEPS_EOF
    chmod +x "$WORK_DIR/rpm/download-dependencies.sh"
}

# Create installation scripts
create_installation_scripts() {
    log_info "Creating installation scripts..."

    # Main offline installer
    cat > "$WORK_DIR/offline-install.sh" << 'EOF'
#!/bin/bash
# OpenWatch Air-Gapped Installation Script

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log_info "OpenWatch Air-Gapped Installation"
log_info "=================================="

# Install RPM dependencies
log_info "Installing RPM dependencies..."
if [[ -d "$SCRIPT_DIR/rpm/dependencies" ]]; then
    dnf install -y "$SCRIPT_DIR"/rpm/dependencies/*.rpm || \
        yum install -y "$SCRIPT_DIR"/rpm/dependencies/*.rpm
    log_success "Dependencies installed"
else
    log_warning "No dependencies found - ensure they are downloaded"
fi

# Install OpenWatch RPM
log_info "Installing OpenWatch RPM..."
dnf install -y "$SCRIPT_DIR"/rpm/openwatch-*.rpm || \
    yum install -y "$SCRIPT_DIR"/rpm/openwatch-*.rpm
log_success "OpenWatch RPM installed"

# Load container images
log_info "Loading container images..."
"$SCRIPT_DIR/load-images.sh"

# Apply Podman fixes
log_info "Applying Podman configuration fixes..."
if [[ -f "/usr/share/openwatch/scripts/fix-podman-permissions.sh" ]]; then
    /usr/share/openwatch/scripts/fix-podman-permissions.sh
else
    log_warning "Podman fix script not found"
fi

log_success "OpenWatch air-gapped installation completed!"
log_info ""
log_info "Next steps:"
log_info "1. Configure: /etc/openwatch/ow.yml"
log_info "2. Start: systemctl start openwatch"
log_info "3. Status: owadm status"
EOF

    # Image loader script
    cat > "$WORK_DIR/load-images.sh" << 'EOF'
#!/bin/bash
# Load container images from bundle

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="$SCRIPT_DIR/images"

echo "Loading container images..."

if [[ ! -f "$IMAGES_DIR/image-manifest.json" ]]; then
    echo "Error: Image manifest not found"
    exit 1
fi

# Load each image file
for image_file in "$IMAGES_DIR"/*.tar; do
    if [[ -f "$image_file" ]]; then
        echo "Loading $(basename "$image_file")..."
        podman load -i "$image_file"
    fi
done

echo "All images loaded successfully!"

# List loaded images
echo ""
echo "Loaded images:"
podman images --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.Created}}"
EOF

    # Verification script
    cat > "$WORK_DIR/verify-bundle.sh" << 'EOF'
#!/bin/bash
# Verify bundle integrity

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Verifying OpenWatch bundle integrity..."

# Check required directories
REQUIRED_DIRS=("images" "rpm" "scripts")
for dir in "${REQUIRED_DIRS[@]}"; do
    if [[ ! -d "$SCRIPT_DIR/$dir" ]]; then
        echo "Error: Missing directory $dir"
        exit 1
    fi
done

# Verify image checksums
if [[ -f "$SCRIPT_DIR/images/image-manifest.json" ]]; then
    echo "Verifying image checksums..."
    cd "$SCRIPT_DIR/images"

    # Extract checksums and verify
    jq -r '.images[] | "\(.sha256)  \(.file)"' image-manifest.json > checksums.txt
    if sha256sum -c checksums.txt; then
        echo "[OK] All image checksums verified"
    else
        echo "[FAIL] Checksum verification failed"
        exit 1
    fi
    rm checksums.txt
fi

# Check RPM file
if ls "$SCRIPT_DIR"/rpm/openwatch-*.rpm >/dev/null 2>&1; then
    echo "[OK] OpenWatch RPM found"
else
    echo "[FAIL] OpenWatch RPM not found"
    exit 1
fi

echo ""
echo "Bundle verification completed successfully!"
EOF

    chmod +x "$WORK_DIR"/{offline-install.sh,load-images.sh,verify-bundle.sh}
    log_success "Installation scripts created"
}

# Create documentation
create_documentation() {
    log_info "Creating documentation..."

    cat > "$WORK_DIR/README-AIRGAP.md" << EOF
# OpenWatch Air-Gapped Installation

This bundle contains everything needed to install OpenWatch in an air-gapped environment.

## Bundle Contents

- **images/**: Container images (.tar files)
- **rpm/**: OpenWatch RPM and dependencies
- **scripts/**: Installation and management scripts
- **docs/**: Documentation

## Prerequisites

- RHEL 8+, Oracle Linux 8+, or compatible
- Root access
- Minimum 4GB RAM, 20GB disk space

## Installation Steps

### 1. Extract Bundle
\`\`\`bash
tar -xzf openwatch-bundle-${BUNDLE_VERSION}.tar.gz
cd openwatch-bundle-${BUNDLE_VERSION}
\`\`\`

### 2. Verify Bundle (Optional)
\`\`\`bash
./verify-bundle.sh
\`\`\`

### 3. Install OpenWatch
\`\`\`bash
sudo ./offline-install.sh
\`\`\`

### 4. Configure and Start
\`\`\`bash
# Edit configuration
sudo vi /etc/openwatch/ow.yml

# Start services
sudo systemctl start openwatch

# Check status
sudo owadm status
\`\`\`

## Troubleshooting

If container issues occur:
\`\`\`bash
sudo /usr/share/openwatch/scripts/podman-troubleshoot.sh
\`\`\`

## Manual Image Loading

If needed, load images manually:
\`\`\`bash
./load-images.sh
\`\`\`

## Support

- Documentation: /usr/share/doc/openwatch/
- Logs: /var/log/openwatch/
- Config: /etc/openwatch/

Generated: $(date)
Bundle Version: ${BUNDLE_VERSION}
EOF

    log_success "Documentation created"
}

# Create the final bundle
create_final_bundle() {
    log_info "Creating final bundle archive..."

    cd "$(dirname "$WORK_DIR")"
    tar -czf "${OUTPUT_DIR}/${BUNDLE_NAME}.tar.gz" "$(basename "$WORK_DIR")"

    # Generate checksums
    cd "$OUTPUT_DIR"
    sha256sum "${BUNDLE_NAME}.tar.gz" > "${BUNDLE_NAME}.tar.gz.sha256"

    # Bundle info
    local bundle_size=$(du -sh "${BUNDLE_NAME}.tar.gz" | cut -f1)

    log_success "Bundle created successfully!"
    log_info ""
    log_info "Bundle Information:"
    log_info "  File: ${OUTPUT_DIR}/${BUNDLE_NAME}.tar.gz"
    log_info "  Size: $bundle_size"
    log_info "  SHA256: $(cat "${BUNDLE_NAME}.tar.gz.sha256")"
    log_info ""
    log_info "Transfer this file to your air-gapped environment"
}

# Cleanup
cleanup() {
    log_info "Cleaning up temporary files..."
    rm -rf "$WORK_DIR"
    log_success "Cleanup completed"
}

# Check for Docker Hub rate limiting
check_rate_limit() {
    log_info "Checking Docker Hub rate limit status..."

    # Try to pull a small test image
    if timeout 30 podman pull hello-world >/dev/null 2>&1; then
        log_success "Docker Hub is accessible"
        podman rmi hello-world >/dev/null 2>&1 || true
        return 0
    else
        log_warning "Docker Hub may be rate limited or inaccessible"
        log_info "You can still proceed - fallback registries will be used"

        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Bundle creation cancelled"
            exit 0
        fi
        return 1
    fi
}

# Main execution
main() {
    log_info "Starting OpenWatch air-gap bundle creation..."
    log_info "Bundle version: $BUNDLE_VERSION"
    log_info "Output directory: $OUTPUT_DIR"
    log_info ""

    check_prerequisites
    check_rate_limit
    create_bundle_structure

    # Pull images (may fail due to rate limits)
    if ! pull_and_save_images; then
        log_warning "Image pulling had issues - bundle may be incomplete"
        log_info "You can still proceed with available images"

        read -p "Continue creating bundle? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            cleanup
            exit 1
        fi
    fi

    build_custom_images
    copy_rpm_dependencies
    create_installation_scripts
    create_documentation
    create_final_bundle
    cleanup

    log_success "Air-gap bundle creation completed!"
    log_info ""
    log_info "Next Steps:"
    log_info "1. Transfer the bundle to your air-gapped environment"
    log_info "2. Extract: tar -xzf ${BUNDLE_NAME}.tar.gz"
    log_info "3. Install: sudo ./offline-install.sh"
}

# Handle interruption
trap cleanup EXIT

# Run main function
main "$@"
