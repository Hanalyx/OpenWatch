#!/bin/bash
# Switch to alternative container registries to avoid Docker Hub rate limits

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

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root"
    exit 1
fi

DOCKER_DIR="/usr/share/openwatch/docker"
BACKUP_DIR="/usr/share/openwatch/docker/backup-$(date +%Y%m%d-%H%M%S)"

log_info "Creating backup of Containerfiles..."
mkdir -p "$BACKUP_DIR"
cp "$DOCKER_DIR"/Containerfile.* "$BACKUP_DIR/" 2>/dev/null || true
cp "$DOCKER_DIR"/Dockerfile.* "$BACKUP_DIR/" 2>/dev/null || true

# Alternative registries that don't have rate limits
log_info "Switching to alternative registries..."

# Update frontend Containerfile to use quay.io
if [[ -f "$DOCKER_DIR/Containerfile.frontend" ]]; then
    sed -i 's|docker.io/library/node:18-alpine|quay.io/nodejs/node:18-alpine|g' "$DOCKER_DIR/Containerfile.frontend"
    sed -i 's|docker.io/library/nginx:alpine|quay.io/nginx/nginx:alpine|g' "$DOCKER_DIR/Containerfile.frontend"
    log_success "Updated frontend Containerfile to use quay.io"
fi

# Update backend Containerfile to use registry.redhat.io (already using UBI)
if [[ -f "$DOCKER_DIR/Containerfile.backend" ]]; then
    # UBI images are already from registry.access.redhat.com, no Docker Hub dependency
    log_info "Backend already uses Red Hat registry (no changes needed)"
fi

# Create alternative Containerfiles for different registries
log_info "Creating alternative Containerfiles..."

# Frontend with gcr.io
cat > "$DOCKER_DIR/Containerfile.frontend.gcr" << 'EOF'
# Multi-stage build for OpenWatch Frontend using gcr.io
FROM gcr.io/distroless/nodejs:18 AS builder

WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci --only=production

COPY frontend/ .
RUN npm run build

# Production stage
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /app/build /usr/share/nginx/html
EXPOSE 80
EOF

# Frontend with ghcr.io (GitHub Container Registry)
cat > "$DOCKER_DIR/Containerfile.frontend.ghcr" << 'EOF'
# Multi-stage build for OpenWatch Frontend using GitHub Container Registry
FROM ghcr.io/node-js/node:18-alpine AS builder

WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci --only=production

COPY frontend/ .
RUN npm run build

# Production stage
FROM ghcr.io/nginx/nginx:alpine
COPY --from=builder /app/build /usr/share/nginx/html
COPY docker/frontend/default.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
EOF

# Create a registry selector script
cat > "$DOCKER_DIR/select-registry.sh" << 'EOF'
#!/bin/bash
# Select which container registry to use based on availability

set -euo pipefail

REGISTRIES=(
    "quay.io"
    "ghcr.io"
    "gcr.io"
    "registry.access.redhat.com"
)

test_registry() {
    local registry="$1"
    local test_image="$2"

    echo "Testing $registry..."
    if timeout 10 podman pull "$registry/$test_image" --quiet; then
        echo "[OK] $registry is available"
        return 0
    else
        echo "[FAIL] $registry failed or timed out"
        return 1
    fi
}

echo "Testing container registries for availability..."
echo "================================================"

for registry in "${REGISTRIES[@]}"; do
    case $registry in
        "quay.io")
            if test_registry "$registry" "nodejs/node:18-alpine"; then
                PREFERRED_REGISTRY="$registry"
                break
            fi
            ;;
        "ghcr.io")
            if test_registry "$registry" "nginx/nginx:alpine"; then
                PREFERRED_REGISTRY="$registry"
                break
            fi
            ;;
        "gcr.io")
            if test_registry "$registry" "distroless/nodejs:18"; then
                PREFERRED_REGISTRY="$registry"
                break
            fi
            ;;
        "registry.access.redhat.com")
            if test_registry "$registry" "ubi9/ubi:latest"; then
                PREFERRED_REGISTRY="$registry"
                break
            fi
            ;;
    esac
done

if [[ -n "${PREFERRED_REGISTRY:-}" ]]; then
    echo ""
    echo "Recommended registry: $PREFERRED_REGISTRY"
    echo "Use Containerfile.frontend.${PREFERRED_REGISTRY//\./_} if available"
else
    echo ""
    echo "Warning: All registries appear to be unavailable or rate limited"
    echo "Consider waiting for Docker Hub rate limit to reset (6 hours)"
fi
EOF

chmod +x "$DOCKER_DIR/select-registry.sh"

log_success "Created alternative registry configurations"
log_info "Files created:"
log_info "  - $DOCKER_DIR/Containerfile.frontend.gcr"
log_info "  - $DOCKER_DIR/Containerfile.frontend.ghcr"
log_info "  - $DOCKER_DIR/select-registry.sh"
log_info "  - Backup: $BACKUP_DIR/"
log_info ""
log_info "To test registries:"
log_info "  $DOCKER_DIR/select-registry.sh"
log_info ""
log_warning "Docker Hub rate limit typically resets after 6 hours"
log_warning "Wait until 19:52 or later before retrying with docker.io"
