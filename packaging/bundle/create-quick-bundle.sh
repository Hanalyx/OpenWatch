#!/bin/bash
# Quick OpenWatch Bundle Creator
# Creates a lightweight bundle using standard base images + OpenWatch source

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

# Configuration
VERSION="1.2.1-8"
BUNDLE_NAME="openwatch-quick-bundle-$VERSION"
OUTPUT_DIR="$(pwd)/$BUNDLE_NAME"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Lightweight image set (only essential images)
ESSENTIAL_IMAGES=(
    "docker.io/postgres:15-alpine"
    "docker.io/redis:7-alpine"
    "registry.access.redhat.com/ubi9/ubi:latest"
    "docker.io/python:3.11-slim"
    "docker.io/nginx:alpine"
)

log_info "Creating OpenWatch Quick Bundle v$VERSION"
log_info "=========================================="

# Create bundle structure
mkdir -p "$OUTPUT_DIR"/{images,rpm,source,configs,scripts}

# Download essential images only
log_info "Downloading essential base images..."
for image in "${ESSENTIAL_IMAGES[@]}"; do
    image_name=$(echo "$image" | sed 's|.*/||' | tr ':' '-')
    log_info "Saving $image..."

    if podman pull "$image" && podman save -o "$OUTPUT_DIR/images/${image_name}.tar" "$image"; then
        log_success "Saved $image"
    else
        log_warning "Failed to save $image - skipping"
    fi
done

# Copy OpenWatch source code
log_info "Copying OpenWatch source code..."
cd "$PROJECT_ROOT"

# Create source archive
tar --exclude='.git' --exclude='node_modules' --exclude='venv' \
    --exclude='*.rpm' --exclude='dist' --exclude='__pycache__' \
    -czf "$OUTPUT_DIR/source/openwatch-source-$VERSION.tar.gz" .

log_success "Source code archived"

# Copy RPM if available
if [[ -f "$PROJECT_ROOT/packaging/rpm/dist/openwatch-$VERSION.x86_64.rpm" ]]; then
    cp "$PROJECT_ROOT/packaging/rpm/dist/openwatch-$VERSION.x86_64.rpm" "$OUTPUT_DIR/rpm/"
    log_success "OpenWatch RPM copied"
else
    log_warning "OpenWatch RPM not found"
fi

# Create runtime compose files
log_info "Creating runtime configuration..."

cat > "$OUTPUT_DIR/configs/docker-compose-airgap.yml" << EOF
version: '3.8'

services:
  database:
    image: postgres:15-alpine
    container_name: openwatch-database
    environment:
      POSTGRES_USER: openwatch
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
      POSTGRES_DB: openwatch
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./source/backend/docker/database/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    ports:
      - "5432:5432"
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    container_name: openwatch-redis
    command: redis-server --requirepass \${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    restart: unless-stopped

  backend:
    image: python:3.11-slim
    container_name: openwatch-backend
    working_dir: /app
    command: >
      bash -c "
        apt-get update &&
        apt-get install -y gcc libpq-dev curl &&
        pip install --no-cache-dir -r requirements.txt &&
        python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
      "
    environment:
      - DATABASE_URL=postgresql://openwatch:\${POSTGRES_PASSWORD}@database:5432/openwatch
      - REDIS_URL=redis://:\${REDIS_PASSWORD}@redis:6379/0
    volumes:
      - ./source/backend:/app
      - backend_data:/app/data
    ports:
      - "8000:8000"
    depends_on:
      - database
      - redis
    restart: unless-stopped

  frontend:
    image: nginx:alpine
    container_name: openwatch-frontend
    volumes:
      - ./source/frontend/build:/usr/share/nginx/html:ro
      - ./source/docker/frontend/default.conf:/etc/nginx/conf.d/default.conf:ro
    ports:
      - "3001:80"
    depends_on:
      - backend
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
  backend_data:
EOF

# Create installation script
cat > "$OUTPUT_DIR/install-quick-bundle.sh" << 'EOF'
#!/bin/bash
# OpenWatch Quick Bundle Installer

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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log_info "OpenWatch Quick Bundle Installation"
log_info "==================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# Install OpenWatch RPM if available
if ls "$SCRIPT_DIR"/rpm/openwatch-*.rpm >/dev/null 2>&1; then
    log_info "Installing OpenWatch RPM..."
    dnf install -y "$SCRIPT_DIR"/rpm/openwatch-*.rpm || \
        yum install -y "$SCRIPT_DIR"/rpm/openwatch-*.rpm
    log_success "OpenWatch RPM installed"
fi

# Load container images
log_info "Loading container images..."
for image_file in "$SCRIPT_DIR"/images/*.tar; do
    if [[ -f "$image_file" ]]; then
        log_info "Loading $(basename "$image_file")..."
        podman load -i "$image_file"
    fi
done
log_success "Container images loaded"

# Extract source code
log_info "Extracting OpenWatch source..."
cd "$SCRIPT_DIR"
if [[ -f "source/openwatch-source-*.tar.gz" ]]; then
    tar -xzf source/openwatch-source-*.tar.gz -C source/
    log_success "Source code extracted"
fi

# Build frontend (if Node.js is available)
if command -v npm >/dev/null 2>&1; then
    log_info "Building frontend..."
    cd "$SCRIPT_DIR/source/frontend"
    npm install --production
    npm run build
    log_success "Frontend built"
else
    log_warning "Node.js not available - frontend will need manual build"
fi

# Apply Podman fixes
if [[ -f "/usr/share/openwatch/scripts/fix-podman-permissions.sh" ]]; then
    log_info "Applying Podman fixes..."
    /usr/share/openwatch/scripts/fix-podman-permissions.sh
fi

log_success "Quick bundle installation completed!"
log_info ""
log_info "Next steps:"
log_info "1. Set environment variables:"
log_info "   export POSTGRES_PASSWORD='your-password'"
log_info "   export REDIS_PASSWORD='your-redis-password'"
log_info "2. Start services:"
log_info "   cd $SCRIPT_DIR"
log_info "   podman-compose -f configs/docker-compose-airgap.yml up -d"
log_info "3. Access OpenWatch at http://localhost:3001"
EOF

chmod +x "$OUTPUT_DIR/install-quick-bundle.sh"

# Create load images script
cat > "$OUTPUT_DIR/scripts/load-images.sh" << 'EOF'
#!/bin/bash
# Load all images from the bundle

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="$(dirname "$SCRIPT_DIR")"

echo "Loading OpenWatch bundle images..."

for image_file in "$BUNDLE_DIR"/images/*.tar; do
    if [[ -f "$image_file" ]]; then
        echo "Loading $(basename "$image_file")..."
        podman load -i "$image_file"
    fi
done

echo "All images loaded!"
podman images
EOF

chmod +x "$OUTPUT_DIR/scripts/load-images.sh"

# Create README
cat > "$OUTPUT_DIR/README.md" << EOF
# OpenWatch Quick Bundle

Lightweight air-gapped deployment bundle for OpenWatch.

## Contents

- **images/**: Essential container images (.tar files)
- **rpm/**: OpenWatch RPM package
- **source/**: OpenWatch source code archive
- **configs/**: Docker Compose configurations
- **scripts/**: Helper scripts

## Installation

### Quick Install (Recommended)
\`\`\`bash
sudo ./install-quick-bundle.sh
\`\`\`

### Manual Install

1. **Load Images**
\`\`\`bash
./scripts/load-images.sh
\`\`\`

2. **Install RPM**
\`\`\`bash
sudo dnf install rpm/openwatch-*.rpm
\`\`\`

3. **Extract Source**
\`\`\`bash
tar -xzf source/openwatch-source-*.tar.gz
\`\`\`

4. **Start Services**
\`\`\`bash
export POSTGRES_PASSWORD="your-password"
export REDIS_PASSWORD="your-redis-password"
podman-compose -f configs/docker-compose-airgap.yml up -d
\`\`\`

## Requirements

- Podman/Docker
- 4GB RAM minimum
- 10GB disk space

## Access

- Frontend: http://localhost:3001
- Backend API: http://localhost:8000

Generated: $(date)
Version: $VERSION
EOF

# Create bundle archive
log_info "Creating bundle archive..."
cd "$(dirname "$OUTPUT_DIR")"
tar -czf "${BUNDLE_NAME}.tar.gz" "$(basename "$OUTPUT_DIR")"

# Calculate sizes
bundle_size=$(du -sh "${BUNDLE_NAME}.tar.gz" | cut -f1)
images_size=$(du -sh "$OUTPUT_DIR/images" | cut -f1)

log_success "Quick bundle created successfully!"
log_info ""
log_info "Bundle Summary:"
log_info "  Bundle: ${BUNDLE_NAME}.tar.gz ($bundle_size)"
log_info "  Images: $images_size"
log_info "  Directory: $OUTPUT_DIR"
log_info ""
log_info "Transfer ${BUNDLE_NAME}.tar.gz to your air-gapped environment"
log_info "Extract and run: sudo ./install-quick-bundle.sh"
