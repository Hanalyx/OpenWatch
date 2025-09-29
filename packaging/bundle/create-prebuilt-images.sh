#!/bin/bash
# Create pre-built OpenWatch images for offline deployment
# This script builds and packages only the custom OpenWatch components

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
OUTPUT_DIR="$(pwd)/prebuilt-images"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Create output directory
mkdir -p "$OUTPUT_DIR"

log_info "Creating OpenWatch pre-built images v$VERSION"
log_info "=============================================="

# Build OpenWatch backend image with all dependencies
log_info "Building OpenWatch backend image..."
cat > "$PROJECT_ROOT/docker/Containerfile.backend.prebuilt" << 'EOF'
# Pre-built OpenWatch Backend Image
FROM registry.access.redhat.com/ubi9/ubi:latest

# Install system dependencies
RUN dnf update -y && \
    dnf install -y python3 python3-pip python3-devel \
                   postgresql-devel gcc gcc-c++ make \
                   openscap-scanner openssh-clients && \
    dnf clean all

# Create application user
RUN useradd -r -u 1001 -g root openwatch

# Set working directory
WORKDIR /app

# Copy backend code
COPY backend/ ./

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy configuration
COPY packaging/config/ow.yml.template /etc/openwatch/ow.yml

# Set permissions
RUN chown -R 1001:0 /app && chmod -R g=u /app

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run as non-root
USER 1001

# Start application
CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF

# Build OpenWatch frontend image
log_info "Building OpenWatch frontend image..."
cat > "$PROJECT_ROOT/docker/Containerfile.frontend.prebuilt" << 'EOF'
# Pre-built OpenWatch Frontend Image
FROM registry.access.redhat.com/ubi9/ubi:latest AS builder

# Install Node.js
RUN dnf update -y && \
    dnf install -y nodejs npm && \
    dnf clean all

WORKDIR /app

# Copy frontend source
COPY frontend/package*.json ./
RUN npm ci --only=production

COPY frontend/ ./
RUN npm run build

# Production stage
FROM registry.access.redhat.com/ubi9/ubi:latest

# Install nginx
RUN dnf update -y && \
    dnf install -y nginx && \
    dnf clean all

# Copy built frontend
COPY --from=builder /app/build /usr/share/nginx/html

# Copy nginx configuration
COPY docker/frontend/default.conf /etc/nginx/conf.d/default.conf

# Create nginx user
RUN useradd -r -u 1001 nginx || true

# Set permissions
RUN chown -R 1001:0 /usr/share/nginx/html && \
    chown -R 1001:0 /var/log/nginx && \
    chown -R 1001:0 /etc/nginx && \
    chmod -R g=u /var/log/nginx /etc/nginx

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# Run as non-root
USER 1001

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
EOF

# Build the images
cd "$PROJECT_ROOT"

log_info "Building backend image..."
if podman build -t openwatch-backend:$VERSION -f docker/Containerfile.backend.prebuilt .; then
    log_success "Backend image built successfully"
else
    log_warning "Backend image build failed - check Containerfile"
fi

log_info "Building frontend image..."
if podman build -t openwatch-frontend:$VERSION -f docker/Containerfile.frontend.prebuilt .; then
    log_success "Frontend image built successfully"
else
    log_warning "Frontend image build failed - check Containerfile"
fi

# Save images to files
log_info "Saving images to files..."
podman save -o "$OUTPUT_DIR/openwatch-backend-$VERSION.tar" openwatch-backend:$VERSION
podman save -o "$OUTPUT_DIR/openwatch-frontend-$VERSION.tar" openwatch-frontend:$VERSION

# Create load script
cat > "$OUTPUT_DIR/load-openwatch-images.sh" << EOF
#!/bin/bash
# Load pre-built OpenWatch images

set -euo pipefail

SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"

echo "Loading OpenWatch pre-built images..."

# Load backend image
if [[ -f "\$SCRIPT_DIR/openwatch-backend-$VERSION.tar" ]]; then
    echo "Loading OpenWatch backend..."
    podman load -i "\$SCRIPT_DIR/openwatch-backend-$VERSION.tar"
    echo "✓ Backend image loaded"
else
    echo "✗ Backend image file not found"
fi

# Load frontend image  
if [[ -f "\$SCRIPT_DIR/openwatch-frontend-$VERSION.tar" ]]; then
    echo "Loading OpenWatch frontend..."
    podman load -i "\$SCRIPT_DIR/openwatch-frontend-$VERSION.tar"
    echo "✓ Frontend image loaded"
else
    echo "✗ Frontend image file not found"
fi

echo ""
echo "Loaded OpenWatch images:"
podman images | grep openwatch || echo "No OpenWatch images found"
EOF

chmod +x "$OUTPUT_DIR/load-openwatch-images.sh"

# Create compose file for pre-built images
cat > "$OUTPUT_DIR/podman-compose-prebuilt.yml" << EOF
version: '3.8'

services:
  database:
    image: docker.io/postgres:15-alpine
    container_name: openwatch-database
    environment:
      POSTGRES_USER: openwatch
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD:-changeme}
      POSTGRES_DB: openwatch
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U openwatch -d openwatch"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: docker.io/redis:7-alpine
    container_name: openwatch-redis
    command: redis-server --requirepass \${REDIS_PASSWORD:-changeme}
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  backend:
    image: openwatch-backend:$VERSION
    container_name: openwatch-backend
    environment:
      - DATABASE_URL=postgresql://openwatch:\${POSTGRES_PASSWORD:-changeme}@database:5432/openwatch
      - REDIS_URL=redis://:\${REDIS_PASSWORD:-changeme}@redis:6379/0
    volumes:
      - backend_data:/app/data
      - backend_logs:/app/logs
    ports:
      - "8000:8000"
    depends_on:
      - database
      - redis
    restart: unless-stopped

  frontend:
    image: openwatch-frontend:$VERSION
    container_name: openwatch-frontend
    ports:
      - "3001:8080"
    depends_on:
      - backend
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
  backend_data:
  backend_logs:
EOF

# Create usage instructions
cat > "$OUTPUT_DIR/README.md" << EOF
# OpenWatch Pre-built Images

This directory contains pre-built OpenWatch container images for offline deployment.

## Contents

- \`openwatch-backend-$VERSION.tar\` - Backend application image
- \`openwatch-frontend-$VERSION.tar\` - Frontend application image  
- \`load-openwatch-images.sh\` - Script to load images
- \`podman-compose-prebuilt.yml\` - Compose file for pre-built images

## Usage

### 1. Load Images
\`\`\`bash
./load-openwatch-images.sh
\`\`\`

### 2. Start Services
\`\`\`bash
# Set environment variables
export POSTGRES_PASSWORD="your-secure-password"
export REDIS_PASSWORD="your-redis-password"

# Start with compose
podman-compose -f podman-compose-prebuilt.yml up -d
\`\`\`

### 3. Access OpenWatch
- Frontend: http://localhost:3001
- Backend API: http://localhost:8000
- Database: localhost:5432

## Notes

- You still need to pull external images (postgres, redis) from registries
- For completely air-gapped environments, use the full bundle creator
- These images include all OpenWatch-specific code and dependencies

Generated: $(date)
Version: $VERSION
EOF

# Calculate sizes and create summary
log_info "Creating bundle summary..."
backend_size=$(du -sh "$OUTPUT_DIR/openwatch-backend-$VERSION.tar" | cut -f1)
frontend_size=$(du -sh "$OUTPUT_DIR/openwatch-frontend-$VERSION.tar" | cut -f1)
total_size=$(du -sh "$OUTPUT_DIR" | cut -f1)

log_success "Pre-built images created successfully!"
log_info ""
log_info "Created files:"
log_info "  📁 Directory: $OUTPUT_DIR"
log_info "  🐳 Backend image: openwatch-backend-$VERSION.tar ($backend_size)"
log_info "  🌐 Frontend image: openwatch-frontend-$VERSION.tar ($frontend_size)"
log_info "  📜 Load script: load-openwatch-images.sh"
log_info "  🐙 Compose file: podman-compose-prebuilt.yml"
log_info "  📖 Documentation: README.md"
log_info "  📊 Total size: $total_size"
log_info ""
log_info "Next steps:"
log_info "1. Transfer $OUTPUT_DIR to target system"
log_info "2. Run ./load-openwatch-images.sh"
log_info "3. Use podman-compose-prebuilt.yml to start services"