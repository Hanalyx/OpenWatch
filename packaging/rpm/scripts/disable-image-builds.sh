#!/bin/bash
# Disable image building to avoid Docker Hub rate limits
# This modifies compose files to use pre-built images instead

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

COMPOSE_DIR="/usr/share/openwatch/compose"
BACKUP_DIR="/usr/share/openwatch/compose/backup-$(date +%Y%m%d-%H%M%S)"

log_info "Creating backup of compose files..."
mkdir -p "$BACKUP_DIR"
cp "$COMPOSE_DIR"/*.yml "$BACKUP_DIR/" 2>/dev/null || true

# Modify podman-compose.yml to use pre-built images
log_info "Modifying compose files to use pre-built images..."

# Create modified podman-compose.yml
cat > "$COMPOSE_DIR/podman-compose-no-build.yml" << 'EOF'
version: '3.8'

services:
  database:
    image: docker.io/postgres:15-alpine
    container_name: openwatch-database
    environment:
      POSTGRES_USER: openwatch
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: openwatch
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./docker/database/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
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
    command: redis-server --requirepass ${REDIS_PASSWORD}
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
    image: docker.io/python:3.11-slim
    container_name: openwatch-backend
    working_dir: /app
    command: >
      bash -c "
        echo 'Installing Python dependencies...' &&
        pip install --no-cache-dir fastapi uvicorn sqlalchemy psycopg2-binary redis celery alembic &&
        echo 'Backend would start here - placeholder for now' &&
        sleep infinity
      "
    environment:
      - DATABASE_URL=postgresql://openwatch:${POSTGRES_PASSWORD}@database:5432/openwatch
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0
    volumes:
      - backend_data:/app/data
    ports:
      - "8000:8000"
    depends_on:
      - database
      - redis
    restart: unless-stopped

  frontend:
    image: docker.io/nginx:alpine
    container_name: openwatch-frontend
    volumes:
      - frontend_data:/usr/share/nginx/html
      - ./docker/frontend/default.conf:/etc/nginx/conf.d/default.conf:ro
    ports:
      - "3001:80"
    depends_on:
      - backend
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
  backend_data:
  frontend_data:
EOF

# Create a start script that uses the no-build compose
cat > "$COMPOSE_DIR/start-no-build.sh" << 'EOF'
#!/bin/bash
# Start OpenWatch without building images (avoids Docker Hub rate limits)

set -euo pipefail

cd /usr/share/openwatch/compose

echo "Starting OpenWatch with pre-built images (no Docker Hub builds)..."
echo "This avoids Docker Hub rate limiting issues."
echo ""

# Use the no-build compose file
podman-compose -f podman-compose-no-build.yml up -d

echo ""
echo "OpenWatch started with pre-built images!"
echo "Note: This is a minimal configuration to avoid rate limits."
echo "Backend and frontend will need manual setup."
EOF

chmod +x "$COMPOSE_DIR/start-no-build.sh"

log_success "Created no-build compose configuration"
log_info "Files created:"
log_info "  - $COMPOSE_DIR/podman-compose-no-build.yml"
log_info "  - $COMPOSE_DIR/start-no-build.sh"
log_info "  - Backup: $BACKUP_DIR/"
log_info ""
log_info "To use:"
log_info "  cd $COMPOSE_DIR"
log_info "  ./start-no-build.sh"
log_info ""
log_warning "This is a temporary workaround for Docker Hub rate limits"
log_warning "Full functionality requires the original compose files"