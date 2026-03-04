#!/bin/bash
# OpenWatch DEB Build Script
# Builds native DEB packages for Ubuntu 24.04+ distribution
# Air-gapped: bundles backend, frontend, Kensa rules, and owadm binary

set -euo pipefail

# Build configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PACKAGE_NAME="openwatch"
ARCH="amd64"

# Source version from single source of truth
source "$SCRIPT_DIR/../version.env"

# Convert semver pre-release for Debian: "0.0.0-dev" -> "0.0.0~dev1"
if [[ "$VERSION" == *"-"* ]]; then
    deb_base="${VERSION%-*}"
    deb_pre="${VERSION#*-}"
    DEB_VERSION="${deb_base}~${deb_pre}1"
else
    DEB_VERSION="${VERSION}-1"
fi

# Build directory
BUILD_DIR="$SCRIPT_DIR/build"
PACKAGE_DIR="$BUILD_DIR/${PACKAGE_NAME}_${DEB_VERSION}_${ARCH}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

log_success() {
    echo -e "${GREEN}[OK] $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

log_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking build prerequisites..."

    # Check if we're on Debian/Ubuntu
    if ! command -v dpkg >/dev/null 2>&1; then
        log_error "Debian packaging tools not found. This script requires Ubuntu or Debian."
        exit 1
    fi

    # Check for required tools
    local missing_tools=()
    for tool in dpkg-deb fakeroot go git npm python3; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Install with: sudo apt install build-essential golang-go git nodejs npm python3-venv"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# Clean build directory
clean_build() {
    log_info "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
}

# Build owadm binary
build_binary() {
    log_info "Building owadm binary..."

    cd "$PROJECT_ROOT"

    # Build with proper flags
    export CGO_ENABLED=0
    export GOOS=linux
    export GOARCH=amd64

    # Set build-time variables (VERSION and CODENAME sourced from packaging/version.env)
    LDFLAGS="-s -w \
        -X github.com/hanalyx/openwatch/internal/owadm/cmd.Version=$VERSION \
        -X github.com/hanalyx/openwatch/internal/owadm/cmd.Codename=$CODENAME \
        -X github.com/hanalyx/openwatch/internal/owadm/cmd.Commit=$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown') \
        -X github.com/hanalyx/openwatch/internal/owadm/cmd.BuildTime=$(date -u '+%Y-%m-%d_%H:%M:%S')"

    # Build with native tag (excludes container-specific commands)
    go build -tags native -ldflags "$LDFLAGS" -o "$BUILD_DIR/owadm" cmd/owadm/main.go

    if [ ! -f "$BUILD_DIR/owadm" ]; then
        log_error "Failed to build owadm binary"
        exit 1
    fi

    log_success "Binary built successfully"
}

# Build frontend
build_frontend() {
    log_info "Building frontend..."

    cd "$PROJECT_ROOT/frontend"
    npm ci --production=false
    npm run build
    cd "$PROJECT_ROOT"

    if [ ! -d "$PROJECT_ROOT/frontend/build" ]; then
        log_error "Frontend build output not found at frontend/build/"
        exit 1
    fi

    log_success "Frontend built successfully"
}

# Install Kensa rules from pip package
install_kensa_data() {
    log_info "Installing Kensa rules and mappings..."

    local venv_dir="$BUILD_DIR/.kensa-build-venv"
    python3 -m venv "$venv_dir"
    "$venv_dir/bin/pip" install --quiet -r "$PROJECT_ROOT/backend/requirements.txt"

    KENSA_SHARE=$(find "$venv_dir" -path '*/share/kensa' -type d | head -1)
    if [ -z "$KENSA_SHARE" ]; then
        log_error "Could not locate Kensa share directory after pip install"
        exit 1
    fi

    # Copy to a staging location
    cp -r "$KENSA_SHARE" "$BUILD_DIR/kensa-data"

    local rule_count
    rule_count=$(find "$BUILD_DIR/kensa-data/rules" -name "*.yml" | wc -l)
    log_success "Kensa data staged ($rule_count rules)"
}

# Create package structure
create_package_structure() {
    log_info "Creating package structure..."

    # Create directory structure matching RPM native package
    mkdir -p "$PACKAGE_DIR/DEBIAN"
    mkdir -p "$PACKAGE_DIR/usr/bin"
    mkdir -p "$PACKAGE_DIR/opt/openwatch/venv"
    mkdir -p "$PACKAGE_DIR/opt/openwatch/backend/app"
    mkdir -p "$PACKAGE_DIR/opt/openwatch/backend/kensa"
    mkdir -p "$PACKAGE_DIR/opt/openwatch/backend/alembic"
    mkdir -p "$PACKAGE_DIR/opt/openwatch/frontend"
    mkdir -p "$PACKAGE_DIR/etc/openwatch/ssh"
    mkdir -p "$PACKAGE_DIR/etc/openwatch/ssl"
    mkdir -p "$PACKAGE_DIR/etc/nginx/sites-available"
    mkdir -p "$PACKAGE_DIR/lib/systemd/system"
    mkdir -p "$PACKAGE_DIR/usr/share/openwatch/scripts"
    mkdir -p "$PACKAGE_DIR/usr/share/doc/openwatch"
    mkdir -p "$PACKAGE_DIR/var/lib/openwatch/celery"
    mkdir -p "$PACKAGE_DIR/var/lib/openwatch/exports"
    mkdir -p "$PACKAGE_DIR/var/lib/openwatch/ssh"
    mkdir -p "$PACKAGE_DIR/var/log/openwatch"

    # Copy control files
    cp -r "$SCRIPT_DIR/DEBIAN"/* "$PACKAGE_DIR/DEBIAN/"

    # Update version in control file
    sed -i "s/^Version:.*/Version: $DEB_VERSION/" "$PACKAGE_DIR/DEBIAN/control"

    # --- Binary ---
    cp "$BUILD_DIR/owadm" "$PACKAGE_DIR/usr/bin/"
    chmod 755 "$PACKAGE_DIR/usr/bin/owadm"

    # --- Backend application ---
    cp -r "$PROJECT_ROOT/backend/app" "$PACKAGE_DIR/opt/openwatch/backend/"
    cp -r "$PROJECT_ROOT/backend/alembic" "$PACKAGE_DIR/opt/openwatch/backend/"
    cp "$PROJECT_ROOT/backend/requirements.txt" "$PACKAGE_DIR/opt/openwatch/backend/"
    cp "$PROJECT_ROOT/backend/alembic.ini" "$PACKAGE_DIR/opt/openwatch/backend/"

    # --- Kensa rules, mappings, config, schema ---
    cp -r "$BUILD_DIR/kensa-data"/* "$PACKAGE_DIR/opt/openwatch/backend/kensa/"

    # --- Frontend (pre-built React application) ---
    cp -r "$PROJECT_ROOT/frontend/build"/* "$PACKAGE_DIR/opt/openwatch/frontend/"

    # --- Configuration files ---
    create_config_files

    # --- Systemd service files ---
    create_systemd_files

    # --- Nginx configuration ---
    create_nginx_config

    # --- Helper scripts ---
    create_helper_scripts

    # --- Documentation ---
    cp "$PROJECT_ROOT/README.md" "$PACKAGE_DIR/usr/share/doc/openwatch/"
    cp "$PROJECT_ROOT/LICENSE" "$PACKAGE_DIR/usr/share/doc/openwatch/" 2>/dev/null || true
    create_changelog
    create_copyright

    log_success "Package structure created"
}

# Create configuration files
create_config_files() {
    log_info "Creating configuration files..."

    # Main configuration
    cat > "$PACKAGE_DIR/etc/openwatch/ow.yml" << 'EOF'
# OpenWatch Native Installation Configuration

# Runtime mode
runtime:
  mode: native                    # native (systemd) deployment

# Database configuration (system PostgreSQL)
database:
  host: localhost
  port: 5432
  name: openwatch
  user: openwatch
  # Password from secrets.env: OPENWATCH_DATABASE_PASSWORD
  ssl_mode: prefer
  pool_size: 25
  max_overflow: 10

# Redis configuration (system Redis)
redis:
  host: localhost
  port: 6379
  db: 0
  # Password from secrets.env: OPENWATCH_REDIS_PASSWORD

# API configuration
api:
  host: 127.0.0.1                 # Bind to localhost (nginx proxies)
  port: 8000
  workers: 4

# Celery configuration
celery:
  worker_concurrency: 4
  worker_instances: 2
  queues:
    - default
    - scans
    - results
    - maintenance
    - monitoring
    - compliance_scanning

# Scanning configuration (Kensa-based)
scanning:
  ssh_key_path: /etc/openwatch/ssh/openwatch_rsa
  concurrent_scans: 5
  timeout_seconds: 600

# Kensa compliance engine
kensa:
  rules_path: /opt/openwatch/backend/kensa/rules
  config_path: /opt/openwatch/backend/kensa/config

# Logging configuration
logging:
  level: INFO
  format: json
  api_log: /var/log/openwatch/api.log
  worker_log: /var/log/openwatch/worker.log
  audit_log: /var/log/openwatch/audit.log
  max_size_mb: 100
  max_age_days: 30

# Security configuration
security:
  fips_mode: false
  require_https: true
  session_timeout_minutes: 60
  jwt_algorithm: RS256
  jwt_private_key: /etc/openwatch/jwt_private.pem
  jwt_public_key: /etc/openwatch/jwt_public.pem
EOF

    # Secrets template
    cat > "$PACKAGE_DIR/etc/openwatch/secrets.env" << 'EOF'
# OpenWatch Secrets Configuration
# IMPORTANT: This file must have chmod 600 permissions
#
# After installation, run: /usr/share/openwatch/scripts/generate-secrets.sh
# to generate secure random values for all secrets.

# Database credentials
OPENWATCH_DATABASE_PASSWORD=CHANGEME_SECURE_DB_PASSWORD

# Redis credentials
OPENWATCH_REDIS_PASSWORD=CHANGEME_SECURE_REDIS_PASSWORD

# Application secrets
OPENWATCH_SECRET_KEY=CHANGEME_64_CHAR_SECRET_KEY
OPENWATCH_MASTER_KEY=CHANGEME_32_CHAR_MASTER_KEY
OPENWATCH_ENCRYPTION_KEY=CHANGEME_32_CHAR_ENCRYPTION_KEY

# JWT key paths
JWT_PRIVATE_KEY_PATH=/etc/openwatch/jwt_private.pem
JWT_PUBLIC_KEY_PATH=/etc/openwatch/jwt_public.pem

# Database URL (constructed from above)
DATABASE_URL=postgresql://openwatch:${OPENWATCH_DATABASE_PASSWORD}@localhost:5432/openwatch

# Redis URL (constructed from above)
REDIS_URL=redis://:${OPENWATCH_REDIS_PASSWORD}@localhost:6379/0

# Celery broker and backend
CELERY_BROKER_URL=redis://:${OPENWATCH_REDIS_PASSWORD}@localhost:6379/1
CELERY_RESULT_BACKEND=redis://:${OPENWATCH_REDIS_PASSWORD}@localhost:6379/2
EOF

    # Logging configuration
    cat > "$PACKAGE_DIR/etc/openwatch/logging.yml" << 'EOF'
version: 1
disable_existing_loggers: false

formatters:
  json:
    format: '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}'
    datefmt: '%Y-%m-%dT%H:%M:%S%z'
  standard:
    format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

handlers:
  console:
    class: logging.StreamHandler
    level: INFO
    formatter: standard
    stream: ext://sys.stdout

  api_file:
    class: logging.handlers.RotatingFileHandler
    level: INFO
    formatter: json
    filename: /var/log/openwatch/api.log
    maxBytes: 104857600  # 100MB
    backupCount: 5

  audit_file:
    class: logging.handlers.RotatingFileHandler
    level: INFO
    formatter: json
    filename: /var/log/openwatch/audit.log
    maxBytes: 104857600
    backupCount: 10

loggers:
  uvicorn:
    level: INFO
    handlers: [console, api_file]
    propagate: false

  openwatch:
    level: INFO
    handlers: [console, api_file]
    propagate: false

  openwatch.audit:
    level: INFO
    handlers: [audit_file]
    propagate: false

root:
  level: INFO
  handlers: [console]
EOF
}

# Create systemd service files
create_systemd_files() {
    log_info "Creating systemd service files..."

    # OpenWatch API service
    cat > "$PACKAGE_DIR/lib/systemd/system/openwatch-api.service" << 'EOF'
[Unit]
Description=OpenWatch API Server
Documentation=https://github.com/hanalyx/openwatch
After=network-online.target postgresql.service redis-server.service
Requires=postgresql.service redis-server.service
Wants=network-online.target

[Service]
Type=notify
User=openwatch
Group=openwatch
WorkingDirectory=/opt/openwatch/backend

# Environment
EnvironmentFile=/etc/openwatch/secrets.env
Environment=PYTHONPATH=/opt/openwatch/backend
Environment=OPENWATCH_CONFIG_FILE=/etc/openwatch/ow.yml

# Start command
ExecStart=/opt/openwatch/venv/bin/uvicorn \
    app.main:app \
    --host 127.0.0.1 \
    --port 8000 \
    --workers 4 \
    --log-config /etc/openwatch/logging.yml

# Lifecycle
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
TimeoutStartSec=120
TimeoutStopSec=30

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/openwatch /var/log/openwatch
ReadOnlyPaths=/opt/openwatch /etc/openwatch

# Resource limits
LimitNOFILE=65536
TasksMax=4096

[Install]
WantedBy=multi-user.target
EOF

    # OpenWatch Worker service (template for multiple instances)
    cat > "$PACKAGE_DIR/lib/systemd/system/openwatch-worker@.service" << 'EOF'
[Unit]
Description=OpenWatch Celery Worker %i
Documentation=https://github.com/hanalyx/openwatch
After=network-online.target postgresql.service redis-server.service openwatch-api.service
Requires=postgresql.service redis-server.service
PartOf=openwatch-api.service

[Service]
Type=notify
User=openwatch
Group=openwatch
WorkingDirectory=/opt/openwatch/backend

# Environment
EnvironmentFile=/etc/openwatch/secrets.env
Environment=PYTHONPATH=/opt/openwatch/backend
Environment=OPENWATCH_CONFIG_FILE=/etc/openwatch/ow.yml
Environment=C_FORCE_ROOT=false

# Celery worker command
ExecStart=/opt/openwatch/venv/bin/celery \
    -A app.celery_app worker \
    --loglevel=info \
    --hostname=worker-%i@%%h \
    --queues=default,scans,results,maintenance,monitoring,host_monitoring,health_monitoring,compliance_scanning \
    --concurrency=4 \
    --logfile=/var/log/openwatch/worker-%i.log

# Lifecycle
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10

# Security (less restrictive for SSH scanning)
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=false
ReadWritePaths=/var/lib/openwatch /var/log/openwatch /tmp
ReadOnlyPaths=/opt/openwatch /etc/openwatch /etc/ssl

# Resource limits
LimitNOFILE=16384
TasksMax=2048

[Install]
WantedBy=multi-user.target
EOF

    # OpenWatch Beat service (Celery scheduler)
    cat > "$PACKAGE_DIR/lib/systemd/system/openwatch-beat.service" << 'EOF'
[Unit]
Description=OpenWatch Celery Beat Scheduler
Documentation=https://github.com/hanalyx/openwatch
After=network-online.target postgresql.service redis-server.service
Requires=postgresql.service redis-server.service

[Service]
Type=simple
User=openwatch
Group=openwatch
WorkingDirectory=/opt/openwatch/backend

# Environment
EnvironmentFile=/etc/openwatch/secrets.env
Environment=PYTHONPATH=/opt/openwatch/backend
Environment=OPENWATCH_CONFIG_FILE=/etc/openwatch/ow.yml

# Celery beat command
ExecStart=/opt/openwatch/venv/bin/celery \
    -A app.celery_app beat \
    --loglevel=info \
    --logfile=/var/log/openwatch/beat.log \
    --schedule=/var/lib/openwatch/celery/celerybeat-schedule

Restart=on-failure
RestartSec=10

# Security
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
ReadWritePaths=/var/lib/openwatch /var/log/openwatch
ReadOnlyPaths=/opt/openwatch /etc/openwatch

[Install]
WantedBy=multi-user.target
EOF

    # OpenWatch target (starts all services)
    cat > "$PACKAGE_DIR/lib/systemd/system/openwatch.target" << 'EOF'
[Unit]
Description=OpenWatch Compliance Platform
Documentation=https://github.com/hanalyx/openwatch
Requires=openwatch-api.service openwatch-worker@1.service openwatch-beat.service
After=openwatch-api.service openwatch-worker@1.service openwatch-beat.service

[Install]
WantedBy=multi-user.target
EOF
}

# Create nginx configuration
create_nginx_config() {
    cat > "$PACKAGE_DIR/etc/nginx/sites-available/openwatch" << 'EOF'
# OpenWatch Nginx Configuration
# Reverse proxy for API + static file serving for frontend
#
# Enable with: ln -s /etc/nginx/sites-available/openwatch /etc/nginx/sites-enabled/

upstream openwatch_backend {
    server 127.0.0.1:8000;
    keepalive 32;
}

server {
    listen 80;
    server_name _;

    # Redirect HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name _;

    # TLS Configuration
    ssl_certificate /etc/openwatch/ssl/openwatch.crt;
    ssl_certificate_key /etc/openwatch/ssl/openwatch.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Frontend (React SPA)
    root /opt/openwatch/frontend;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # API Proxy
    location /api/ {
        proxy_pass http://openwatch_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
        proxy_buffering off;
    }

    # Health check (no auth required)
    location /health {
        proxy_pass http://openwatch_backend/health;
        proxy_http_version 1.1;
    }

    # Metrics (internal only)
    location /metrics {
        allow 127.0.0.1;
        deny all;
        proxy_pass http://openwatch_backend/metrics;
    }

    # Static assets caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOF
}

# Create helper scripts
create_helper_scripts() {
    log_info "Creating helper scripts..."

    # Secret generation script
    cat > "$PACKAGE_DIR/usr/share/openwatch/scripts/generate-secrets.sh" << 'EOFSCRIPT'
#!/bin/bash
# OpenWatch Secret Generation Script for Native Installation

set -euo pipefail

SECRETS_FILE="/etc/openwatch/secrets.env"
CONFIG_DIR="/etc/openwatch"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-32
}

generate_jwt_keys() {
    local private_key="$CONFIG_DIR/jwt_private.pem"
    local public_key="$CONFIG_DIR/jwt_public.pem"

    log_info "Generating JWT key pair..."

    if openssl genpkey -algorithm RSA -out "$private_key" -pkeyopt rsa_keygen_bits:2048 2>/dev/null; then
        log_info "Generated private key"
    elif openssl genrsa -out "$private_key" 2048 2>/dev/null; then
        log_info "Generated private key (legacy method)"
    else
        log_error "Failed to generate RSA private key"
        exit 1
    fi

    if openssl pkey -in "$private_key" -pubout -out "$public_key" 2>/dev/null; then
        log_info "Extracted public key"
    elif openssl rsa -in "$private_key" -pubout -out "$public_key" 2>/dev/null; then
        log_info "Extracted public key (legacy method)"
    else
        log_error "Failed to extract public key"
        exit 1
    fi

    chmod 600 "$private_key"
    chmod 644 "$public_key"
    chown openwatch:openwatch "$private_key" "$public_key"
}

log_info "Generating OpenWatch secrets..."

if [ -f "$SECRETS_FILE" ] && ! grep -q "CHANGEME" "$SECRETS_FILE"; then
    cp "$SECRETS_FILE" "$SECRETS_FILE.backup.$(date +%Y%m%d_%H%M%S)"
    log_info "Backed up existing secrets file"
fi

DB_PASSWORD=$(generate_password)
REDIS_PASSWORD=$(generate_password)
SECRET_KEY=$(openssl rand -base64 48 | tr -d "=+/" | cut -c1-64)
MASTER_KEY=$(generate_password)
ENCRYPTION_KEY=$(generate_password)

log_info "Updating secrets file..."
sed -i "s/CHANGEME_SECURE_DB_PASSWORD/$DB_PASSWORD/" "$SECRETS_FILE"
sed -i "s/CHANGEME_SECURE_REDIS_PASSWORD/$REDIS_PASSWORD/" "$SECRETS_FILE"
sed -i "s/CHANGEME_64_CHAR_SECRET_KEY/$SECRET_KEY/" "$SECRETS_FILE"
sed -i "s/CHANGEME_32_CHAR_MASTER_KEY/$MASTER_KEY/" "$SECRETS_FILE"
sed -i "s/CHANGEME_32_CHAR_ENCRYPTION_KEY/$ENCRYPTION_KEY/" "$SECRETS_FILE"

generate_jwt_keys

chmod 600 "$SECRETS_FILE"
chown openwatch:openwatch "$SECRETS_FILE"

log_info "Secrets generated successfully!"
echo ""
echo "Next steps:"
echo "  1. Initialize PostgreSQL: /usr/share/openwatch/scripts/setup-database.sh"
echo "  2. Configure Redis password in /etc/redis/redis.conf"
echo "  3. Configure TLS certificates in /etc/openwatch/ssl/"
echo "  4. Enable nginx site: ln -s /etc/nginx/sites-available/openwatch /etc/nginx/sites-enabled/"
echo "  5. Start services: systemctl start openwatch.target"
EOFSCRIPT

    # Database setup script
    cat > "$PACKAGE_DIR/usr/share/openwatch/scripts/setup-database.sh" << 'EOFSCRIPT'
#!/bin/bash
# OpenWatch Database Setup Script

set -euo pipefail

source /etc/openwatch/secrets.env

log_info() { echo -e "\033[0;32m[INFO]\033[0m $1"; }
log_error() { echo -e "\033[0;31m[ERROR]\033[0m $1"; }

if [[ $EUID -ne 0 ]] && [[ "$(whoami)" != "postgres" ]]; then
    log_error "This script must be run as root or postgres user"
    exit 1
fi

log_info "Setting up OpenWatch database..."

sudo -u postgres psql << EOSQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'openwatch') THEN
        CREATE USER openwatch WITH PASSWORD '${OPENWATCH_DATABASE_PASSWORD}';
    END IF;
END
\$\$;

SELECT 'CREATE DATABASE openwatch OWNER openwatch'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'openwatch')\gexec

GRANT ALL PRIVILEGES ON DATABASE openwatch TO openwatch;
EOSQL

log_info "Database created successfully"

log_info "Running database migrations..."
cd /opt/openwatch/backend
sudo -u openwatch /opt/openwatch/venv/bin/alembic upgrade head

log_info "Database setup complete!"
EOFSCRIPT

    chmod +x "$PACKAGE_DIR/usr/share/openwatch/scripts/generate-secrets.sh"
    chmod +x "$PACKAGE_DIR/usr/share/openwatch/scripts/setup-database.sh"
}

# Create changelog
create_changelog() {
    log_info "Creating changelog..."

    cat > "$PACKAGE_DIR/usr/share/doc/openwatch/changelog" << EOF
openwatch ($DEB_VERSION) stable; urgency=medium

  * Native systemd deployment (no containers required)
  * Kensa compliance engine with bundled rules and mappings
  * Support for Ubuntu 24.04 LTS and newer
  * Air-gapped deployment: all dependencies bundled
  * PostgreSQL 15+, Redis 6+, nginx reverse proxy
  * Pre-built React frontend
  * AppArmor security profile support
  * Systemd service management

 -- OpenWatch Team <admin@hanalyx.com>  $(date -R)
EOF

    gzip -9 "$PACKAGE_DIR/usr/share/doc/openwatch/changelog"
}

# Create copyright file
create_copyright() {
    cat > "$PACKAGE_DIR/usr/share/doc/openwatch/copyright" << 'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: openwatch
Upstream-Contact: OpenWatch Team <admin@hanalyx.com>
Source: https://github.com/hanalyx/openwatch

Files: *
Copyright: 2025 Hanalyx
License: Apache-2.0

Files: debian/*
Copyright: 2025 Hanalyx
License: Apache-2.0

License: Apache-2.0
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 .
     http://www.apache.org/licenses/LICENSE-2.0
 .
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 .
 On Debian systems, the complete text of the Apache version 2.0 license
 can be found in "/usr/share/common-licenses/Apache-2.0".
EOF
}

# Build the package
build_package() {
    log_info "Building DEB package..."

    # Set proper permissions
    find "$PACKAGE_DIR" -type d -exec chmod 755 {} \;
    find "$PACKAGE_DIR" -type f -exec chmod 644 {} \;
    chmod 755 "$PACKAGE_DIR/usr/bin/owadm"
    chmod 755 "$PACKAGE_DIR/DEBIAN/postinst"
    chmod 755 "$PACKAGE_DIR/DEBIAN/prerm"
    chmod 755 "$PACKAGE_DIR/DEBIAN/postrm"
    chmod 755 "$PACKAGE_DIR/usr/share/openwatch/scripts/generate-secrets.sh"
    chmod 755 "$PACKAGE_DIR/usr/share/openwatch/scripts/setup-database.sh"

    # Build the package
    cd "$BUILD_DIR"
    fakeroot dpkg-deb --build "${PACKAGE_NAME}_${DEB_VERSION}_${ARCH}"

    if [ $? -eq 0 ]; then
        log_success "DEB package built successfully!"

        # Create dist directory
        mkdir -p "$SCRIPT_DIR/dist"
        mv "${PACKAGE_NAME}_${DEB_VERSION}_${ARCH}.deb" "$SCRIPT_DIR/dist/"

        # Show package info
        echo ""
        log_info "Package details:"
        dpkg-deb --info "$SCRIPT_DIR/dist/${PACKAGE_NAME}_${DEB_VERSION}_${ARCH}.deb"

        echo ""
        log_success "Package saved to: $SCRIPT_DIR/dist/${PACKAGE_NAME}_${DEB_VERSION}_${ARCH}.deb"

    else
        log_error "DEB package build failed!"
        exit 1
    fi
}

# Verify package
verify_package() {
    log_info "Verifying package..."

    local deb_file="$SCRIPT_DIR/dist/${PACKAGE_NAME}_${DEB_VERSION}_${ARCH}.deb"

    # Check with lintian if available
    if command -v lintian >/dev/null 2>&1; then
        log_info "Running lintian checks..."
        lintian --info "$deb_file" || log_warning "Lintian found some issues (this is common for custom packages)"
    fi

    # Show Kensa rule count inside the package
    local rule_count
    rule_count=$(dpkg-deb --contents "$deb_file" | grep -c '/backend/kensa/rules/.*\.yml$' || true)
    log_info "Package contains $rule_count Kensa rules"
}

# Main execution
main() {
    echo "OpenWatch DEB Build Script (Native)"
    echo "================================"

    check_prerequisites
    clean_build
    build_binary
    build_frontend
    install_kensa_data
    create_package_structure
    build_package
    verify_package

    echo ""
    log_success "OpenWatch DEB package build completed!"
    echo ""
    echo "Install with:"
    echo "   sudo apt install $SCRIPT_DIR/dist/${PACKAGE_NAME}_${DEB_VERSION}_${ARCH}.deb"
    echo ""
    echo "After installation:"
    echo "   1. Review: /etc/openwatch/ow.yml"
    echo "   2. Start: sudo systemctl start openwatch.target"
    echo "   3. Status: owadm status"
    echo ""
}

# Allow script to be sourced for testing
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
