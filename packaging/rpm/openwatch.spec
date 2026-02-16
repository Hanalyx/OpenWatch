# OpenWatch Native RPM Package Specification
# Enterprise SCAP compliance scanning platform - Native systemd deployment
#
# This package installs OpenWatch to run directly on the host via systemd,
# without requiring Docker or Podman containers.
#
# Package naming convention:
#   openwatch-*.rpm        - Native (this package)
#   openwatch-po-*.rpm     - Podman container deployment
#   openwatch-do-*.rpm     - Docker container deployment
#   openwatch-ko-*.rpm     - Kubernetes deployment

%global commit %(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
%global python_version 3.12

Name:           openwatch
Version:        2.0.0
Release:        1%{?dist}
Summary:        Enterprise SCAP compliance scanning platform - Native deployment
License:        Apache-2.0
URL:            https://github.com/hanalyx/openwatch
Source0:        %{name}-%{version}.tar.gz

# Architecture requirements
BuildArch:      x86_64
ExclusiveArch:  x86_64 aarch64

# Build requirements
BuildRequires:  golang >= 1.21
BuildRequires:  git
BuildRequires:  make
BuildRequires:  python%{python_version}-devel
BuildRequires:  npm >= 18

# Runtime requirements - Native deployment (NO container runtime)
Requires:       python%{python_version}
Requires:       python%{python_version}-pip
Requires:       postgresql >= 15
Requires:       postgresql-server >= 15
Requires:       redis >= 6
Requires:       nginx >= 1.20
Requires:       openssl >= 1.1

# System requirements
Requires:       openssh-clients
Requires:       systemd
Requires:       shadow-utils
Requires:       policycoreutils
Requires:       policycoreutils-python-utils

# Optional security enhancements
Recommends:     selinux-policy-devel
Recommends:     fapolicyd
Recommends:     aide

# Conflicts with container-based packages
Conflicts:      openwatch-po
Conflicts:      openwatch-do
Conflicts:      openwatch-ko

%description
OpenWatch is an enterprise-grade compliance scanning platform powered by
Aegis v0.1.0. This package provides native systemd deployment without
requiring Docker or Podman containers.

Key features:
- Aegis-powered compliance scanning (338 YAML rules)
- Multi-host fleet management via SSH
- CIS, STIG, NIST 800-53, PCI-DSS framework support
- Real-time compliance dashboards
- Role-based access control
- Audit logging and reporting
- Native systemd service management

Deployment:
- Backend API: uvicorn (FastAPI)
- Workers: Celery with Redis broker
- Database: PostgreSQL 15+
- Frontend: nginx serving React SPA
- Services managed via systemctl

Supports RHEL 8+, Rocky Linux 8+, Oracle Linux 8+, AlmaLinux 8+,
CentOS Stream 8+, and Fedora 38+.

%prep
%autosetup -n %{name}-%{version}

%build
# =============================================================================
# Build owadm CLI tool (native build - excludes container commands)
# =============================================================================
export CGO_ENABLED=0
export GOOS=linux

if [ "%{_arch}" = "x86_64" ]; then
    export GOARCH=amd64
else
    export GOARCH=%{_arch}
fi

export BUILD_TIME=$(date -u '+%%Y-%%m-%%d_%%H:%%M:%%S')
export LDFLAGS="-s -w -X github.com/hanalyx/openwatch/internal/owadm/cmd.Version=%{version} -X github.com/hanalyx/openwatch/internal/owadm/cmd.Commit=%{commit} -X github.com/hanalyx/openwatch/internal/owadm/cmd.BuildTime=$BUILD_TIME"

# Build with native tag (excludes container-specific commands)
go build -tags native -ldflags "$LDFLAGS" -o bin/owadm ./cmd/owadm

# =============================================================================
# Build frontend (React application)
# =============================================================================
cd frontend
npm ci --production=false
npm run build
cd ..

# =============================================================================
# Build SELinux policy if tools are available
# =============================================================================
if command -v make >/dev/null 2>&1 && [ -f /usr/share/selinux/devel/Makefile ]; then
    cd packaging/selinux
    make -f /usr/share/selinux/devel/Makefile openwatch.pp || true
    cd ../..
fi

%install
# =============================================================================
# Create directory structure
# =============================================================================

# Binary directory
install -d %{buildroot}%{_bindir}

# Application directory
install -d %{buildroot}/opt/openwatch
install -d %{buildroot}/opt/openwatch/venv
install -d %{buildroot}/opt/openwatch/backend
install -d %{buildroot}/opt/openwatch/backend/app
install -d %{buildroot}/opt/openwatch/backend/aegis
install -d %{buildroot}/opt/openwatch/backend/alembic
install -d %{buildroot}/opt/openwatch/frontend

# Configuration directory
install -d %{buildroot}%{_sysconfdir}/openwatch
install -d %{buildroot}%{_sysconfdir}/openwatch/ssh
install -d %{buildroot}%{_sysconfdir}/openwatch/ssl

# Nginx configuration
install -d %{buildroot}%{_sysconfdir}/nginx/conf.d

# Systemd services
install -d %{buildroot}/lib/systemd/system

# Runtime directories
install -d %{buildroot}%{_localstatedir}/lib/openwatch
install -d %{buildroot}%{_localstatedir}/lib/openwatch/celery
install -d %{buildroot}%{_localstatedir}/lib/openwatch/exports
install -d %{buildroot}%{_localstatedir}/lib/openwatch/ssh
install -d %{buildroot}%{_localstatedir}/log/openwatch

# SELinux policy directory
install -d %{buildroot}%{_datadir}/selinux/packages

# Scripts directory
install -d %{buildroot}%{_datadir}/openwatch/scripts

# =============================================================================
# Install owadm binary (native build)
# =============================================================================
install -m 0755 bin/owadm %{buildroot}%{_bindir}/owadm

# =============================================================================
# Install backend application
# =============================================================================
cp -r backend/app %{buildroot}/opt/openwatch/backend/
cp -r backend/aegis %{buildroot}/opt/openwatch/backend/
cp -r backend/alembic %{buildroot}/opt/openwatch/backend/
cp backend/requirements.txt %{buildroot}/opt/openwatch/backend/
cp backend/alembic.ini %{buildroot}/opt/openwatch/backend/

# Create runner symlink for Aegis imports
ln -s aegis/runner %{buildroot}/opt/openwatch/backend/runner

# =============================================================================
# Install frontend (pre-built React application)
# =============================================================================
cp -r frontend/dist/* %{buildroot}/opt/openwatch/frontend/

# =============================================================================
# Install configuration files
# =============================================================================

# Main configuration file
cat > %{buildroot}%{_sysconfdir}/openwatch/ow.yml << 'EOF'
# OpenWatch Native Installation Configuration
# Version: 2.0.0

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

# Scanning configuration (Aegis-based)
scanning:
  ssh_key_path: /etc/openwatch/ssh/openwatch_rsa
  concurrent_scans: 5
  timeout_seconds: 600

# Aegis compliance engine
aegis:
  rules_path: /opt/openwatch/backend/aegis/rules
  config_path: /opt/openwatch/backend/aegis/config

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
cat > %{buildroot}%{_sysconfdir}/openwatch/secrets.env << 'EOF'
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
cat > %{buildroot}%{_sysconfdir}/openwatch/logging.yml << 'EOF'
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

# =============================================================================
# Install systemd service files
# =============================================================================

# OpenWatch API service
cat > %{buildroot}/lib/systemd/system/openwatch-api.service << 'EOF'
[Unit]
Description=OpenWatch API Server
Documentation=https://github.com/hanalyx/openwatch
After=network-online.target postgresql.service redis.service
Requires=postgresql.service redis.service
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
cat > %{buildroot}/lib/systemd/system/openwatch-worker@.service << 'EOF'
[Unit]
Description=OpenWatch Celery Worker %i
Documentation=https://github.com/hanalyx/openwatch
After=network-online.target postgresql.service redis.service openwatch-api.service
Requires=postgresql.service redis.service
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
cat > %{buildroot}/lib/systemd/system/openwatch-beat.service << 'EOF'
[Unit]
Description=OpenWatch Celery Beat Scheduler
Documentation=https://github.com/hanalyx/openwatch
After=network-online.target postgresql.service redis.service
Requires=postgresql.service redis.service

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
cat > %{buildroot}/lib/systemd/system/openwatch.target << 'EOF'
[Unit]
Description=OpenWatch Compliance Platform
Documentation=https://github.com/hanalyx/openwatch
Requires=openwatch-api.service openwatch-worker@1.service openwatch-beat.service
After=openwatch-api.service openwatch-worker@1.service openwatch-beat.service

[Install]
WantedBy=multi-user.target
EOF

# =============================================================================
# Install nginx configuration
# =============================================================================
cat > %{buildroot}%{_sysconfdir}/nginx/conf.d/openwatch.conf << 'EOF'
# OpenWatch Nginx Configuration
# Reverse proxy for API + static file serving for frontend

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

# =============================================================================
# Install helper scripts
# =============================================================================

# Secret generation script
cat > %{buildroot}%{_datadir}/openwatch/scripts/generate-secrets.sh << 'EOFSCRIPT'
#!/bin/bash
# OpenWatch Secret Generation Script for Native Installation

set -euo pipefail

SECRETS_FILE="/etc/openwatch/secrets.env"
CONFIG_DIR="/etc/openwatch"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# Generate secure random password
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-32
}

# Generate JWT key pair
generate_jwt_keys() {
    local private_key="$CONFIG_DIR/jwt_private.pem"
    local public_key="$CONFIG_DIR/jwt_public.pem"

    log_info "Generating JWT key pair..."

    # Generate private key
    if openssl genpkey -algorithm RSA -out "$private_key" -pkeyopt rsa_keygen_bits:2048 2>/dev/null; then
        log_info "Generated private key"
    elif openssl genrsa -out "$private_key" 2048 2>/dev/null; then
        log_info "Generated private key (legacy method)"
    else
        log_error "Failed to generate RSA private key"
        exit 1
    fi

    # Extract public key
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

# Main
log_info "Generating OpenWatch secrets..."

# Backup existing secrets
if [ -f "$SECRETS_FILE" ] && ! grep -q "CHANGEME" "$SECRETS_FILE"; then
    cp "$SECRETS_FILE" "$SECRETS_FILE.backup.$(date +%Y%m%d_%H%M%S)"
    log_info "Backed up existing secrets file"
fi

# Generate passwords
DB_PASSWORD=$(generate_password)
REDIS_PASSWORD=$(generate_password)
SECRET_KEY=$(openssl rand -base64 48 | tr -d "=+/" | cut -c1-64)
MASTER_KEY=$(generate_password)
ENCRYPTION_KEY=$(generate_password)

# Update secrets file
log_info "Updating secrets file..."
sed -i "s/CHANGEME_SECURE_DB_PASSWORD/$DB_PASSWORD/" "$SECRETS_FILE"
sed -i "s/CHANGEME_SECURE_REDIS_PASSWORD/$REDIS_PASSWORD/" "$SECRETS_FILE"
sed -i "s/CHANGEME_64_CHAR_SECRET_KEY/$SECRET_KEY/" "$SECRETS_FILE"
sed -i "s/CHANGEME_32_CHAR_MASTER_KEY/$MASTER_KEY/" "$SECRETS_FILE"
sed -i "s/CHANGEME_32_CHAR_ENCRYPTION_KEY/$ENCRYPTION_KEY/" "$SECRETS_FILE"

# Generate JWT keys
generate_jwt_keys

# Secure the secrets file
chmod 600 "$SECRETS_FILE"
chown openwatch:openwatch "$SECRETS_FILE"

log_info "Secrets generated successfully!"
echo ""
echo "Next steps:"
echo "  1. Initialize PostgreSQL: /usr/share/openwatch/scripts/setup-database.sh"
echo "  2. Configure Redis password in /etc/redis/redis.conf"
echo "  3. Configure TLS certificates in /etc/openwatch/ssl/"
echo "  4. Start services: systemctl start openwatch.target"
EOFSCRIPT

# Database setup script
cat > %{buildroot}%{_datadir}/openwatch/scripts/setup-database.sh << 'EOFSCRIPT'
#!/bin/bash
# OpenWatch Database Setup Script

set -euo pipefail

source /etc/openwatch/secrets.env

log_info() { echo -e "\033[0;32m[INFO]\033[0m $1"; }
log_error() { echo -e "\033[0;31m[ERROR]\033[0m $1"; }

# Check if running as root or postgres user
if [[ $EUID -ne 0 ]] && [[ "$(whoami)" != "postgres" ]]; then
    log_error "This script must be run as root or postgres user"
    exit 1
fi

log_info "Setting up OpenWatch database..."

# Create database user and database
sudo -u postgres psql << EOSQL
-- Create user if not exists
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'openwatch') THEN
        CREATE USER openwatch WITH PASSWORD '${OPENWATCH_DATABASE_PASSWORD}';
    END IF;
END
\$\$;

-- Create database if not exists
SELECT 'CREATE DATABASE openwatch OWNER openwatch'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'openwatch')\gexec

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE openwatch TO openwatch;
EOSQL

log_info "Database created successfully"

# Run migrations
log_info "Running database migrations..."
cd /opt/openwatch/backend
sudo -u openwatch /opt/openwatch/venv/bin/alembic upgrade head

log_info "Database setup complete!"
EOFSCRIPT

chmod +x %{buildroot}%{_datadir}/openwatch/scripts/generate-secrets.sh
chmod +x %{buildroot}%{_datadir}/openwatch/scripts/setup-database.sh

# =============================================================================
# Install SELinux policy (if available)
# =============================================================================
if [ -f packaging/selinux/openwatch.pp ]; then
    install -m 0644 packaging/selinux/openwatch.pp %{buildroot}%{_datadir}/selinux/packages/openwatch.pp
else
    touch %{buildroot}%{_datadir}/selinux/packages/openwatch.pp
fi

# =============================================================================
# Pre-installation script
# =============================================================================
%pre
# Create openwatch user and group
getent group openwatch >/dev/null || groupadd -r openwatch
getent passwd openwatch >/dev/null || \
    useradd -r -g openwatch -d /opt/openwatch -s /sbin/nologin \
    -c "OpenWatch service account" openwatch

# =============================================================================
# Post-installation script
# =============================================================================
%post
# Create log directory
mkdir -p /var/log/openwatch
touch /var/log/openwatch/install.log
chmod 640 /var/log/openwatch/install.log

exec 1>>/var/log/openwatch/install.log 2>&1

echo "=== OpenWatch Native Post-Installation ==="
echo "=== $(date) ==="

# Set ownership and permissions
echo "Setting ownership and permissions..."
chown -R openwatch:openwatch /opt/openwatch
chown -R openwatch:openwatch /etc/openwatch
chown -R openwatch:openwatch /var/lib/openwatch
chown -R openwatch:openwatch /var/log/openwatch

chmod 750 /etc/openwatch
chmod 700 /etc/openwatch/ssh
chmod 700 /etc/openwatch/ssl
chmod 600 /etc/openwatch/secrets.env

# Make application read-only for service user
chmod -R 755 /opt/openwatch
chmod 644 /opt/openwatch/backend/requirements.txt

# Create Python virtual environment
echo "Creating Python virtual environment..."
if [ ! -d /opt/openwatch/venv/bin ]; then
    python%{python_version} -m venv /opt/openwatch/venv
    /opt/openwatch/venv/bin/pip install --upgrade pip wheel
    /opt/openwatch/venv/bin/pip install -r /opt/openwatch/backend/requirements.txt
    chown -R openwatch:openwatch /opt/openwatch/venv
fi

# Generate secrets if they contain defaults
if grep -q "CHANGEME" /etc/openwatch/secrets.env 2>/dev/null; then
    echo "Generating initial secrets..."
    /usr/share/openwatch/scripts/generate-secrets.sh || true
fi

# Configure SELinux if enabled
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" != "Disabled" ]; then
    echo "Configuring SELinux..."
    if [ -f /usr/share/selinux/packages/openwatch.pp ] && [ -s /usr/share/selinux/packages/openwatch.pp ]; then
        semodule -i /usr/share/selinux/packages/openwatch.pp 2>/dev/null || true
    fi
    restorecon -R /opt/openwatch 2>/dev/null || true
    restorecon -R /etc/openwatch 2>/dev/null || true
    restorecon -R /var/lib/openwatch 2>/dev/null || true
    restorecon -R /var/log/openwatch 2>/dev/null || true
fi

# Reload systemd
systemctl daemon-reload

# Enable services (but don't start)
systemctl enable openwatch-api.service
systemctl enable openwatch-worker@1.service
systemctl enable openwatch-beat.service
systemctl enable openwatch.target

echo ""
echo "=== Installation Summary ==="
echo "OpenWatch Native installed successfully!"
echo ""
echo "Next steps:"
echo "  1. Initialize PostgreSQL: postgresql-setup --initdb && systemctl enable --now postgresql"
echo "  2. Setup database: /usr/share/openwatch/scripts/setup-database.sh"
echo "  3. Start Redis: systemctl enable --now redis"
echo "  4. Configure TLS certificates in /etc/openwatch/ssl/"
echo "  5. Configure nginx: systemctl enable nginx"
echo "  6. Start OpenWatch: systemctl start openwatch.target"
echo ""
echo "Service management:"
echo "  systemctl start openwatch.target     # Start all services"
echo "  systemctl stop openwatch.target      # Stop all services"
echo "  systemctl status openwatch-api       # Check API status"
echo "  journalctl -u openwatch-api -f       # View API logs"
echo ""
echo "Admin commands:"
echo "  owadm validate-config                # Validate configuration"
echo "  owadm health                         # Health check"
echo "  owadm backup                         # Create backup"
echo ""

# Output to terminal
exec 3>&2
echo >&3
echo "OpenWatch Native installation completed successfully." >&3
echo "Installation log: /var/log/openwatch/install.log" >&3
echo >&3

# =============================================================================
# Pre-uninstallation script
# =============================================================================
%preun
if [ $1 -eq 0 ]; then
    # Stop and disable services
    systemctl stop openwatch.target 2>/dev/null || true
    systemctl stop openwatch-api.service 2>/dev/null || true
    systemctl stop openwatch-worker@1.service 2>/dev/null || true
    systemctl stop openwatch-beat.service 2>/dev/null || true
    systemctl disable openwatch.target 2>/dev/null || true
    systemctl disable openwatch-api.service 2>/dev/null || true
    systemctl disable openwatch-worker@1.service 2>/dev/null || true
    systemctl disable openwatch-beat.service 2>/dev/null || true
fi

# =============================================================================
# Post-uninstallation script
# =============================================================================
%postun
systemctl daemon-reload || true

if [ $1 -eq 0 ]; then
    echo ""
    echo "OpenWatch has been removed."
    echo ""
    echo "The following data has been preserved:"
    echo "  - Configuration: /etc/openwatch/"
    echo "  - Database: PostgreSQL 'openwatch' database"
    echo "  - Logs: /var/log/openwatch/"
    echo ""
    echo "To completely remove all data:"
    echo "  rm -rf /etc/openwatch /var/lib/openwatch /var/log/openwatch"
    echo "  sudo -u postgres dropdb openwatch"
    echo "  sudo -u postgres dropuser openwatch"
    echo "  userdel openwatch"
    echo ""

    # Remove SELinux policy
    if command -v semodule >/dev/null 2>&1; then
        semodule -r openwatch 2>/dev/null || true
    fi
fi

# =============================================================================
# File list
# =============================================================================
%files
# Binary
%{_bindir}/owadm

# Application
%dir %attr(755,openwatch,openwatch) /opt/openwatch
%dir %attr(755,openwatch,openwatch) /opt/openwatch/venv
%attr(755,openwatch,openwatch) /opt/openwatch/backend
%attr(755,openwatch,openwatch) /opt/openwatch/frontend

# Configuration
%dir %attr(750,openwatch,openwatch) %{_sysconfdir}/openwatch
%dir %attr(700,openwatch,openwatch) %{_sysconfdir}/openwatch/ssh
%dir %attr(700,openwatch,openwatch) %{_sysconfdir}/openwatch/ssl
%config(noreplace) %attr(640,openwatch,openwatch) %{_sysconfdir}/openwatch/ow.yml
%config(noreplace) %attr(600,openwatch,openwatch) %{_sysconfdir}/openwatch/secrets.env
%config(noreplace) %attr(644,openwatch,openwatch) %{_sysconfdir}/openwatch/logging.yml

# Nginx configuration
%config(noreplace) %attr(644,root,root) %{_sysconfdir}/nginx/conf.d/openwatch.conf

# Systemd services
/lib/systemd/system/openwatch-api.service
/lib/systemd/system/openwatch-worker@.service
/lib/systemd/system/openwatch-beat.service
/lib/systemd/system/openwatch.target

# Runtime directories
%dir %attr(750,openwatch,openwatch) %{_localstatedir}/lib/openwatch
%dir %attr(750,openwatch,openwatch) %{_localstatedir}/lib/openwatch/celery
%dir %attr(750,openwatch,openwatch) %{_localstatedir}/lib/openwatch/exports
%dir %attr(750,openwatch,openwatch) %{_localstatedir}/lib/openwatch/ssh
%dir %attr(750,openwatch,openwatch) %{_localstatedir}/log/openwatch

# Scripts
%dir %attr(755,root,root) %{_datadir}/openwatch
%dir %attr(755,root,root) %{_datadir}/openwatch/scripts
%attr(755,root,root) %{_datadir}/openwatch/scripts/generate-secrets.sh
%attr(755,root,root) %{_datadir}/openwatch/scripts/setup-database.sh

# SELinux policy
%{_datadir}/selinux/packages/openwatch.pp

# =============================================================================
# Changelog
# =============================================================================
%changelog
* Wed Feb 12 2026 OpenWatch Team <admin@hanalyx.com> - 2.0.0-1
- Initial native RPM package (non-containerized deployment)
- Aegis v0.1.0 compliance engine with 338 YAML rules
- Native systemd service management
- Support for RHEL 8/9/10, Rocky Linux, Oracle Linux, AlmaLinux
- owadm CLI built with native tag (admin commands only)
- PostgreSQL 15+, Redis 6+, nginx reverse proxy
- Pre-built React frontend
- SELinux policy support
- FIPS 140-2/140-3 ready
