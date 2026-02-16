# OpenWatch RPM Package Specification - Podman Container Deployment
# Enterprise SCAP compliance scanning platform (Container-based)

%global commit %(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

Name:           openwatch-po
Version:        2.0.0
Release:        1%{?dist}
Summary:        Enterprise SCAP compliance platform - Podman container deployment
License:        Apache-2.0
URL:            https://github.com/hanalyx/openwatch
Source0:        openwatch-%{version}.tar.gz

# Architecture requirements
BuildArch:      x86_64
ExclusiveArch:  x86_64 aarch64

# Build requirements
BuildRequires:  golang >= 1.21
BuildRequires:  git
BuildRequires:  make

# Runtime requirements - Podman container orchestration
Requires:       podman >= 4.0
Requires:       podman-compose >= 1.0

# System requirements
Requires:       openscap-scanner >= 1.3.0
Requires:       openssh-clients
Requires:       systemd
Requires:       shadow-utils
Requires:       policycoreutils
Requires:       policycoreutils-python-utils
Requires:       selinux-policy-devel

# Package conflicts - cannot install alongside native or Docker deployment
Conflicts:      openwatch
Conflicts:      openwatch-do
Conflicts:      openwatch-ko

# Optional security enhancements
Recommends:     fapolicyd
Recommends:     aide

%description
OpenWatch Podman Container Deployment (openwatch-po)

This package provides OpenWatch deployed via Podman containers. The application
runs inside rootless or system containers orchestrated by podman-compose.

OpenWatch is an enterprise-grade SCAP (Security Content Automation Protocol)
compliance scanning and remediation platform. It provides automated security
compliance monitoring, vulnerability assessment, and remediation capabilities
for enterprise Linux environments.

DEPLOYMENT OPTIONS:
- openwatch (native):   Runs directly on host via systemd (no containers)
- openwatch-po:         Podman container deployment (this package)
- openwatch-do:         Docker container deployment (planned)
- openwatch-ko:         Kubernetes deployment (planned)

Key features:
- SCAP-compliant security scanning
- Multi-host fleet management
- Automated remediation workflows
- Real-time compliance dashboards
- Role-based access control
- Audit logging and reporting
- Container-based deployment with Podman

Supports RHEL 8/9/10, Rocky Linux, AlmaLinux, Oracle Linux, CentOS Stream, and Fedora.

%prep
# Source tarball uses 'openwatch' name regardless of package variant
%autosetup -n openwatch-%{version}

%build
# Build owadm CLI tool with CONTAINER build tag
# This enables container orchestration commands (start, stop, logs, exec, etc.)
export CGO_ENABLED=0
export GOOS=linux

# Set build-time variables and correct architecture
if [ "%{_arch}" = "x86_64" ]; then
    export GOARCH=amd64
else
    export GOARCH=%{_arch}
fi

export BUILD_TIME=$(date -u '+%%Y-%%m-%%d_%%H:%%M:%%S')
export LDFLAGS="-s -w -X github.com/hanalyx/openwatch/internal/owadm/cmd.Version=%{version} -X github.com/hanalyx/openwatch/internal/owadm/cmd.Commit=%{commit} -X github.com/hanalyx/openwatch/internal/owadm/cmd.BuildTime=$BUILD_TIME"

# Build with 'container' tag for container deployment mode
go build -tags container -ldflags "$LDFLAGS" -o bin/owadm ./cmd/owadm

# Build SELinux policy if tools are available
if command -v make >/dev/null 2>&1 && [ -f /usr/share/selinux/devel/Makefile ]; then
    cd packaging/selinux
    make -f /usr/share/selinux/devel/Makefile openwatch.pp
    cd ../..
fi

%install
# Create directory structure
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_sysconfdir}/openwatch
install -d %{buildroot}%{_sysconfdir}/openwatch/ssh
install -d %{buildroot}%{_datadir}/openwatch
install -d %{buildroot}%{_datadir}/openwatch/compose
install -d %{buildroot}%{_datadir}/openwatch/scripts
install -d %{buildroot}/lib/systemd/system
install -d %{buildroot}%{_localstatedir}/lib/openwatch
install -d %{buildroot}%{_localstatedir}/log/openwatch
install -d %{buildroot}%{_localstatedir}/cache/openwatch

# Install owadm binary
install -m 0755 bin/owadm %{buildroot}%{_bindir}/owadm

# Install container orchestration files
install -m 0644 docker-compose.yml %{buildroot}%{_datadir}/openwatch/compose/docker-compose.yml
install -m 0644 podman-compose.yml %{buildroot}%{_datadir}/openwatch/compose/podman-compose.yml

# Install docker build files
install -d %{buildroot}%{_datadir}/openwatch/docker
install -d %{buildroot}%{_datadir}/openwatch/docker/database
install -d %{buildroot}%{_datadir}/openwatch/docker/frontend
install -m 0644 docker/Containerfile.backend %{buildroot}%{_datadir}/openwatch/docker/Containerfile.backend
install -m 0644 docker/Containerfile.frontend %{buildroot}%{_datadir}/openwatch/docker/Containerfile.frontend
install -m 0644 docker/Dockerfile.backend %{buildroot}%{_datadir}/openwatch/docker/Dockerfile.backend
install -m 0644 docker/Dockerfile.frontend %{buildroot}%{_datadir}/openwatch/docker/Dockerfile.frontend
install -m 0644 docker/README.md %{buildroot}%{_datadir}/openwatch/docker/README.md
install -m 0644 docker/database/init.sql %{buildroot}%{_datadir}/openwatch/docker/database/init.sql
install -m 0644 docker/frontend/default.conf %{buildroot}%{_datadir}/openwatch/docker/frontend/default.conf
install -m 0644 docker/frontend/nginx.conf %{buildroot}%{_datadir}/openwatch/docker/frontend/nginx.conf

# Install configuration templates
cat > %{buildroot}%{_sysconfdir}/openwatch/ow.yml << 'EOF'
# OpenWatch Configuration
# Generated by RPM package installation

runtime:
  engine: "podman"              # podman (default), docker, auto
  rootless: false               # Use system-level containers for systemd services
  compose_file: "/usr/share/openwatch/compose/podman-compose.yml"
  compose_command: "podman-compose"  # podman-compose or podman compose or docker-compose
  working_directory: "/usr/share/openwatch/compose"  # Directory containing compose files

database:
  host: "localhost"
  port: 5432
  name: "openwatch"
  user: "openwatch"
  ssl_mode: "require"
  # Password loaded from secrets.env

web:
  port: 3001
  bind_address: "0.0.0.0"
  ssl:
    enabled: false              # Set to true for production
    cert_path: "/etc/ssl/certs/openwatch.crt"
    key_path: "/etc/ssl/private/openwatch.key"

scanning:
  ssh_key_path: "/etc/openwatch/ssh/openwatch_rsa"
  concurrent_scans: 5
  timeout: 300
  scap_content_dir: "/var/lib/openwatch/scap"
  results_dir: "/var/lib/openwatch/results"

logging:
  level: "INFO"
  file: "/var/log/openwatch/openwatch.log"
  audit_file: "/var/log/openwatch/audit.log"
  max_size: "100MB"
  max_age: 30

security:
  fips_mode: false              # Enable for FIPS 140-2 compliance
  audit_logging: true
  rate_limiting: true
  session_timeout: 3600
EOF

# Install secrets template (will be configured by admin)
cat > %{buildroot}%{_sysconfdir}/openwatch/secrets.env << 'EOF'
# OpenWatch Secrets Configuration
# IMPORTANT: Secure this file with chmod 600 and set proper ownership

# Database password
POSTGRES_PASSWORD=CHANGEME_SECURE_DB_PASSWORD

# Redis password
REDIS_PASSWORD=CHANGEME_SECURE_REDIS_PASSWORD

# Application secrets
SECRET_KEY=CHANGEME_64_CHAR_SECRET_KEY
MASTER_KEY=CHANGEME_32_CHAR_MASTER_KEY

# JWT signing keys (auto-generated by post-install script)
JWT_PRIVATE_KEY_PATH=/etc/openwatch/jwt_private.pem
JWT_PUBLIC_KEY_PATH=/etc/openwatch/jwt_public.pem
EOF

# Install systemd service files
cat > %{buildroot}/lib/systemd/system/openwatch.service << 'EOF'
[Unit]
Description=OpenWatch SCAP Compliance Platform
Documentation=https://github.com/hanalyx/openwatch
Requires=openwatch-db.service
After=network-online.target openwatch-db.service
Wants=network-online.target

[Service]
Type=forking
User=root
Group=root
WorkingDirectory=/usr/share/openwatch/compose
EnvironmentFile=/etc/openwatch/secrets.env
EnvironmentFile=-/etc/openwatch/.env
Environment="COMPOSE_PROJECT_NAME=openwatch"
Environment="CONTAINER_RUNTIME=podman"
Environment="OPENWATCH_CONFIG_DIR=/etc/openwatch"  # pragma: allowlist secret
Environment="OPENWATCH_USER=openwatch"  # pragma: allowlist secret
Environment="OPENWATCH_GROUP=openwatch"
ExecStartPre=/usr/bin/owadm validate-config --config /etc/openwatch/ow.yml
ExecStart=/usr/bin/owadm start --daemon --config /etc/openwatch/ow.yml
ExecStop=/usr/bin/owadm stop --config /etc/openwatch/ow.yml
ExecReload=/usr/bin/owadm restart --config /etc/openwatch/ow.yml
Restart=on-failure
RestartSec=10
KillMode=mixed
TimeoutStartSec=300
TimeoutStopSec=120

# Security settings for system containers
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
LockPersonality=true
PrivateDevices=false
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

cat > %{buildroot}/lib/systemd/system/openwatch-db.service << 'EOF'
[Unit]
Description=OpenWatch Database Container
Documentation=https://github.com/hanalyx/openwatch
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=root
Group=root
WorkingDirectory=/usr/share/openwatch/compose
EnvironmentFile=/etc/openwatch/secrets.env
EnvironmentFile=-/etc/openwatch/.env
Environment="COMPOSE_PROJECT_NAME=openwatch"
Environment="CONTAINER_RUNTIME=podman"
Environment="OPENWATCH_CONFIG_DIR=/etc/openwatch"  # pragma: allowlist secret
Environment="OPENWATCH_USER=openwatch"  # pragma: allowlist secret
Environment="OPENWATCH_GROUP=openwatch"
ExecStartPre=/usr/bin/owadm validate-config --config /etc/openwatch/ow.yml
ExecStart=/usr/bin/owadm start --daemon --service database --config /etc/openwatch/ow.yml
ExecStop=/usr/bin/owadm stop --service database --config /etc/openwatch/ow.yml
Restart=on-failure
RestartSec=5
TimeoutStartSec=60
TimeoutStopSec=30

# Security settings for system containers
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
LockPersonality=true
PrivateDevices=false
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

# Install SELinux policy files (if available)
install -d %{buildroot}%{_datadir}/selinux/packages
if [ -f packaging/selinux/openwatch.pp ]; then
    install -m 0644 packaging/selinux/openwatch.pp %{buildroot}%{_datadir}/selinux/packages/openwatch.pp
else
    # Create empty policy file as placeholder
    touch %{buildroot}%{_datadir}/selinux/packages/openwatch.pp
fi

# Install fapolicyd configuration scripts
install -m 0755 packaging/rpm/scripts/configure-fapolicyd.sh %{buildroot}%{_datadir}/openwatch/scripts/configure-fapolicyd.sh
install -m 0755 packaging/rpm/scripts/fapolicyd-troubleshoot.sh %{buildroot}%{_datadir}/openwatch/scripts/fapolicyd-troubleshoot.sh

# Install comprehensive cleanup script
install -m 0755 packaging/rpm/scripts/cleanup-openwatch.sh %{buildroot}%{_datadir}/openwatch/scripts/cleanup-openwatch.sh

# Install Podman permission fix script
install -m 0755 packaging/rpm/scripts/fix-podman-permissions.sh %{buildroot}%{_datadir}/openwatch/scripts/fix-podman-permissions.sh

# Install Podman troubleshooting script
install -m 0755 packaging/rpm/scripts/podman-troubleshoot.sh %{buildroot}%{_datadir}/openwatch/scripts/podman-troubleshoot.sh

# Install fapolicyd rules template
install -d %{buildroot}%{_datadir}/openwatch/templates
install -m 0644 packaging/rpm/templates/90-openwatch.rules %{buildroot}%{_datadir}/openwatch/templates/90-openwatch.rules

# Create owadm required directories (matching prerequisites.go expectations)
install -d %{buildroot}%{_datadir}/openwatch/compose/logs
install -d %{buildroot}%{_datadir}/openwatch/compose/data/scap
install -d %{buildroot}%{_datadir}/openwatch/compose/data/results
install -d %{buildroot}%{_datadir}/openwatch/compose/data/uploads
install -d %{buildroot}%{_datadir}/openwatch/compose/security/certs
install -d %{buildroot}%{_datadir}/openwatch/compose/security/keys
install -d %{buildroot}%{_datadir}/openwatch/compose/backend/logs
install -d %{buildroot}%{_datadir}/openwatch/compose/backend/security/keys

# Install helper scripts
cat > %{buildroot}%{_datadir}/openwatch/scripts/generate-secrets.sh << 'EOF'
#!/bin/bash
# OpenWatch Secret Generation Script

set -euo pipefail

SECRETS_FILE="/etc/openwatch/secrets.env"
CONFIG_DIR="/etc/openwatch"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}INFO: $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
}

log_error() {
    echo -e "${RED}ERROR: $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if OpenSSL is installed
    if ! command -v openssl >/dev/null 2>&1; then
        log_error "OpenSSL is not installed!"
        echo ""
        echo "Please install OpenSSL first:"
        echo "  RHEL/Fedora/Oracle Linux: sudo dnf install openssl"
        echo "  Ubuntu/Debian:             sudo apt install openssl"
        echo "  SLES/openSUSE:             sudo zypper install openssl"
        echo ""
        exit 1
    fi

    # Check OpenSSL version
    local openssl_version
    openssl_version=$(openssl version | cut -d' ' -f2)
    log_info "OpenSSL version: $openssl_version"

    # Check if we have required tools
    local missing_tools=()
    for tool in sed chown chmod; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi

    log_info "Prerequisites check passed"
}

# Generate secure random passwords
generate_password() {
    # Try different methods based on what's available
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32 | tr -d "=+/" | cut -c1-32
    elif [ -f /dev/urandom ]; then
        tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32
    else
        log_error "Cannot generate secure random passwords - no entropy source available"
        exit 1
    fi
}

# Generate JWT key pair with compatibility
generate_jwt_keys() {
    local private_key="$CONFIG_DIR/jwt_private.pem"
    local public_key="$CONFIG_DIR/jwt_public.pem"

    log_info "Generating JWT key pair..."

    # Try modern OpenSSL syntax first, fall back to older syntax
    if openssl genpkey -algorithm RSA -out "$private_key" -pkeyopt rsa_keygen_bits:2048 2>/dev/null; then
        log_info "Generated private key using modern OpenSSL"
    elif openssl genrsa -out "$private_key" 2048 2>/dev/null; then
        log_info "Generated private key using legacy OpenSSL"
    else
        log_error "Failed to generate RSA private key"
        log_info "Trying alternative method..."

        # Alternative method for very old OpenSSL versions
        if ! openssl genrsa 2048 > "$private_key" 2>/dev/null; then
            log_error "All RSA key generation methods failed"
            exit 1
        fi
        log_info "Generated private key using alternative method"
    fi

    # Extract public key (try different methods)
    if openssl pkey -in "$private_key" -pubout -out "$public_key" 2>/dev/null; then
        log_info "Extracted public key using modern OpenSSL"
    elif openssl rsa -in "$private_key" -pubout -out "$public_key" 2>/dev/null; then
        log_info "Extracted public key using legacy OpenSSL"
    else
        log_error "Failed to extract public key from private key"
        exit 1
    fi

    # Set proper permissions
    chmod 600 "$private_key"
    chmod 644 "$public_key"

    # Only change ownership if openwatch user exists
    if id "openwatch" >/dev/null 2>&1; then
        chown openwatch:openwatch "$private_key" "$public_key"
    else
        log_warning "openwatch user not found - keeping root ownership"
    fi

    log_info "JWT keys generated successfully"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# Check if secrets file exists
if [ ! -f "$SECRETS_FILE" ]; then
    log_error "Secrets file not found: $SECRETS_FILE"
    log_info "Please ensure OpenWatch is properly installed"
    exit 1
fi

echo "OpenWatch Secret Generation Script"
echo "====================================="

check_prerequisites

log_info "Generating OpenWatch secrets..."

# Generate secrets with error handling
log_info "Generating database password..."
DB_PASSWORD=$(generate_password)

log_info "Generating Redis password..."
REDIS_PASSWORD=$(generate_password)

log_info "Generating application secret key..."
if command -v openssl >/dev/null 2>&1; then
    SECRET_KEY=$(openssl rand -base64 48 | tr -d "=+/" | cut -c1-64)
else
    SECRET_KEY=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 64)
fi

log_info "Generating master key..."
MASTER_KEY=$(generate_password)

# Backup original secrets file
cp "$SECRETS_FILE" "$SECRETS_FILE.backup.$(date +%%Y%%m%%d_%%H%%M%%S)"
log_info "Backed up original secrets file"

# Update secrets file
log_info "Updating secrets file..."
sed -i "s/CHANGEME_SECURE_DB_PASSWORD/$DB_PASSWORD/" "$SECRETS_FILE"
sed -i "s/CHANGEME_SECURE_REDIS_PASSWORD/$REDIS_PASSWORD/" "$SECRETS_FILE"
sed -i "s/CHANGEME_64_CHAR_SECRET_KEY/$SECRET_KEY/" "$SECRETS_FILE"
sed -i "s/CHANGEME_32_CHAR_MASTER_KEY/$MASTER_KEY/" "$SECRETS_FILE"

# Generate JWT keys
generate_jwt_keys

# Secure the secrets file
chmod 600 "$SECRETS_FILE"
if id "openwatch" >/dev/null 2>&1; then
    chown openwatch:openwatch "$SECRETS_FILE"
else
    log_warning "openwatch user not found - keeping root ownership"
fi

echo ""
echo "Secrets generated successfully!"
echo ""
echo "Files created/updated:"
echo "  - $SECRETS_FILE"
echo "  - $CONFIG_DIR/jwt_private.pem"
echo "  - $CONFIG_DIR/jwt_public.pem"
echo ""
echo "Next steps:"
echo "  1. Review and customize /etc/openwatch/ow.yml"
echo "  2. Generate SSH keys if needed: ssh-keygen -t rsa -f /etc/openwatch/ssh/openwatch_rsa"
echo "  3. Start OpenWatch: systemctl start openwatch"
echo ""
echo "Secrets stored securely with restricted permissions"
EOF

chmod +x %{buildroot}%{_datadir}/openwatch/scripts/generate-secrets.sh

%pre
# Create openwatch user and group
getent group openwatch >/dev/null || groupadd -r openwatch
getent passwd openwatch >/dev/null || \
    useradd -r -g openwatch -d /var/lib/openwatch -s /sbin/nologin \
    -c "OpenWatch service account" openwatch

# Note: Using system-level containers - openwatch user for file ownership only

%post
# Create log directory and log file with proper permissions
mkdir -p /var/log/openwatch
touch /var/log/openwatch/install.log
chmod 640 /var/log/openwatch/install.log

# Redirect all output to log file
exec 1>>/var/log/openwatch/install.log 2>&1

echo "=== OpenWatch Post-Installation Script ==="
echo "=== $(date) ==="

# Set proper ownership and permissions
echo "Setting ownership and permissions..."
chown -R openwatch:openwatch /etc/openwatch
chown -R openwatch:openwatch /var/lib/openwatch
chown -R openwatch:openwatch /var/log/openwatch

# Set restrictive permissions on config directory
chmod 750 /etc/openwatch
chmod 700 /etc/openwatch/ssh
chmod 600 /etc/openwatch/secrets.env

# Generate initial secrets if they don't exist
if grep -q "CHANGEME" /etc/openwatch/secrets.env; then
    echo "Generating initial secrets..."
    /usr/share/openwatch/scripts/generate-secrets.sh
fi

# Create .env file for container services from secrets.env
echo "Creating .env file for container services..."
create_env_file() {
    local env_file="/etc/openwatch/.env"
    local secrets_file="/etc/openwatch/secrets.env"

    # Source the secrets file to get the values
    if [ -f "$secrets_file" ]; then
        # Create .env file with required environment variables
        cat > "$env_file" << EOF
# Auto-generated from secrets.env - DO NOT EDIT DIRECTLY
# Generated on $(date)

# Database Configuration
$(grep "POSTGRES_PASSWORD=" "$secrets_file" || echo "POSTGRES_PASSWORD=changeme")

# Redis Configuration
$(grep "REDIS_PASSWORD=" "$secrets_file" || echo "REDIS_PASSWORD=changeme")

# Application Secrets
$(grep "SECRET_KEY=" "$secrets_file" || echo "SECRET_KEY=changeme")
$(grep "MASTER_KEY=" "$secrets_file" || echo "MASTER_KEY=changeme")

# JWT Keys
$(grep "JWT_PRIVATE_KEY_PATH=" "$secrets_file" || echo "JWT_PRIVATE_KEY_PATH=/etc/openwatch/jwt_private.pem")
$(grep "JWT_PUBLIC_KEY_PATH=" "$secrets_file" || echo "JWT_PUBLIC_KEY_PATH=/etc/openwatch/jwt_public.pem")

# Container Settings
COMPOSE_PROJECT_NAME=openwatch
CONTAINER_RUNTIME=podman
EOF

        # Set proper permissions
        chmod 600 "$env_file"
        chown openwatch:openwatch "$env_file"
        echo "Created .env file at $env_file"
    else
        echo "Warning: secrets.env not found, .env file not created"
    fi
}

create_env_file

# Create symbolic link for .env file in compose directory
echo "Configuring compose directory..."
if [ -f /etc/openwatch/.env ]; then
    ln -sf /etc/openwatch/.env /usr/share/openwatch/compose/.env
fi

# Create symbolic link for docker directory to be accessible from compose directory
ln -sf /usr/share/openwatch/docker /usr/share/openwatch/compose/docker

# Create all directories that owadm expects in its working directory
echo "Creating owadm required directories..."
create_owadm_directories() {
    local base_dir="/usr/share/openwatch/compose"

    # Create all directories that owadm expects (from prerequisites.go)
    local directories=(
        "logs"
        "data/scap"
        "data/results"
        "data/uploads"
        "security/certs"
        "security/keys"
        "backend/logs"
        "backend/security/keys"
    )

    for dir in "${directories[@]}"; do
        mkdir -p "$base_dir/$dir"
        echo "Created directory: $base_dir/$dir"
    done

    # Set proper ownership on all directories
    chown -R openwatch:openwatch "$base_dir/logs" "$base_dir/data" "$base_dir/backend" 2>/dev/null || true

    # Set restrictive permissions on security directories (matching owadm expectations)
    chmod 700 "$base_dir/security/keys" 2>/dev/null || true
    chmod 700 "$base_dir/backend/security/keys" 2>/dev/null || true
    chown -R openwatch:openwatch "$base_dir/security" 2>/dev/null || true

    echo "All owadm directories created and configured"
}

create_owadm_directories

# Set proper ownership for compose directory
chown -R openwatch:openwatch /usr/share/openwatch/compose
echo "Compose directory configured"

# Check and configure SELinux policy for RHEL/Oracle Linux
check_and_configure_selinux() {
    # Check if SELinux tools are available
    if ! command -v semanage >/dev/null 2>&1; then
        echo "INFO: SELinux management tools not found - skipping SELinux policy installation"
        return 0
    fi

    # Check if SELinux is installed and enabled
    if ! command -v getenforce >/dev/null 2>&1; then
        echo "INFO: SELinux not installed - skipping SELinux policy installation"
        return 0
    fi

    local selinux_status
    selinux_status=$(getenforce 2>/dev/null || echo "Disabled")

    if [ "$selinux_status" = "Disabled" ]; then
        echo "INFO: SELinux is disabled - skipping SELinux policy installation"
        return 0
    fi

    echo "Installing OpenWatch SELinux policy (SELinux status: $selinux_status)..."

    # Install policy module only if the file exists and is valid
    if [ -f /usr/share/selinux/packages/openwatch.pp ] && [ -s /usr/share/selinux/packages/openwatch.pp ]; then
        if semodule -i /usr/share/selinux/packages/openwatch.pp 2>/dev/null; then
            echo "SELinux policy module installed successfully"
        else
            echo "WARNING: SELinux policy installation failed - this is expected if policy wasn't built"
        fi
    else
        echo "WARNING: SELinux policy file not found or empty - skipping policy installation"
    fi

    # Apply file contexts regardless of policy installation
    echo "Applying SELinux file contexts..."
    if [ -d /etc/openwatch ]; then
        restorecon -R /etc/openwatch 2>/dev/null || true
    fi
    if [ -d /var/lib/openwatch ]; then
        restorecon -R /var/lib/openwatch 2>/dev/null || true
    fi
    if [ -d /var/log/openwatch ]; then
        restorecon -R /var/log/openwatch 2>/dev/null || true
    fi
    if [ -f /usr/bin/owadm ]; then
        restorecon /usr/bin/owadm 2>/dev/null || true
    fi

    echo "SELinux contexts configured"
}

# Check and configure fapolicyd for OpenWatch
check_and_configure_fapolicyd() {
    # Check if fapolicyd is installed
    if ! command -v fapolicyd >/dev/null 2>&1; then
        echo "INFO: fapolicyd not installed - skipping fapolicyd configuration"
        return 0
    fi

    # Check if fapolicyd service exists
    if ! systemctl list-unit-files fapolicyd.service >/dev/null 2>&1; then
        echo "INFO: fapolicyd service not available - skipping fapolicyd configuration"
        return 0
    fi

    # Check if fapolicyd is enabled and running
    local fapolicyd_enabled=false
    local fapolicyd_active=false

    if systemctl is-enabled fapolicyd >/dev/null 2>&1; then
        fapolicyd_enabled=true
    fi

    if systemctl is-active --quiet fapolicyd 2>/dev/null; then
        fapolicyd_active=true
    fi

    if [ "$fapolicyd_enabled" = "false" ] && [ "$fapolicyd_active" = "false" ]; then
        echo "INFO: fapolicyd is not enabled or running - skipping automatic configuration"
        echo "INFO: To configure fapolicyd later: /usr/share/openwatch/scripts/configure-fapolicyd.sh configure"
        return 0
    fi

    echo "Configuring fapolicyd for OpenWatch (enabled: $fapolicyd_enabled, active: $fapolicyd_active)..."

    # Check if configuration script exists
    if [ -f /usr/share/openwatch/scripts/configure-fapolicyd.sh ]; then
        if /usr/share/openwatch/scripts/configure-fapolicyd.sh configure 2>/dev/null; then
            echo "fapolicyd rules configured successfully"
        else
            echo "WARNING: fapolicyd configuration failed - manual configuration may be needed"
        fi
        echo "INFO: Troubleshooting: /usr/share/openwatch/scripts/fapolicyd-troubleshoot.sh"
    else
        echo "WARNING: fapolicyd configuration script not found"
    fi
}

# Run security configurations
check_and_configure_selinux
check_and_configure_fapolicyd

# Enable but don't start services (let admin control startup)
if command -v systemctl >/dev/null 2>&1; then
    echo "Enabling systemd services..."
    systemctl daemon-reload
    systemctl enable openwatch.service openwatch-db.service
fi

echo ""
echo "=== Installation Summary ==="
echo "OpenWatch installed successfully!"
echo ""
echo "Next steps:"
echo "1. Review configuration: /etc/openwatch/ow.yml"
echo "2. Configure SSL certificates (recommended)"
echo "3. Start services: systemctl start openwatch"
echo "4. Check status: owadm status"
echo ""

# Show runtime environment info
echo "Runtime Configuration:"
echo "  - Container runtime: Podman (System-level containers)"
echo "  - Compose command: podman-compose"
echo "  - Config file: /etc/openwatch/ow.yml"
echo "  - Environment file: /etc/openwatch/.env"
echo "  - Execution mode: System containers (root with security constraints)"
echo ""

# Show security configuration status
echo "Security Configuration Status:"
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null || echo Disabled)" != "Disabled" ]; then
    echo "  - SELinux: Enabled and configured"
else
    echo "  - SELinux: Not enabled"
fi

if command -v fapolicyd >/dev/null 2>&1 && systemctl is-enabled fapolicyd >/dev/null 2>&1; then
    echo "  - fapolicyd: Detected and configured"
    echo "    Troubleshooting: /usr/share/openwatch/scripts/fapolicyd-troubleshoot.sh"
else
    echo "  - fapolicyd: Not enabled"
fi
echo ""

echo "Documentation: https://github.com/hanalyx/openwatch"
echo ""
echo "=== Post-installation log saved to /var/log/openwatch/install.log ==="

# Show minimal output to screen (stdout is still redirected to log)
# Use file descriptor 3 to write to terminal
exec 3>&2
echo >&3
echo "OpenWatch installation completed successfully." >&3
echo "Installation log: /var/log/openwatch/install.log" >&3
echo >&3

%preun
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop openwatch.service openwatch-db.service || true
    systemctl disable openwatch.service openwatch-db.service || true
fi

%postun
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

# Handle package removal (not upgrade)
if [ $1 -eq 0 ]; then
    echo ""
    echo "OpenWatch RPM package has been removed."
    echo ""
    echo "IMPORTANT: Application data and containers have been preserved."
    echo ""
    echo "To completely remove all OpenWatch data, run:"
    echo "  /usr/share/openwatch/scripts/cleanup-openwatch.sh --help"
    echo ""
    echo "Cleanup options:"
    echo "  Basic cleanup:     /usr/share/openwatch/scripts/cleanup-openwatch.sh"
    echo "  With backup:       /usr/share/openwatch/scripts/cleanup-openwatch.sh --backup"
    echo "  Preview cleanup:   /usr/share/openwatch/scripts/cleanup-openwatch.sh --dry-run"
    echo ""
    echo "WARNING: Complete cleanup is irreversible without backup!"
    echo ""

    # Basic cleanup - only user accounts and system integration
    # Data directories are preserved for safety

    # Remove openwatch user (but preserve data directories)
    userdel openwatch 2>/dev/null || true

    # Remove SELinux policy module
    if command -v semodule >/dev/null 2>&1; then
        semodule -r openwatch 2>/dev/null || true
        echo "Removed OpenWatch SELinux policy"
    fi

    # Clean up fapolicyd rules
    if command -v fapolicyd >/dev/null 2>&1 && [ -f /usr/share/openwatch/scripts/configure-fapolicyd.sh ]; then
        /usr/share/openwatch/scripts/configure-fapolicyd.sh cleanup 2>/dev/null || true
        echo "Removed OpenWatch fapolicyd rules"
    fi
fi

%files
# Main binary
%{_bindir}/owadm

# Configuration files
%dir %attr(750,openwatch,openwatch) %{_sysconfdir}/openwatch
%dir %attr(700,openwatch,openwatch) %{_sysconfdir}/openwatch/ssh
%config(noreplace) %attr(640,openwatch,openwatch) %{_sysconfdir}/openwatch/ow.yml
%config(noreplace) %attr(600,openwatch,openwatch) %{_sysconfdir}/openwatch/secrets.env
%ghost %attr(600,openwatch,openwatch) %{_sysconfdir}/openwatch/.env

# Systemd service files
/lib/systemd/system/openwatch.service
/lib/systemd/system/openwatch-db.service

# Application data
%dir %attr(755,root,root) %{_datadir}/openwatch
%dir %attr(755,openwatch,openwatch) %{_datadir}/openwatch/compose
%dir %attr(755,root,root) %{_datadir}/openwatch/scripts
%dir %attr(755,root,root) %{_datadir}/openwatch/templates
%dir %attr(755,root,root) %{_datadir}/openwatch/docker
%dir %attr(755,root,root) %{_datadir}/openwatch/docker/database
%dir %attr(755,root,root) %{_datadir}/openwatch/docker/frontend

# owadm required directories (created by post-install script)
%dir %attr(755,openwatch,openwatch) %{_datadir}/openwatch/compose/logs
%dir %attr(755,openwatch,openwatch) %{_datadir}/openwatch/compose/data
%dir %attr(755,openwatch,openwatch) %{_datadir}/openwatch/compose/data/scap
%dir %attr(755,openwatch,openwatch) %{_datadir}/openwatch/compose/data/results
%dir %attr(755,openwatch,openwatch) %{_datadir}/openwatch/compose/data/uploads
%dir %attr(755,openwatch,openwatch) %{_datadir}/openwatch/compose/security
%dir %attr(700,openwatch,openwatch) %{_datadir}/openwatch/compose/security/keys
%dir %attr(755,openwatch,openwatch) %{_datadir}/openwatch/compose/security/certs
%dir %attr(755,openwatch,openwatch) %{_datadir}/openwatch/compose/backend
%dir %attr(755,openwatch,openwatch) %{_datadir}/openwatch/compose/backend/logs
%dir %attr(755,openwatch,openwatch) %{_datadir}/openwatch/compose/backend/security
%dir %attr(700,openwatch,openwatch) %{_datadir}/openwatch/compose/backend/security/keys
%{_datadir}/openwatch/compose/docker-compose.yml
%{_datadir}/openwatch/compose/podman-compose.yml
%ghost %{_datadir}/openwatch/compose/.env
%ghost %{_datadir}/openwatch/compose/docker
%{_datadir}/openwatch/docker/Containerfile.backend
%{_datadir}/openwatch/docker/Containerfile.frontend
%{_datadir}/openwatch/docker/Dockerfile.backend
%{_datadir}/openwatch/docker/Dockerfile.frontend
%{_datadir}/openwatch/docker/README.md
%{_datadir}/openwatch/docker/database/init.sql
%{_datadir}/openwatch/docker/frontend/default.conf
%{_datadir}/openwatch/docker/frontend/nginx.conf
%attr(755,root,root) %{_datadir}/openwatch/scripts/generate-secrets.sh
%attr(755,root,root) %{_datadir}/openwatch/scripts/configure-fapolicyd.sh
%attr(755,root,root) %{_datadir}/openwatch/scripts/fapolicyd-troubleshoot.sh
%attr(755,root,root) %{_datadir}/openwatch/scripts/cleanup-openwatch.sh
%attr(755,root,root) %{_datadir}/openwatch/scripts/fix-podman-permissions.sh
%attr(755,root,root) %{_datadir}/openwatch/scripts/podman-troubleshoot.sh
%{_datadir}/openwatch/templates/90-openwatch.rules

# SELinux policy files
%{_datadir}/selinux/packages/openwatch.pp

# Runtime directories
%dir %attr(755,openwatch,openwatch) %{_localstatedir}/lib/openwatch
%dir %attr(755,openwatch,openwatch) %{_localstatedir}/log/openwatch
%dir %attr(755,openwatch,openwatch) %{_localstatedir}/cache/openwatch

%changelog
* Wed Feb 12 2026 OpenWatch Team <admin@hanalyx.com> - 2.0.0-1
- NEW: Renamed package to openwatch-po for Podman container deployment
- NEW: Added package conflict with openwatch (native), openwatch-do, openwatch-ko
- NEW: Build owadm with -tags container for container orchestration support
- IMPROVED: Updated description to clarify deployment options
- IMPROVED: Support for RHEL 8/9/10, Rocky Linux, AlmaLinux, Oracle Linux, CentOS Stream, Fedora
- NOTE: This package deploys OpenWatch via Podman containers
- NOTE: For native deployment without containers, use 'openwatch' package

* Sat Sep 21 2024 OpenWatch Team <admin@hanalyx.com> - 1.2.1-8
- NEW: Added comprehensive Podman permission fix scripts
- NEW: Added Podman troubleshooting tool for container build issues
- FIXED: Container image unpacking failures with "operation not permitted"
- IMPROVED: SELinux detection with fallback for non-SELinux systems
- IMPROVED: Storage driver configuration for better compatibility
- ADDED: Systemd service override recommendations for container permissions

* Sat Sep 21 2024 OpenWatch Team <admin@hanalyx.com> - 1.2.1-7
- FIXED: Git repository properly initialized to include committed owladm fixes
- FIXED: RPM build now uses git archive with committed source code changes
- RESOLVED: "operation not permitted" errors in production installations
- RESOLVED: "missing backend/app/main.py" environment detection issues
- Enhanced directory permission handling with graceful fallback for constrained environments

* Sat Sep 21 2024 OpenWatch Team <admin@hanalyx.com> - 1.2.1-6
- FIXED: owadm source code changes properly included in RPM package
- FIXED: Directory permission handling now works correctly in production
- FIXED: Environment detection properly identifies production vs development
- Remove all emoji characters from owadm terminal output
- Comprehensive cleanup script with backup capabilities included

* Sat Sep 21 2024 OpenWatch Team <admin@hanalyx.com> - 1.2.1-5
- Add comprehensive cleanup script for complete OpenWatch removal
- Implement cleanup with backup options for data preservation
- Fix directory permission handling to work in production environments
- Improve environment detection for RPM vs development installations
- Enhanced removal process with clear administrator guidance
- Remove all emoji characters from owadm terminal output for compatibility

* Fri Sep 20 2024 OpenWatch Team <admin@hanalyx.com> - 1.2.1-4
- Fix owadm directory creation logic for production installations
- Resolve security/keys permission errors during service startup
- Improve environment file detection for RPM installations
- Add graceful handling of missing source files in production
- Skip directory chmod operations when permissions are already correct

* Fri Sep 20 2024 OpenWatch Team <admin@hanalyx.com> - 1.2.1-3
- Pre-create all owadm required directories to prevent permission errors
- Fix "operation not permitted" chmod failures on security directories
- Ensure consistent owadm behavior across all deployment environments
- Add proper directory structure matching owadm prerequisites.go expectations
- Set correct ownership and permissions on security key directories

* Fri Sep 20 2024 OpenWatch Team <admin@hanalyx.com> - 1.2.1-2
- Switch to system-level containers for systemd service reliability
- Resolve user namespace UID/GID mapping issues
- Fix SELinux transition denials for container operations
- Enhance systemd service security with capability restrictions
- Improve container build process compatibility
- Add comprehensive docker directory structure to RPM
- Remove emoji characters for terminal compatibility

* Wed Sep 18 2024 OpenWatch Team <admin@hanalyx.com> - 1.2.1-1
- Update to version 1.2.1
- Add fapolicyd integration for application whitelisting
- Include comprehensive fapolicyd rules for all OpenWatch components
- Add fapolicyd troubleshooting and diagnostic tools
- Automatic fapolicyd configuration during package installation
- Enhanced security for RHEL/Oracle Linux deployments

* Tue Sep 17 2024 OpenWatch Team <admin@hanalyx.com> - 1.0.0-1
- Initial RPM package for OpenWatch
- Support for RHEL 8+, Oracle Linux 8+
- Container runtime abstraction (Podman/Docker)
- Enterprise security defaults
- SELinux integration
- Systemd service management
- Automated secret generation
- FIPS compliance ready
