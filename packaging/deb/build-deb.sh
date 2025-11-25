#!/bin/bash
# OpenWatch DEB Build Script
# Builds DEB packages for Ubuntu 24.04+ distribution

set -euo pipefail

# Build configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PACKAGE_NAME="openwatch"
ARCH="amd64"

# Get version from git or default
VERSION=$(cd "$PROJECT_ROOT" && git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "1.0.0")

# Build directory
BUILD_DIR="$SCRIPT_DIR/build"
PACKAGE_DIR="$BUILD_DIR/${PACKAGE_NAME}_${VERSION}_${ARCH}"

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
    for tool in dpkg-deb fakeroot go git; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Install with: sudo apt install build-essential golang git"
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

    # Set build-time variables
    LDFLAGS="-s -w \
        -X github.com/hanalyx/openwatch/internal/owadm/cmd.Version=$VERSION \
        -X github.com/hanalyx/openwatch/internal/owadm/cmd.Commit=$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown') \
        -X github.com/hanalyx/openwatch/internal/owadm/cmd.BuildTime=$(date -u '+%Y-%m-%d_%H:%M:%S')"

    go build -ldflags "$LDFLAGS" -o "$BUILD_DIR/owadm" cmd/owadm/main.go

    if [ ! -f "$BUILD_DIR/owadm" ]; then
        log_error "Failed to build owadm binary"
        exit 1
    fi

    log_success "Binary built successfully"
}

# Create package structure
create_package_structure() {
    log_info "Creating package structure..."

    # Create directory structure
    mkdir -p "$PACKAGE_DIR/DEBIAN"
    mkdir -p "$PACKAGE_DIR/usr/bin"
    mkdir -p "$PACKAGE_DIR/usr/share/openwatch/compose"
    mkdir -p "$PACKAGE_DIR/usr/share/openwatch/scripts"
    mkdir -p "$PACKAGE_DIR/usr/share/openwatch/systemd"
    mkdir -p "$PACKAGE_DIR/usr/share/doc/openwatch"
    mkdir -p "$PACKAGE_DIR/etc/openwatch/ssh"
    mkdir -p "$PACKAGE_DIR/var/lib/openwatch"
    mkdir -p "$PACKAGE_DIR/var/log/openwatch"

    # Copy control files
    cp -r "$SCRIPT_DIR/DEBIAN"/* "$PACKAGE_DIR/DEBIAN/"

    # Update version in control file
    sed -i "s/^Version:.*/Version: $VERSION/" "$PACKAGE_DIR/DEBIAN/control"

    # Copy binary
    cp "$BUILD_DIR/owadm" "$PACKAGE_DIR/usr/bin/"
    chmod 755 "$PACKAGE_DIR/usr/bin/owadm"

    # Copy compose files
    cp "$PROJECT_ROOT/docker-compose.yml" "$PACKAGE_DIR/usr/share/openwatch/compose/"
    cp "$PROJECT_ROOT/podman-compose.yml" "$PACKAGE_DIR/usr/share/openwatch/compose/" 2>/dev/null || true

    # Create systemd service files
    create_systemd_files

    # Copy documentation
    cp "$PROJECT_ROOT/README.md" "$PACKAGE_DIR/usr/share/doc/openwatch/"
    cp "$PROJECT_ROOT/LICENSE" "$PACKAGE_DIR/usr/share/doc/openwatch/" 2>/dev/null || true

    # Create changelog
    create_changelog

    # Create copyright file
    create_copyright

    log_success "Package structure created"
}

# Create systemd service files
create_systemd_files() {
    log_info "Creating systemd service files..."

    # Main service
    cat > "$PACKAGE_DIR/usr/share/openwatch/systemd/openwatch.service" << 'EOF'
[Unit]
Description=OpenWatch SCAP Compliance Platform
Documentation=https://github.com/hanalyx/openwatch
Requires=openwatch-db.service
After=network-online.target openwatch-db.service docker.service
Wants=network-online.target

[Service]
Type=forking
User=openwatch
Group=openwatch
EnvironmentFile=/etc/openwatch/secrets.env
ExecStartPre=/usr/bin/owadm validate-config
ExecStart=/usr/bin/owadm start --daemon
ExecStop=/usr/bin/owadm stop
ExecReload=/usr/bin/owadm restart
Restart=on-failure
RestartSec=10
KillMode=mixed
TimeoutStartSec=300
TimeoutStopSec=120

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/openwatch /var/log/openwatch /etc/openwatch
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
LockPersonality=true

# Ubuntu-specific: AppArmor profile
AppArmorProfile=openwatch-containers

[Install]
WantedBy=multi-user.target
EOF

    # Database service
    cat > "$PACKAGE_DIR/usr/share/openwatch/systemd/openwatch-db.service" << 'EOF'
[Unit]
Description=OpenWatch Database Container
Documentation=https://github.com/hanalyx/openwatch
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=forking
User=openwatch
Group=openwatch
EnvironmentFile=/etc/openwatch/secrets.env
ExecStartPre=/usr/bin/owadm validate-config --database-only
ExecStart=/usr/bin/owadm start --database-only --daemon
ExecStop=/usr/bin/owadm stop --database-only
Restart=on-failure
RestartSec=5
TimeoutStartSec=60
TimeoutStopSec=30

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/openwatch
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
}

# Create changelog
create_changelog() {
    log_info "Creating changelog..."

    cat > "$PACKAGE_DIR/usr/share/doc/openwatch/changelog" << EOF
openwatch ($VERSION) stable; urgency=medium

  * Initial Ubuntu package release
  * Support for Ubuntu 24.04 LTS and newer
  * Docker runtime as default (with Podman support)
  * AppArmor security profile integration
  * Systemd service management
  * Automated secret generation
  * SCAP compliance scanning platform

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

    # Build the package
    cd "$BUILD_DIR"
    fakeroot dpkg-deb --build "${PACKAGE_NAME}_${VERSION}_${ARCH}"

    if [ $? -eq 0 ]; then
        log_success "DEB package built successfully!"

        # Create dist directory
        mkdir -p "$SCRIPT_DIR/dist"
        mv "${PACKAGE_NAME}_${VERSION}_${ARCH}.deb" "$SCRIPT_DIR/dist/"

        # Show package info
        echo ""
        log_info "Package details:"
        dpkg-deb --info "$SCRIPT_DIR/dist/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"

        echo ""
        log_success "Package saved to: $SCRIPT_DIR/dist/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"

    else
        log_error "DEB package build failed!"
        exit 1
    fi
}

# Verify package
verify_package() {
    log_info "Verifying package..."

    local deb_file="$SCRIPT_DIR/dist/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"

    # Check with lintian if available
    if command -v lintian >/dev/null 2>&1; then
        log_info "Running lintian checks..."
        lintian --info "$deb_file" || log_warning "Lintian found some issues (this is common for custom packages)"
    fi

    # List contents
    log_info "Package contents:"
    dpkg-deb --contents "$deb_file" | head -20
    echo "..."
}

# Main execution
main() {
    echo "OpenWatch DEB Build Script"
    echo "================================"

    check_prerequisites
    clean_build
    build_binary
    create_package_structure
    build_package
    verify_package

    echo ""
    log_success "OpenWatch DEB package build completed!"
    echo ""
    echo "Install with:"
    echo "   sudo apt install $SCRIPT_DIR/dist/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"
    echo ""
    echo "After installation:"
    echo "   1. Review: /etc/openwatch/ow.yml"
    echo "   2. Start: sudo systemctl start openwatch"
    echo "   3. Status: owadm status"
    echo ""
}

# Allow script to be sourced for testing
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
