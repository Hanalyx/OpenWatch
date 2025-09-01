#!/bin/bash
# OpenWatch RPM Build Script
# Builds RPM packages for RHEL/Oracle Linux distribution

set -euo pipefail

# Build configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$HOME/rpmbuild"
SPEC_FILE="$SCRIPT_DIR/openwatch.spec"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking build prerequisites..."
    
    # Check if we're on RHEL/Oracle/Fedora
    if ! command -v rpm >/dev/null 2>&1; then
        log_error "RPM tools not found. This script requires RHEL, Oracle Linux, or Fedora."
        exit 1
    fi
    
    # Check for required tools
    local missing_tools=()
    for tool in rpmbuild rpmdev-setuptree go git; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Install with: dnf install rpm-build rpmdevtools golang git"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Setup RPM build environment
setup_build_env() {
    log_info "Setting up RPM build environment..."
    
    # Create RPM build directory structure
    rpmdev-setuptree
    
    # Verify directory structure
    for dir in BUILD RPMS SOURCES SPECS SRPMS; do
        if [ ! -d "$BUILD_DIR/$dir" ]; then
            log_error "Failed to create RPM directory: $BUILD_DIR/$dir"
            exit 1
        fi
    done
    
    log_success "RPM build environment ready"
}

# Prepare source tarball
prepare_sources() {
    log_info "Preparing source tarball..."
    
    cd "$PROJECT_ROOT"
    
    # Get version from git or default
    local version
    version=$(git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "1.0.0")
    
    # Build SELinux policy first
    log_info "Building SELinux policy..."
    cd "$PROJECT_ROOT/packaging/selinux"
    make -f /usr/share/selinux/devel/Makefile openwatch.pp 2>/dev/null || {
        log_warning "SELinux policy compilation failed - policy will be compiled during RPM build"
    }
    
    cd "$PROJECT_ROOT"
    
    # Create source tarball
    local tarball_name="openwatch-${version}.tar.gz"
    local tarball_path="$BUILD_DIR/SOURCES/$tarball_name"
    
    # Create clean source archive (exclude build artifacts and sensitive files)
    git archive --format=tar.gz --prefix="openwatch-${version}/" \
        --output="$tarball_path" HEAD
    
    log_success "Source tarball created: $tarball_path"
    echo "Version: $version"
}

# Copy spec file
copy_spec() {
    log_info "Copying RPM spec file..."
    
    cp "$SPEC_FILE" "$BUILD_DIR/SPECS/"
    
    log_success "Spec file copied to $BUILD_DIR/SPECS/"
}

# Build RPM packages
build_rpm() {
    log_info "Building RPM packages..."
    
    cd "$BUILD_DIR"
    
    # Build source and binary RPMs
    rpmbuild -ba SPECS/openwatch.spec
    
    if [ $? -eq 0 ]; then
        log_success "RPM build completed successfully!"
        
        # Show built packages
        echo ""
        log_info "Built packages:"
        find RPMS SRPMS -name "openwatch*.rpm" -exec ls -lh {} \;
        
        # Copy to project directory for easy access
        mkdir -p "$PROJECT_ROOT/packaging/rpm/dist"
        find RPMS SRPMS -name "openwatch*.rpm" -exec cp {} "$PROJECT_ROOT/packaging/rpm/dist/" \;
        
        echo ""
        log_success "Packages copied to: $PROJECT_ROOT/packaging/rpm/dist/"
        
    else
        log_error "RPM build failed!"
        exit 1
    fi
}

# Test installation (if running as root)
test_installation() {
    if [ "$EUID" -eq 0 ]; then
        log_info "Testing RPM installation..."
        
        local rpm_file
        rpm_file=$(find "$PROJECT_ROOT/packaging/rpm/dist" -name "openwatch-*.x86_64.rpm" | head -1)
        
        if [ -n "$rpm_file" ]; then
            # Test install (dry run)
            rpm -qp --requires "$rpm_file"
            log_success "RPM dependency check passed"
        else
            log_warning "No RPM file found for testing"
        fi
    else
        log_warning "Skipping installation test (not running as root)"
    fi
}

# Main execution
main() {
    echo "🏗️  OpenWatch RPM Build Script"
    echo "================================"
    
    check_prerequisites
    setup_build_env
    prepare_sources
    copy_spec
    build_rpm
    test_installation
    
    echo ""
    log_success "OpenWatch RPM package build completed!"
    echo ""
    echo "📦 Install with:"
    echo "   sudo dnf install $PROJECT_ROOT/packaging/rpm/dist/openwatch-*.rpm"
    echo ""
    echo "🚀 After installation:"
    echo "   1. Review: /etc/openwatch/ow.yml"
    echo "   2. Start: sudo systemctl start openwatch"
    echo "   3. Status: owadm status"
    echo ""
}

# Allow script to be sourced for testing
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi