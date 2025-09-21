#!/bin/bash
# Minimal RPM build script for OpenWatch 1.2.1-7
set -euo pipefail

PROJECT_ROOT="/home/rracine/hanalyx/openwatch"
BUILD_DIR="$HOME/rpmbuild"
VERSION="1.2.1"

echo "OpenWatch RPM Build - Version 1.2.1-7"
echo "======================================="

# Create build directories
echo "Creating build directories..."
mkdir -p "$BUILD_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
mkdir -p "$BUILD_DIR/RPMS"/{i386,i586,i686,x86_64,noarch}

# Create source tarball using tar (includes all current files with fixes)
echo "Creating source tarball..."
cd "$PROJECT_ROOT"
tar --exclude-vcs --exclude='*.rpm' --exclude='dist/' --exclude='rpmbuild/' \
    --exclude='node_modules/' --exclude='venv/' --exclude='*.log' \
    --exclude='*.tmp' --exclude='*.backup' --exclude='*.swp' \
    --exclude='security/keys/*.pem' --exclude='*.sock' --exclude='*.pid' \
    --transform "s,^,openwatch-${VERSION}/," \
    -czf "$BUILD_DIR/SOURCES/openwatch-${VERSION}.tar.gz" \
    -C "$PROJECT_ROOT/.." \
    "$(basename "$PROJECT_ROOT")"

# Copy spec file
echo "Copying spec file..."
cp "$PROJECT_ROOT/packaging/rpm/openwatch.spec" "$BUILD_DIR/SPECS/"

# Build RPM
echo "Building RPM..."
cd "$BUILD_DIR"
rpmbuild --nodeps -ba SPECS/openwatch.spec

# Copy results
echo "Copying built packages..."
mkdir -p "$PROJECT_ROOT/packaging/rpm/dist"
find RPMS SRPMS -name "openwatch*.rpm" -exec cp {} "$PROJECT_ROOT/packaging/rpm/dist/" \;

echo ""
echo "Build completed! Check $PROJECT_ROOT/packaging/rpm/dist/ for the new RPM files."