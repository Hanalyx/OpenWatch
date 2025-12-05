#!/bin/bash
# Build OpenWatch with version information
#
# Usage:
#   ./scripts/build-with-version.sh              # Use VERSION file
#   ./scripts/build-with-version.sh 0.2.0        # Override version
#
# This script is designed for CI/CD pipelines.
# See docs/core/VERSIONING.md for versioning plan.

set -e

# Read version from VERSION file or use argument
if [ -n "$1" ]; then
    APP_VERSION="$1"
else
    APP_VERSION=$(cat VERSION 2>/dev/null || echo "0.0.0-dev")
fi

# Get git commit (short hash)
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "")

# Get build date in ISO format
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "Building OpenWatch with:"
echo "  VERSION:    $APP_VERSION"
echo "  GIT_COMMIT: $GIT_COMMIT"
echo "  BUILD_DATE: $BUILD_DATE"
echo ""

# Export for docker-compose
export APP_VERSION
export GIT_COMMIT
export BUILD_DATE

# Build with version info
docker compose build \
    --build-arg APP_VERSION="$APP_VERSION" \
    --build-arg GIT_COMMIT="$GIT_COMMIT" \
    --build-arg BUILD_DATE="$BUILD_DATE"

echo ""
echo "Build complete: OpenWatch v$APP_VERSION"
