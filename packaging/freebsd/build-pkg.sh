#!/usr/bin/env bash
# Build FreeBSD pkg for OpenWatch
# UNTESTED -- requires FreeBSD 15.0 build environment (native or jail)
#
# This script must run on FreeBSD 15.0 or inside a FreeBSD jail.
# It uses pkg-create(8) to produce a .pkg file suitable for air-gapped
# deployment via `pkg add openwatch-<version>.pkg`.
#
# Prerequisites:
#   - FreeBSD 15.0-RELEASE or compatible jail
#   - pkg, python312, py312-pip, postgresql15-client, openssh-portable
#   - Node.js 20+ (for frontend build)
#   - git (for Kensa install from GitHub)
#
# Usage:
#   ./packaging/freebsd/build-pkg.sh
#
# Output:
#   packaging/freebsd/output/openwatch-<VERSION>.pkg
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Source version info
# shellcheck source=packaging/version.env
source "${PROJECT_ROOT}/packaging/version.env"

echo "========================================"
echo "OpenWatch FreeBSD Package Builder"
echo "Version: ${VERSION}"
echo "Codename: ${CODENAME}"
echo "========================================"
echo ""
echo "NOTE: This script must run on FreeBSD 15.0 or in a FreeBSD jail."
echo "      It has NOT been tested and is provided as a structural skeleton."
echo ""

# Verify we are on FreeBSD
if [ "$(uname -s)" != "FreeBSD" ]; then
    echo "ERROR: This script must run on FreeBSD. Detected: $(uname -s)"
    exit 1
fi

# --- Build directories ---
BUILD_DIR="${SCRIPT_DIR}/build"
STAGING="${BUILD_DIR}/staging"
OUTPUT_DIR="${SCRIPT_DIR}/output"

rm -rf "${BUILD_DIR}"
mkdir -p "${STAGING}" "${OUTPUT_DIR}"

# --- Stage 1: Python virtual environment ---
echo "[1/5] Creating Python virtual environment..."
python3.12 -m venv "${STAGING}/opt/openwatch/venv"
"${STAGING}/opt/openwatch/venv/bin/pip" install --no-cache-dir --upgrade pip
"${STAGING}/opt/openwatch/venv/bin/pip" install --no-cache-dir -r "${PROJECT_ROOT}/backend/requirements.txt"

# --- Stage 2: Backend application ---
echo "[2/5] Copying backend application..."
mkdir -p "${STAGING}/opt/openwatch/backend"
cp -a "${PROJECT_ROOT}/backend/app" "${STAGING}/opt/openwatch/backend/app"
cp "${PROJECT_ROOT}/backend/requirements.txt" "${STAGING}/opt/openwatch/backend/"

# --- Stage 3: Frontend SPA ---
echo "[3/5] Building frontend SPA..."
if command -v npm >/dev/null 2>&1; then
    cd "${PROJECT_ROOT}/frontend"
    npm ci --no-audit --no-fund
    npm run build
    mkdir -p "${STAGING}/opt/openwatch/frontend"
    cp -a "${PROJECT_ROOT}/frontend/build" "${STAGING}/opt/openwatch/frontend/build"
    cd "${PROJECT_ROOT}"
else
    echo "WARNING: npm not found, skipping frontend build."
    echo "         Install node20 and npm to include the frontend SPA."
fi

# --- Stage 4: Kensa rules and mappings ---
echo "[4/5] Bundling Kensa rules..."
KENSA_TEMP=$(mktemp -d)
python3.12 -m venv "${KENSA_TEMP}/venv"
"${KENSA_TEMP}/venv/bin/pip" install --no-cache-dir kensa 2>/dev/null || \
    "${KENSA_TEMP}/venv/bin/pip" install --no-cache-dir \
        "kensa @ git+https://github.com/Hanalyx/kensa.git@v1.2.5" 2>/dev/null || true

KENSA_SHARE=$(find "${KENSA_TEMP}/venv" -type d -name "kensa" -path "*/share/*" 2>/dev/null | head -1)
if [ -n "${KENSA_SHARE}" ]; then
    mkdir -p "${STAGING}/opt/openwatch/backend/kensa"
    cp -a "${KENSA_SHARE}/"* "${STAGING}/opt/openwatch/backend/kensa/"
    echo "    Kensa data copied from ${KENSA_SHARE}"
else
    echo "WARNING: Could not locate Kensa share data. Rules will not be bundled."
fi
rm -rf "${KENSA_TEMP}"

# --- Stage 5: Configuration and services ---
echo "[5/5] Installing configuration and rc.d services..."

# Configuration directory
mkdir -p "${STAGING}/usr/local/etc/openwatch"
# TODO: Copy default ow.yml, secrets.env.example, logging.yml from packaging/config/

# rc.d service scripts
mkdir -p "${STAGING}/usr/local/etc/rc.d"
install -m 0555 "${SCRIPT_DIR}/rc.d/openwatch_api" "${STAGING}/usr/local/etc/rc.d/openwatch_api"
install -m 0555 "${SCRIPT_DIR}/rc.d/openwatch_worker" "${STAGING}/usr/local/etc/rc.d/openwatch_worker"

# --- Create package manifest ---
echo "Creating package manifest..."

cat > "${BUILD_DIR}/+MANIFEST" <<MANIFEST
name: openwatch
version: "${VERSION}"
origin: "security/openwatch"
comment: "OpenWatch Compliance Scanning Platform"
desc: "OpenWatch is an enterprise compliance scanning platform powered by Kensa."
maintainer: "security@openwatch.dev"
www: "https://github.com/Hanalyx/openwatch"
prefix: /
deps: {
    python312: { origin: "lang/python312", version: "3.12" },
    postgresql15-client: { origin: "databases/postgresql15-client", version: "15" },
    openssh-portable: { origin: "security/openssh-portable", version: "9" }
}
MANIFEST

# Generate packing list
(cd "${STAGING}" && find . -type f | sed 's|^\./||') > "${BUILD_DIR}/+COMPACT_MANIFEST"

# --- Build the package ---
echo ""
echo "TODO: Run pkg-create(8) to produce the final .pkg file."
echo "      The staging directory is ready at: ${STAGING}"
echo ""
echo "      Example (untested):"
echo "        pkg create -m ${BUILD_DIR} -r ${STAGING} -o ${OUTPUT_DIR}"
echo ""
echo "      Expected output: ${OUTPUT_DIR}/openwatch-${VERSION}.pkg"
echo ""

# Uncomment when ready to build:
# pkg create -m "${BUILD_DIR}" -r "${STAGING}" -o "${OUTPUT_DIR}"

echo "Build skeleton complete. Package staging directory: ${STAGING}"
