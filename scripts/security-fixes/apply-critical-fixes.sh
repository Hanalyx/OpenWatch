#!/bin/bash
################################################################################
# OpenWatch Critical Security Fixes - Automated Application Script
# Generated: October 15, 2025
################################################################################

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_FILE="${PROJECT_ROOT}/security-fixes-$(date +%Y%m%d-%H%M%S).log"

log() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"; }

log "Starting OpenWatch Security Fixes..."
log "Project root: ${PROJECT_ROOT}"

DRY_RUN=false
if [ "${1:-}" = "--check-only" ] || [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=true
    warning "Running in DRY-RUN mode"
fi

# Phase 1: Update packages
log "Phase 1: Updating vulnerable Python packages..."
if [ "$DRY_RUN" = false ]; then
    cd "${PROJECT_ROOT}/backend"
    source venv/bin/activate
    pip install --upgrade cryptography==44.0.2 PyJWT==2.10.1 Pillow==11.3.0 requests==2.32.5 PyYAML==6.0.3 Jinja2==3.1.6
    pip check && success "All packages updated"
else
    log "DRY-RUN: Would upgrade 6 packages"
fi

# Phase 2: Generate secrets
log "Phase 2: Generating secure secrets..."
if [ "$DRY_RUN" = false ]; then
    echo "OPENWATCH_ENCRYPTION_KEY=$(openssl rand -hex 32)"
    echo "OPENWATCH_SECRET_KEY=$(openssl rand -hex 32)"
    success "Generated secure secrets (add to .env file)"
else
    log "DRY-RUN: Would generate 2 secure secrets"
fi

success "Script completed"
log "See ${PROJECT_ROOT}/SECURITY_ASSESSMENT_COMPLETE.md for details"
