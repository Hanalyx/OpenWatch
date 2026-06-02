#!/bin/bash

# OpenWatch (Go rebuild) stop script.
#
# The Go rebuild runs as a host binary (./dist/openwatch serve +
# ./dist/openwatch worker) plus one standalone PostgreSQL container
# (openwatch-pg, volume openwatch-pg-fresh). No docker-compose.
# This script tears that down safely.
#
# What it does:
#   1. Default: stop the host processes (serve, worker, Vite). The DB
#      container keeps running so the next start is instant. Data is
#      always preserved on the named volume.
#   2. --stop-db: also stop the DB container. Volume still survives.
#   3. --clean-data: stop + DELETE the named DB volume (hosts,
#      credentials, scans, audit log). Gated on --yes / interactive.
#   4. --deep-clean: --clean-data + remove the DB container entirely
#      and clear frontend node_modules.
#
# What it does NOT do (and why):
#   - No docker-compose. The Python compose stack is gone.
#   - No image cleanup. The Go build produces a host binary, not an image.
#   - No Redis / MongoDB / Celery tear-down. None of those run anymore.

set -e

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# ---------------------------------------------------------------------------
# Config — must stay in sync with start-openwatch.sh
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
APP_DIR="${SCRIPT_DIR}/app"

DB_CONTAINER="${OPENWATCH_DB_CONTAINER:-openwatch-pg}"
DB_VOLUME="${OPENWATCH_DB_VOLUME:-openwatch-pg-fresh}"
CONTAINER_RUNTIME="${OPENWATCH_CONTAINER_RUNTIME:-}"

MODE="safe"        # safe | stop-db | clean-data | deep-clean
ASSUME_YES=false

# ---------------------------------------------------------------------------
# Runtime detection
# ---------------------------------------------------------------------------
detect_container_runtime() {
    if [ -n "$CONTAINER_RUNTIME" ]; then
        return 0
    fi
    if command -v docker &> /dev/null; then
        CONTAINER_RUNTIME=docker
    elif command -v podman &> /dev/null; then
        CONTAINER_RUNTIME=podman
    else
        # No container runtime — nothing to do for the DB side.
        CONTAINER_RUNTIME=""
    fi
}

# ---------------------------------------------------------------------------
# Destruction confirmation — gates --clean-data and --deep-clean
# ---------------------------------------------------------------------------
confirm_destroy() {
    local action="$1"
    log_warning "About to perform: ${action}"
    log_warning "This will DELETE the DB volume (if present):"
    if [ -n "$CONTAINER_RUNTIME" ] && \
       "$CONTAINER_RUNTIME" volume ls --format "{{.Name}}" 2>/dev/null | grep -qx "$DB_VOLUME"; then
        echo -e "  - ${RED}${DB_VOLUME}${NC} (hosts, credentials, scans, audit log)"
    else
        echo -e "  - ${DB_VOLUME} (does not exist; nothing to delete)"
        return 0
    fi

    if [ "$ASSUME_YES" = true ]; then
        log_warning "--yes supplied; proceeding without prompt."
        return 0
    fi
    if [ "${OPENWATCH_CONFIRM_DESTROY:-}" = "yes" ]; then
        log_warning "OPENWATCH_CONFIRM_DESTROY=yes set; proceeding without prompt."
        return 0
    fi
    if [ ! -t 0 ]; then
        log_error "Refusing to delete the DB volume non-interactively without --yes or OPENWATCH_CONFIRM_DESTROY=yes."
        exit 1
    fi
    echo ""
    read -r -p "Type 'yes' to confirm destruction, anything else aborts: " confirm
    if [ "$confirm" != "yes" ]; then
        log_info "Aborted — no data was deleted."
        exit 0
    fi
}

# ---------------------------------------------------------------------------
# Process lifecycle — host binaries + Vite
# ---------------------------------------------------------------------------
stop_one_process() {
    # $1 = pgrep pattern, $2 = human label
    local pattern="$1" label="$2"
    local pids
    pids=$(pgrep -f "$pattern" || true)
    if [ -z "$pids" ]; then
        return 0
    fi
    log_info "Stopping ${label} (PIDs: $(echo "$pids" | tr '\n' ' '))..."
    # SIGTERM first, give it 3s to exit cleanly, then SIGKILL.
    echo "$pids" | xargs -r kill -TERM 2>/dev/null || true
    local i
    for i in 1 2 3; do
        pids=$(pgrep -f "$pattern" || true)
        [ -z "$pids" ] && return 0
        sleep 1
    done
    pids=$(pgrep -f "$pattern" || true)
    if [ -n "$pids" ]; then
        log_warning "${label} did not exit on SIGTERM; sending SIGKILL."
        echo "$pids" | xargs -r kill -KILL 2>/dev/null || true
    fi
}

stop_processes() {
    stop_one_process "dist/openwatch serve\$"   "openwatch serve"
    stop_one_process "dist/openwatch worker\$"  "openwatch worker"
    stop_one_process "vite --port 5173"         "Vite dev server"
}

# ---------------------------------------------------------------------------
# DB container lifecycle
# ---------------------------------------------------------------------------
stop_db_container() {
    [ -z "$CONTAINER_RUNTIME" ] && return 0
    if "$CONTAINER_RUNTIME" ps --format "{{.Names}}" 2>/dev/null | grep -qx "$DB_CONTAINER"; then
        log_info "Stopping DB container ${DB_CONTAINER}..."
        "$CONTAINER_RUNTIME" stop "$DB_CONTAINER" >/dev/null
    else
        log_info "DB container ${DB_CONTAINER} is not running."
    fi
}

remove_db_container() {
    [ -z "$CONTAINER_RUNTIME" ] && return 0
    if "$CONTAINER_RUNTIME" ps -a --format "{{.Names}}" 2>/dev/null | grep -qx "$DB_CONTAINER"; then
        log_info "Removing DB container ${DB_CONTAINER}..."
        "$CONTAINER_RUNTIME" rm -f "$DB_CONTAINER" >/dev/null
    fi
}

delete_db_volume() {
    [ -z "$CONTAINER_RUNTIME" ] && return 0
    if "$CONTAINER_RUNTIME" volume ls --format "{{.Name}}" 2>/dev/null | grep -qx "$DB_VOLUME"; then
        log_info "Removing DB volume ${DB_VOLUME}..."
        "$CONTAINER_RUNTIME" volume rm -f "$DB_VOLUME" >/dev/null
    fi
}

clear_frontend_node_modules() {
    local nm="${APP_DIR}/frontend/node_modules"
    if [ -d "$nm" ]; then
        log_info "Removing ${nm}..."
        rm -rf "$nm"
    fi
}

# ---------------------------------------------------------------------------
# Final summary — what survived
# ---------------------------------------------------------------------------
print_data_status() {
    if [ -z "$CONTAINER_RUNTIME" ]; then
        return 0
    fi
    if "$CONTAINER_RUNTIME" volume ls --format "{{.Name}}" 2>/dev/null | grep -qx "$DB_VOLUME"; then
        log_info "Data preserved in volume:"
        echo -e "  ${GREEN}✓${NC} ${DB_VOLUME}"
        log_info "Re-run ./start-openwatch.sh to resume against the same data."
    else
        log_info "DB volume ${DB_VOLUME} no longer exists. The next start will create a fresh DB."
    fi
}

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
print_help() {
    cat <<EOF
OpenWatch (Go) Stop Script

Stops the host binaries (serve, worker, Vite) and optionally the
PostgreSQL container. SAFE BY DEFAULT — the named DB volume is
preserved across stop/start cycles.

Usage: ./stop-openwatch.sh [OPTIONS]

Options:
  (no options)        Stop serve, worker, Vite. Leave the DB container
                      running. Data preserved.
  --stop-db           Also stop the DB container (${DB_CONTAINER}).
                      Volume still preserved.
  --clean-data        Stop everything and DELETE the DB volume
                      (${DB_VOLUME}). Requires --yes /
                      OPENWATCH_CONFIRM_DESTROY=yes / interactive 'yes'.
  --deep-clean        --clean-data + remove the DB container and clear
                      app/frontend/node_modules. Same confirmation gate.
  --yes, -y           Skip the confirmation prompt. Required when running
                      destructive modes non-interactively (CI, scripts).
  --help, -h          Print this help.

Environment overrides:
  OPENWATCH_DB_CONTAINER         postgres container name  (default ${DB_CONTAINER})
  OPENWATCH_DB_VOLUME            named volume holding data (default ${DB_VOLUME})
  OPENWATCH_CONTAINER_RUNTIME    docker or podman          (auto-detect)
  OPENWATCH_CONFIRM_DESTROY=yes  Companion to --yes for destructive modes.

What is preserved on a safe stop:
  - DB volume ${DB_VOLUME} (hosts, credentials, scans, audit log)
  - The DB container (kept running for instant restart)
  - Runtime secrets in OPENWATCH_RUNTIME_DIR (TLS cert, JWT key, DEK)
  - Frontend node_modules

Examples:
  ./stop-openwatch.sh                       # Stop binaries; DB stays up
  ./stop-openwatch.sh --stop-db             # Also stop the DB container
  ./stop-openwatch.sh --clean-data --yes    # Wipe data; scripted
  ./stop-openwatch.sh --deep-clean          # Nuclear; prompts first
EOF
}

# ---------------------------------------------------------------------------
# Arg parsing
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --stop-db)     MODE="stop-db"; shift ;;
        --clean-data)  MODE="clean-data"; shift ;;
        --deep-clean)  MODE="deep-clean"; shift ;;
        --yes|-y)      ASSUME_YES=true; shift ;;
        --help|-h)     print_help; exit 0 ;;
        *)
            log_error "Unknown option: $1"
            log_error "Run ./stop-openwatch.sh --help for usage."
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
    log_info "OpenWatch (Go) Stop Script"
    log_info "===================="

    detect_container_runtime

    case "$MODE" in
        "deep-clean")
            confirm_destroy "deep clean (delete DB container + volume + node_modules)"
            stop_processes
            remove_db_container
            delete_db_volume
            clear_frontend_node_modules
            ;;
        "clean-data")
            confirm_destroy "clean-data (delete DB volume)"
            stop_processes
            stop_db_container  # must stop before volume can be removed
            delete_db_volume
            ;;
        "stop-db")
            stop_processes
            stop_db_container
            ;;
        "safe"|*)
            log_info "Safe mode: processes stop, DB container keeps running, data preserved."
            stop_processes
            ;;
    esac

    print_data_status

    log_success "Done!"
}

main
