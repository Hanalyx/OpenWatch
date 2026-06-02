#!/bin/bash

# OpenWatch (Go rebuild) startup script.
#
# The Go rebuild runs as a host binary (./dist/openwatch) talking to a
# standalone PostgreSQL container. There is no docker-compose for the
# Go build today — the systemd units + RPM/DEB packages handle prod;
# this script handles local/dev.
#
# What it does:
#   1. Make sure the binary exists (build it on --build).
#   2. Make sure runtime secrets exist (TLS cert, JWT signing key,
#      credential DEK) — generate demo material if missing.
#   3. Make sure the PostgreSQL container is running, against the
#      named volume that holds hosts + credentials + scans.
#   4. Refuse to start if a foreign container is squatting on 5432
#      (would silently double-DB and "lose" data).
#   5. Run goose migrations.
#   6. Start `openwatch serve` in the background, then `openwatch
#      worker`. Logs go to "$RUNTIME_DIR/logs/".
#   7. Optionally start the Vite dev server (frontend).
#
# What it does NOT do (and why it's not in this script):
#   - No docker-compose. The Python compose stack is no longer relevant.
#   - No `.env` generation for Python (SECRET_KEY/MASTER_KEY/REDIS_*).
#     Go config is via OPENWATCH_* env vars + the TOML file.
#   - No SCAP content directories. Kensa rules ship inside the binary's
#     packaging path.
#   - No image build / no podman compose. We use one DB container.

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
# Config (every value is env-overridable)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
APP_DIR="${SCRIPT_DIR}/app"
BINARY="${APP_DIR}/dist/openwatch"

DB_CONTAINER="${OPENWATCH_DB_CONTAINER:-openwatch-pg}"
DB_VOLUME="${OPENWATCH_DB_VOLUME:-openwatch-pg-fresh}"
DB_IMAGE="${OPENWATCH_DB_IMAGE:-postgres:15.14-alpine}"
DB_USER="${OPENWATCH_DB_USER:-openwatch}"
DB_PASSWORD="${OPENWATCH_DB_PASSWORD:-openwatch_secure_db_2025}"
DB_NAME="${OPENWATCH_DB_NAME:-openwatch_go_dev}"
DB_PORT="${OPENWATCH_DB_PORT:-5432}"

RUNTIME_DIR="${OPENWATCH_RUNTIME_DIR:-/tmp/ow-run}"
LISTEN="${OPENWATCH_LISTEN:-127.0.0.1:8443}"

CONTAINER_RUNTIME="${OPENWATCH_CONTAINER_RUNTIME:-}"

DO_BUILD=false
RESET_DATA=false
NO_FRONTEND=false
NO_WORKER=false
ASSUME_YES=false

# ---------------------------------------------------------------------------
# preflight_data_check — informational: report whether the DB volume
# already exists. Read-only.
#
# preflight_port_check — refuse to start if a foreign container is
# bound to host port DB_PORT. Idempotent against our own DB_CONTAINER.
#
# reset_data_volumes — the single explicit way to wipe the DB volume.
# Gated on --yes / OPENWATCH_CONFIRM_DESTROY=yes / interactive "yes".
# ---------------------------------------------------------------------------

preflight_data_check() {
    if ! command -v "$CONTAINER_RUNTIME" &> /dev/null; then
        return 0
    fi
    if "$CONTAINER_RUNTIME" volume ls --format "{{.Name}}" 2>/dev/null | grep -qx "$DB_VOLUME"; then
        log_info "Found existing DB volume — start will RESUME against it:"
        echo -e "  ${GREEN}✓${NC} ${DB_VOLUME}"
        log_info "To start from a clean slate instead, run: ./start-openwatch.sh --reset-data"
    else
        log_info "No prior DB volume detected — first-time setup. Will create ${DB_VOLUME}."
    fi
}

reset_data_volumes() {
    log_warning "--reset-data requested. This will DELETE the DB volume:"
    if "$CONTAINER_RUNTIME" volume ls --format "{{.Name}}" 2>/dev/null | grep -qx "$DB_VOLUME"; then
        echo -e "  - ${RED}${DB_VOLUME}${NC} (hosts, credentials, scans, audit log)"
    else
        echo -e "  - ${DB_VOLUME} (does not exist; nothing to do)"
        log_info "Nothing to reset."
        return 0
    fi

    if [ "$ASSUME_YES" != true ] && [ "${OPENWATCH_CONFIRM_DESTROY:-}" != "yes" ]; then
        if [ ! -t 0 ]; then
            log_error "Refusing to delete the DB volume non-interactively without --yes / OPENWATCH_CONFIRM_DESTROY=yes."
            exit 1
        fi
        echo ""
        read -r -p "Type 'yes' to confirm destruction, anything else aborts: " confirm
        if [ "$confirm" != "yes" ]; then
            log_info "Aborted — start canceled, no data deleted."
            exit 0
        fi
    fi

    if "$CONTAINER_RUNTIME" ps -a --format "{{.Names}}" 2>/dev/null | grep -qx "$DB_CONTAINER"; then
        log_info "Removing existing ${DB_CONTAINER} container so its volume can be deleted..."
        "$CONTAINER_RUNTIME" rm -f "$DB_CONTAINER" 2>/dev/null || true
    fi
    "$CONTAINER_RUNTIME" volume rm -f "$DB_VOLUME" 2>/dev/null || true
    log_success "DB volume removed. Next start will initialize a fresh database."
}

preflight_port_check() {
    if ! command -v "$CONTAINER_RUNTIME" &> /dev/null; then
        return 0
    fi
    local binders
    binders=$("$CONTAINER_RUNTIME" ps --filter "publish=${DB_PORT}" --format "{{.Names}}" 2>/dev/null \
              | grep -v "^${DB_CONTAINER}$" || true)
    if [ -z "$binders" ]; then
        return 0
    fi
    log_error "Port 127.0.0.1:${DB_PORT} is already bound by another container:"
    while IFS= read -r c; do
        [ -z "$c" ] && continue
        local image volumes
        image=$("$CONTAINER_RUNTIME" inspect --format '{{.Config.Image}}' "$c" 2>/dev/null || echo "?")
        volumes=$("$CONTAINER_RUNTIME" inspect --format '{{range .Mounts}}{{.Name}} {{end}}' "$c" 2>/dev/null)
        echo -e "  - ${RED}${c}${NC} (image ${image})"
        [ -n "$volumes" ] && echo -e "    Data lives on volume(s): ${volumes}"
    done <<<"$binders"
    log_error ""
    log_error "Starting now would either fail to bind ${DB_PORT}, or worse, point the binary"
    log_error "at the wrong database — so your hosts + credentials would appear to vanish."
    log_error ""
    log_error "Resolve before re-running:"
    log_error "  1. If the existing container holds the data you want, override DB_CONTAINER"
    log_error "     and DB_VOLUME via OPENWATCH_DB_CONTAINER / OPENWATCH_DB_VOLUME, OR set"
    log_error "     OPENWATCH_DB_CONTAINER=$(echo "$binders" | head -1) and re-run."
    log_error "  2. Stop the existing container, then re-run:"
    log_error "       ${CONTAINER_RUNTIME} stop $(echo "$binders" | tr '\n' ' ')"
    exit 1
}

# ---------------------------------------------------------------------------
# Prerequisites + binary + runtime secrets
# ---------------------------------------------------------------------------

detect_container_runtime() {
    if [ -n "$CONTAINER_RUNTIME" ]; then
        if ! command -v "$CONTAINER_RUNTIME" &> /dev/null; then
            log_error "Requested container runtime '${CONTAINER_RUNTIME}' is not installed."
            exit 1
        fi
        return 0
    fi
    if command -v docker &> /dev/null; then
        CONTAINER_RUNTIME=docker
    elif command -v podman &> /dev/null; then
        CONTAINER_RUNTIME=podman
    else
        log_error "Need docker or podman to run the PostgreSQL container."
        log_error "Install one or set OPENWATCH_CONTAINER_RUNTIME explicitly."
        exit 1
    fi
    log_info "Container runtime: ${CONTAINER_RUNTIME}"
}

ensure_binary() {
    if [ "$DO_BUILD" = true ] || [ ! -x "$BINARY" ]; then
        if ! command -v go &> /dev/null; then
            log_error "go toolchain not found; cannot build the binary."
            log_error "Install Go (>= 1.22) or copy a prebuilt openwatch to ${BINARY}."
            exit 1
        fi
        log_info "Building openwatch binary (make build)..."
        (cd "$APP_DIR" && make build)
        log_success "Built ${BINARY}"
    fi
    log_info "Binary: ${BINARY}"
}

ensure_runtime_secrets() {
    mkdir -p "${RUNTIME_DIR}/tls" "${RUNTIME_DIR}/logs"

    if [ ! -f "${RUNTIME_DIR}/tls/cert.pem" ] || [ ! -f "${RUNTIME_DIR}/tls/key.pem" ]; then
        log_info "Generating self-signed TLS cert at ${RUNTIME_DIR}/tls/ (demo only)"
        bash "${APP_DIR}/packaging/common/gen-demo-cert.sh" "${RUNTIME_DIR}/tls"
    fi

    if [ ! -f "${RUNTIME_DIR}/jwt_private.pem" ]; then
        log_info "Generating JWT signing key at ${RUNTIME_DIR}/jwt_private.pem (demo only)"
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
            -out "${RUNTIME_DIR}/jwt_private.pem" 2>/dev/null
        chmod 0600 "${RUNTIME_DIR}/jwt_private.pem"
    fi

    if [ ! -f "${RUNTIME_DIR}/credential.key" ]; then
        log_info "Generating credential DEK at ${RUNTIME_DIR}/credential.key (demo only)"
        head -c 32 /dev/urandom > "${RUNTIME_DIR}/credential.key"
        chmod 0600 "${RUNTIME_DIR}/credential.key"
    fi

    if [[ "$RUNTIME_DIR" == /tmp/* ]]; then
        log_warning "Runtime secrets live in ${RUNTIME_DIR} (likely /tmp) — they will not"
        log_warning "survive a reboot. Set OPENWATCH_RUNTIME_DIR to a persistent path"
        log_warning "(e.g. ~/.openwatch/runtime) for anything beyond a smoke test."
    fi
}

# ---------------------------------------------------------------------------
# DB container lifecycle
# ---------------------------------------------------------------------------

ensure_db_container() {
    if "$CONTAINER_RUNTIME" ps --format "{{.Names}}" 2>/dev/null | grep -qx "$DB_CONTAINER"; then
        log_info "DB container ${DB_CONTAINER} is already running."
        return 0
    fi
    if "$CONTAINER_RUNTIME" ps -a --format "{{.Names}}" 2>/dev/null | grep -qx "$DB_CONTAINER"; then
        log_info "Starting existing DB container ${DB_CONTAINER}..."
        "$CONTAINER_RUNTIME" start "$DB_CONTAINER" >/dev/null
        return 0
    fi
    log_info "Creating DB container ${DB_CONTAINER} (image ${DB_IMAGE}, volume ${DB_VOLUME})..."
    "$CONTAINER_RUNTIME" run -d \
        --name "$DB_CONTAINER" \
        --restart unless-stopped \
        -e POSTGRES_USER="$DB_USER" \
        -e POSTGRES_PASSWORD="$DB_PASSWORD" \
        -e POSTGRES_DB="$DB_NAME" \
        -v "${DB_VOLUME}:/var/lib/postgresql/data" \
        -p "127.0.0.1:${DB_PORT}:5432" \
        "$DB_IMAGE" >/dev/null
    log_success "Started ${DB_CONTAINER}"
}

wait_for_db() {
    log_info "Waiting for ${DB_CONTAINER} to accept connections..."
    local i
    for i in $(seq 1 30); do
        if "$CONTAINER_RUNTIME" exec "$DB_CONTAINER" pg_isready -U "$DB_USER" -d "$DB_NAME" -q 2>/dev/null; then
            log_success "PostgreSQL is ready."
            return 0
        fi
        sleep 1
    done
    log_error "PostgreSQL did not become ready within 30s. Inspect:"
    log_error "  ${CONTAINER_RUNTIME} logs ${DB_CONTAINER}"
    exit 1
}

# ---------------------------------------------------------------------------
# Binary lifecycle (serve + worker)
# ---------------------------------------------------------------------------

dsn() {
    echo "postgres://${DB_USER}:${DB_PASSWORD}@127.0.0.1:${DB_PORT}/${DB_NAME}?sslmode=disable"
}

export_runtime_env() {
    export OPENWATCH_DATABASE_DSN="$(dsn)"
    export OPENWATCH_SERVER_TLS_CERT="${RUNTIME_DIR}/tls/cert.pem"
    export OPENWATCH_SERVER_TLS_KEY="${RUNTIME_DIR}/tls/key.pem"
    export OPENWATCH_SERVER_LISTEN="$LISTEN"
    export OPENWATCH_IDENTITY_JWT_PRIVATE_KEY="${RUNTIME_DIR}/jwt_private.pem"
    export OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE="${RUNTIME_DIR}/credential.key"
}

run_migrations() {
    log_info "Applying migrations..."
    if ! "$BINARY" migrate; then
        log_error "migrate failed; refusing to start serve/worker against an out-of-date schema."
        exit 1
    fi
}

already_running() {
    # $1 = subcommand name (serve|worker)
    pgrep -f "dist/openwatch ${1}$" >/dev/null 2>&1
}

start_serve() {
    if already_running serve; then
        log_info "openwatch serve is already running; skipping."
        return 0
    fi
    log_info "Starting openwatch serve in background (logs: ${RUNTIME_DIR}/logs/serve.log)..."
    nohup "$BINARY" serve > "${RUNTIME_DIR}/logs/serve.log" 2>&1 &
    disown
}

start_worker() {
    if [ "$NO_WORKER" = true ]; then
        log_info "--no-worker set; skipping worker."
        return 0
    fi
    if already_running worker; then
        log_info "openwatch worker is already running; skipping."
        return 0
    fi
    log_info "Starting openwatch worker in background (logs: ${RUNTIME_DIR}/logs/worker.log)..."
    nohup "$BINARY" worker > "${RUNTIME_DIR}/logs/worker.log" 2>&1 &
    disown
}

start_frontend() {
    if [ "$NO_FRONTEND" = true ]; then
        log_info "--no-frontend set; skipping Vite."
        return 0
    fi
    local fe_dir="${APP_DIR}/frontend"
    if [ ! -d "$fe_dir" ]; then
        log_warning "Frontend directory not found at ${fe_dir}; skipping."
        return 0
    fi
    if pgrep -f "vite --port" >/dev/null 2>&1; then
        log_info "Vite is already running; skipping."
        return 0
    fi
    if [ ! -d "${fe_dir}/node_modules" ]; then
        log_info "Installing frontend dependencies (npm install)..."
        (cd "$fe_dir" && npm install) > "${RUNTIME_DIR}/logs/npm-install.log" 2>&1
    fi
    log_info "Starting Vite dev server (logs: ${RUNTIME_DIR}/logs/vite.log)..."
    nohup bash -c "cd ${fe_dir} && ./node_modules/.bin/vite --port 5173" \
        > "${RUNTIME_DIR}/logs/vite.log" 2>&1 &
    disown
}

print_urls() {
    log_info ""
    log_info "Access points:"
    log_info "  Frontend dev:  http://127.0.0.1:5173"
    log_info "  HTTPS API:     https://${LISTEN}  (self-signed cert)"
    log_info "  Health:        curl -sk https://${LISTEN}/api/v1/health"
    log_info ""
    log_info "Logs: tail -F ${RUNTIME_DIR}/logs/*.log"
    log_info "Stop: ./stop-openwatch.sh"
}

# ---------------------------------------------------------------------------
# Help + arg parsing
# ---------------------------------------------------------------------------

print_help() {
    cat <<EOF
OpenWatch (Go) Startup Script

Usage: ./start-openwatch.sh [OPTIONS]

Options:
  --build, -b          Run 'make build' in app/ before starting.
  --reset-data         Drop the DB volume (${DB_VOLUME}) BEFORE starting.
                       Requires --yes / OPENWATCH_CONFIRM_DESTROY=yes /
                       interactive 'yes' on stdin.
  --no-frontend        Skip the Vite dev server.
  --no-worker          Skip the openwatch worker (rare; only the API runs).
  --yes, -y            Skip confirmation prompts.
  --help, -h           Show this help.

Data persistence:
  Hosts, credentials, scan results, and audit log live in named docker
  volume ${DB_VOLUME}. The volume survives:
    - this script's restart
    - 'docker stop ${DB_CONTAINER}'
    - host reboot (the container restarts because we set
      --restart unless-stopped)
  The volume is wiped only by:
    - ./start-openwatch.sh --reset-data
    - ./stop-openwatch.sh --clean-data
    - manual 'docker volume rm ${DB_VOLUME}'

Environment overrides (all optional):
  OPENWATCH_DB_CONTAINER     name of the postgres container (default ${DB_CONTAINER})
  OPENWATCH_DB_VOLUME        named volume holding the data  (default ${DB_VOLUME})
  OPENWATCH_DB_IMAGE         postgres image                 (default ${DB_IMAGE})
  OPENWATCH_DB_USER          postgres user                  (default ${DB_USER})
  OPENWATCH_DB_PASSWORD      postgres password
  OPENWATCH_DB_NAME          postgres database              (default ${DB_NAME})
  OPENWATCH_DB_PORT          host port for postgres         (default ${DB_PORT})
  OPENWATCH_RUNTIME_DIR      where TLS cert + JWT + DEK live (default ${RUNTIME_DIR})
  OPENWATCH_LISTEN           HTTPS listen address           (default ${LISTEN})
  OPENWATCH_CONTAINER_RUNTIME  docker or podman             (auto-detect)
  OPENWATCH_CONFIRM_DESTROY=yes  Companion to --yes for --reset-data.

Examples:
  ./start-openwatch.sh                    # Resume against existing data
  ./start-openwatch.sh --build            # Rebuild the binary then start
  ./start-openwatch.sh --reset-data --yes # Fresh DB, scripted
  ./start-openwatch.sh --no-frontend      # API only (no Vite)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --build|-b)    DO_BUILD=true; shift ;;
        --reset-data)  RESET_DATA=true; shift ;;
        --no-frontend) NO_FRONTEND=true; shift ;;
        --no-worker)   NO_WORKER=true; shift ;;
        --yes|-y)      ASSUME_YES=true; shift ;;
        --help|-h)     print_help; exit 0 ;;
        *)
            log_error "Unknown option: $1"
            log_error "Run ./start-openwatch.sh --help for usage."
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

main() {
    log_info "OpenWatch (Go) Startup Script"
    log_info "======================================="

    detect_container_runtime
    ensure_binary
    ensure_runtime_secrets

    if [ "$RESET_DATA" = true ]; then
        reset_data_volumes
    else
        preflight_data_check
    fi

    preflight_port_check
    ensure_db_container
    wait_for_db

    export_runtime_env
    run_migrations
    start_serve
    start_worker
    start_frontend

    print_urls
    log_success "OpenWatch startup complete!"
}

main
