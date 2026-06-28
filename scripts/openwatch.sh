#!/usr/bin/env bash
#
# OpenWatch local-dev bootstrap — durable {start|stop|restart|status} for the
# full dev stack: the Go backend (HTTPS, :8443) and the Vite frontend (:5173).
#
# Durable, gitignored .dev/ state directory at the repo root:
#
#   .dev/tls/{cert,key}.pem   self-signed TLS for the dev HTTPS listener
#   .dev/jwt_private.pem      RSA key used to sign JWTs
#   .dev/credential.key       32-byte AES key that encrypts stored SSH creds
#   .dev/env                  OPENWATCH_DATABASE_DSN + OPENWATCH_SERVER_LISTEN
#   .dev/openwatch.{pid,log}  backend runtime pid + captured log
#   .dev/vite.{pid,log}       frontend (Vite) runtime pid + captured log
#
# On first run it migrates existing secrets from /tmp/ow-run and the DSN from
# /tmp/ow-env.txt — preserving the credential key so SSH credentials already
# encrypted in the dev DB still decrypt — otherwise it generates fresh material.
# If frontend/node_modules is missing it runs `npm ci` before starting Vite.
#
# start brings up backend then frontend (Vite proxies /api -> the backend, so
# backend-first is correct); stop tears them down in reverse.
#
# Override the DSN / listen / frontend port via the environment or .dev/env.
#
# Usage: scripts/openwatch.sh {start|stop|restart|status}

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DEV_DIR="${OPENWATCH_DEV_DIR:-$ROOT/.dev}"

# Backend
TLS_DIR="$DEV_DIR/tls"
JWT_KEY="$DEV_DIR/jwt_private.pem"
CRED_KEY="$DEV_DIR/credential.key"
ENV_FILE="$DEV_DIR/env"
BE_PID="$DEV_DIR/openwatch.pid"
BE_LOG="$DEV_DIR/openwatch.log"
BIN="$ROOT/dist/openwatch"

# Frontend (Vite)
FE_DIR="$ROOT/frontend"
FE_PID="$DEV_DIR/vite.pid"
FE_LOG="$DEV_DIR/vite.log"
FE_PORT="${OPENWATCH_FRONTEND_PORT:-5173}"

# Legacy locations migrated from on first run (one-time).
OLD_RUN="/tmp/ow-run"
OLD_ENV="/tmp/ow-env.txt"

log() { printf '[openwatch] %s\n' "$*"; }
die() { printf '[openwatch] ERROR: %s\n' "$*" >&2; exit 1; }

pid_alive() { local f="$1"; [[ -f "$f" ]] && kill -0 "$(cat "$f" 2>/dev/null)" 2>/dev/null; }

# poll_health URL PIDFILE LOG LABEL INSECURE(1|0)
poll_health() {
  local url="$1" pf="$2" lg="$3" label="$4" insecure="$5" pid i
  local -a copts=(-sf)
  [[ "$insecure" == "1" ]] && copts+=(-k)
  pid="$(cat "$pf")"
  for i in $(seq 1 60); do
    if ! kill -0 "$pid" 2>/dev/null; then
      log "$label exited during startup; last log lines:"
      tail -n 8 "$lg" >&2 || true
      rm -f "$pf"
      die "$label startup failed — full log at $lg"
    fi
    if curl "${copts[@]}" "$url" >/dev/null 2>&1; then
      log "$label healthy: $url (pid $pid)"
      return 0
    fi
    sleep 0.5
  done
  die "$label not healthy within 30s — see $lg"
}

# stop_proc PIDFILE LABEL
stop_proc() {
  local f="$1" label="$2"
  if ! pid_alive "$f"; then
    log "$label not running"
    rm -f "$f"
    return 0
  fi
  local pid i; pid="$(cat "$f")"
  log "stopping $label (pid $pid) ..."
  kill "$pid" 2>/dev/null || true
  for i in $(seq 1 20); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.25
  done
  pkill -P "$pid" 2>/dev/null || true   # reap children (e.g. Vite's esbuild)
  if kill -0 "$pid" 2>/dev/null; then
    log "force-killing $label (pid $pid)"
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$f"
  log "$label stopped"
}

ensure_env() {
  [[ -f "$ENV_FILE" ]] && return 0
  mkdir -p "$DEV_DIR"
  local dsn="" listen=""
  if [[ -f "$OLD_ENV" ]] && grep -q '^OPENWATCH_DATABASE_DSN=' "$OLD_ENV"; then
    log "migrating DB DSN + listen address from $OLD_ENV"
    dsn="$(grep '^OPENWATCH_DATABASE_DSN=' "$OLD_ENV" | cut -d= -f2-)"
    listen="$(grep '^OPENWATCH_SERVER_LISTEN=' "$OLD_ENV" | cut -d= -f2- || true)"
  fi
  : "${dsn:=postgres://openwatch:CHANGE_ME@127.0.0.1:5432/openwatch_go_dev?sslmode=disable}" # pragma: allowlist secret
  : "${listen:=127.0.0.1:8443}"
  {
    echo "# OpenWatch dev environment (gitignored). Edit as needed."
    echo "OPENWATCH_DATABASE_DSN=$dsn"
    echo "OPENWATCH_SERVER_LISTEN=$listen"
  } > "$ENV_FILE"
  log "wrote $ENV_FILE"
  if grep -q CHANGE_ME "$ENV_FILE"; then
    die "no DB DSN to migrate; edit $ENV_FILE, set OPENWATCH_DATABASE_DSN, then re-run"
  fi
}

ensure_secrets() {
  mkdir -p "$TLS_DIR"

  if [[ ! -f "$TLS_DIR/cert.pem" || ! -f "$TLS_DIR/key.pem" ]]; then
    if [[ -f "$OLD_RUN/tls/cert.pem" && -f "$OLD_RUN/tls/key.pem" ]]; then
      log "migrating TLS cert/key from $OLD_RUN/tls"
      cp "$OLD_RUN/tls/cert.pem" "$TLS_DIR/cert.pem"
      cp "$OLD_RUN/tls/key.pem" "$TLS_DIR/key.pem"
    else
      log "generating self-signed TLS cert/key"
      openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" \
        -days 825 -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
    fi
  fi

  if [[ ! -f "$JWT_KEY" ]]; then
    if [[ -f "$OLD_RUN/jwt_private.pem" ]]; then
      log "migrating JWT key from $OLD_RUN"
      cp "$OLD_RUN/jwt_private.pem" "$JWT_KEY"
    else
      log "generating JWT RSA key"
      openssl genrsa -out "$JWT_KEY" 2048 >/dev/null 2>&1
    fi
  fi

  if [[ ! -f "$CRED_KEY" ]]; then
    if [[ -f "$OLD_RUN/credential.key" ]]; then
      log "migrating credential key from $OLD_RUN (preserves stored-credential decryption)"
      cp "$OLD_RUN/credential.key" "$CRED_KEY"
    else
      log "WARNING: generating a NEW 32-byte credential key. SSH credentials already"
      log "         stored in the DB under the previous key will NOT decrypt."
      head -c 32 /dev/urandom > "$CRED_KEY"
    fi
  fi

  chmod 600 "$JWT_KEY" "$CRED_KEY" "$TLS_DIR/key.pem"
}

backend_start() {
  if pid_alive "$BE_PID"; then
    log "backend already running (pid $(cat "$BE_PID"))"
    return 0
  fi
  ensure_env
  ensure_secrets

  # shellcheck disable=SC1090
  set -a; source "$ENV_FILE"; set +a

  log "building dist/openwatch ..."
  # Inject version metadata (same -X flags as the Makefile) so the dev app
  # reports the real version (e.g. on /settings/about and `--version`) instead
  # of the "dev" default. Without this, every dev build reports "dev".
  ow_version="$( . "$ROOT/packaging/version.env" >/dev/null 2>&1; echo "${VERSION:-dev}" )"
  ow_commit="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  ow_built="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # -tags dev compiles the local-dev entitlement bypass (entitlements_dev.go) so
  # paid features can be exercised locally without a license. The bypass is
  # physically absent from release builds (the Makefile does not pass this tag)
  # and still requires OPENWATCH_DEV_MODE=true at runtime (set below).
  go build -tags dev -ldflags "\
    -X github.com/Hanalyx/openwatch/internal/version.Version=${ow_version} \
    -X github.com/Hanalyx/openwatch/internal/version.Commit=${ow_commit} \
    -X github.com/Hanalyx/openwatch/internal/version.BuildTime=${ow_built}" \
    -o "$BIN" ./cmd/openwatch

  # Keep the dev DB in lockstep with the freshly-built binary. goose is
  # idempotent (a no-op when already current), so this is cheap on every start
  # and prevents the drift class where a rebuilt binary expects a newer schema
  # than the dev DB has — which surfaces as a 500 only on code paths that touch
  # the new columns/tables (e.g. login's refresh-token insert). OPENWATCH_*
  # config (incl. the DSN) is already sourced from $ENV_FILE above.
  log "applying database migrations ..."
  "$BIN" migrate || die "migrate failed — refusing to start against an unmigrated DB (see above)"

  log "starting backend (listen ${OPENWATCH_SERVER_LISTEN}) ..."
  OPENWATCH_SERVER_TLS_CERT="$TLS_DIR/cert.pem" \
  OPENWATCH_SERVER_TLS_KEY="$TLS_DIR/key.pem" \
  OPENWATCH_IDENTITY_JWT_PRIVATE_KEY="$JWT_KEY" \
  OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE="$CRED_KEY" \
  OPENWATCH_DEV_MODE="true" \
    nohup "$BIN" serve >"$BE_LOG" 2>&1 &
  echo $! > "$BE_PID"
  poll_health "https://${OPENWATCH_SERVER_LISTEN}/api/v1/health" "$BE_PID" "$BE_LOG" "backend" 1
}

frontend_start() {
  if pid_alive "$FE_PID"; then
    log "frontend already running (pid $(cat "$FE_PID"))"
    return 0
  fi
  if [[ ! -d "$FE_DIR/node_modules" ]]; then
    log "frontend/node_modules missing — running npm ci (one-time) ..."
    ( cd "$FE_DIR" && npm ci --no-audit --no-fund )
  fi
  log "starting frontend (Vite, port ${FE_PORT}) ..."
  ( cd "$FE_DIR" && exec node_modules/.bin/vite --port "$FE_PORT" >"$FE_LOG" 2>&1 ) &
  echo $! > "$FE_PID"
  poll_health "http://127.0.0.1:${FE_PORT}/" "$FE_PID" "$FE_LOG" "frontend" 0
}

status_one() {
  local pf="$1" label="$2" where="$3"
  if pid_alive "$pf"; then
    log "$label running (pid $(cat "$pf"), $where)"
  else
    log "$label not running"
  fi
}

start()   { backend_start; frontend_start; }
stop()    { stop_proc "$FE_PID" "frontend"; stop_proc "$BE_PID" "backend"; }
restart() { stop; start; }
status()  {
  status_one "$BE_PID" "backend"  "https://127.0.0.1:8443 — log $BE_LOG"
  status_one "$FE_PID" "frontend" "http://localhost:${FE_PORT} — log $FE_LOG"
}

case "${1:-}" in
  start)   start ;;
  stop)    stop ;;
  restart) restart ;;
  status)  status ;;
  *) echo "usage: ${0##*/} {start|stop|restart|status}" >&2; exit 2 ;;
esac
