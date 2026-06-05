#!/usr/bin/env bash
#
# OpenWatch local-dev bootstrap — durable {start|stop|restart|status}.
#
# Replaces the fragile /tmp/ow-env.txt + /tmp/ow-run/ setup with a durable,
# gitignored .dev/ state directory at the repo root:
#
#   .dev/tls/{cert,key}.pem   self-signed TLS for the dev HTTPS listener
#   .dev/jwt_private.pem      RSA key used to sign JWTs
#   .dev/credential.key       32-byte AES key that encrypts stored SSH creds
#   .dev/env                  OPENWATCH_DATABASE_DSN + OPENWATCH_SERVER_LISTEN
#   .dev/openwatch.{pid,log}  runtime pid + captured log
#
# On first run it migrates any existing secrets from /tmp/ow-run and the DSN
# from /tmp/ow-env.txt — crucially preserving the credential key so SSH
# credentials already encrypted in the dev DB still decrypt — otherwise it
# generates fresh material. After that it no longer depends on /tmp.
#
# Override the DSN / listen address via the environment or by editing .dev/env.
#
# Usage: scripts/openwatch.sh {start|stop|restart|status}

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DEV_DIR="${OPENWATCH_DEV_DIR:-$ROOT/.dev}"
TLS_DIR="$DEV_DIR/tls"
JWT_KEY="$DEV_DIR/jwt_private.pem"
CRED_KEY="$DEV_DIR/credential.key"
ENV_FILE="$DEV_DIR/env"
PID_FILE="$DEV_DIR/openwatch.pid"
LOG_FILE="$DEV_DIR/openwatch.log"
BIN="$ROOT/dist/openwatch"

# Legacy locations migrated from on first run (one-time).
OLD_RUN="/tmp/ow-run"
OLD_ENV="/tmp/ow-env.txt"

log() { printf '[openwatch] %s\n' "$*"; }
die() { printf '[openwatch] ERROR: %s\n' "$*" >&2; exit 1; }

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

is_running() {
  [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null
}

start() {
  if is_running; then
    log "already running (pid $(cat "$PID_FILE"))"
    return 0
  fi
  ensure_env
  ensure_secrets

  # shellcheck disable=SC1090
  set -a; source "$ENV_FILE"; set +a

  log "building dist/openwatch ..."
  go build -o "$BIN" ./cmd/openwatch

  log "starting (listen ${OPENWATCH_SERVER_LISTEN}) ..."
  OPENWATCH_SERVER_TLS_CERT="$TLS_DIR/cert.pem" \
  OPENWATCH_SERVER_TLS_KEY="$TLS_DIR/key.pem" \
  OPENWATCH_IDENTITY_JWT_PRIVATE_KEY="$JWT_KEY" \
  OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE="$CRED_KEY" \
    nohup "$BIN" serve >"$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"

  local url="https://${OPENWATCH_SERVER_LISTEN}/api/v1/health" pid
  pid="$(cat "$PID_FILE")"
  local i
  for i in $(seq 1 30); do
    if ! kill -0 "$pid" 2>/dev/null; then
      log "server exited during startup; last log lines:"
      tail -n 8 "$LOG_FILE" >&2 || true
      rm -f "$PID_FILE"
      die "startup failed — full log at $LOG_FILE"
    fi
    if curl -ksf "$url" >/dev/null 2>&1; then
      log "healthy: $url (pid $pid)"
      return 0
    fi
    sleep 0.5
  done
  die "not healthy within 15s — see $LOG_FILE"
}

stop() {
  if ! is_running; then
    log "not running"
    rm -f "$PID_FILE"
    return 0
  fi
  local pid; pid="$(cat "$PID_FILE")"
  log "stopping pid $pid ..."
  kill "$pid" 2>/dev/null || true
  local i
  for i in $(seq 1 20); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.25
  done
  if kill -0 "$pid" 2>/dev/null; then
    log "force-killing pid $pid"
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$PID_FILE"
  log "stopped"
}

status() {
  if is_running; then
    log "running (pid $(cat "$PID_FILE"), log $LOG_FILE)"
  else
    log "not running"
  fi
}

case "${1:-}" in
  start)   start ;;
  stop)    stop ;;
  restart) stop; start ;;
  status)  status ;;
  *) echo "usage: ${0##*/} {start|stop|restart|status}" >&2; exit 2 ;;
esac
