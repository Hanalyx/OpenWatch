#!/usr/bin/env bash
# Local test database, mirroring the CI service container.
#
# WHY THIS EXISTS: the DB-gated suites do not run without OPENWATCH_TEST_DSN, so
# `make ci-local` silently skips them and a change can look clean locally and
# fail in CI. That happened three times in one day on the v0.7 branches: the
# report-schedule suites, the RBAC role-assign tests, and the token tests all
# passed here and failed there. This closes that gap.
#
# Usage:
#   scripts/test-db.sh up        start the container (idempotent)
#   scripts/test-db.sh dsn       print the DSN, for `export $(...)` or eval
#   scripts/test-db.sh test      run the full DB-backed suite
#   scripts/test-db.sh down      stop and remove the container
#
#   eval "$(scripts/test-db.sh dsn)" && go test ./internal/...
set -euo pipefail

NAME=openwatch-pg-test
# 5432 and 5433 are taken on the dev workstation by the dev DB and by
# hanalyx-postgres. Pick something clear of both; override with TEST_DB_PORT.
PORT="${TEST_DB_PORT:-5455}"
# Image and credentials MUST match .github/workflows/go-ci.yml, or "passes
# locally" stops meaning "passes in CI", which is the whole point.
IMAGE=postgres:16-alpine
USER=openwatch
PASS=openwatch_ci
# The name must end in _test: internal/db refuses a non-_test database unless
# OPENWATCH_TEST_DSN_ALLOW_NONTEST is set, which we never want here.
DB=openwatch_go_test

dsn() { echo "postgres://${USER}:${PASS}@127.0.0.1:${PORT}/${DB}?sslmode=disable"; }

up() {
  if [ -n "$(docker ps -q -f "name=^${NAME}$")" ]; then
    echo "${NAME} already running on ${PORT}"
    return 0
  fi
  docker rm -f "${NAME}" >/dev/null 2>&1 || true
  # max_connections: the default 100 is not enough. The suite runs packages in
  # parallel and internal/db/dbtest clones a template database per package, so
  # a default container deadlocks and the first DB test times out at 120s while
  # the rest cascade. That looks exactly like a real failure and is not one.
  #
  # fsync/synchronous_commit/full_page_writes off: this database is disposable.
  # Durability buys nothing and costs most of the runtime.
  docker run -d --name "${NAME}" \
    -e POSTGRES_USER="${USER}" -e POSTGRES_PASSWORD="${PASS}" -e POSTGRES_DB="${DB}" \
    -p "127.0.0.1:${PORT}:5432" \
    --health-cmd "pg_isready -U ${USER}" --health-interval 3s \
    --shm-size=256m \
    "${IMAGE}" \
    -c max_connections=400 \
    -c shared_buffers=256MB \
    -c fsync=off \
    -c synchronous_commit=off \
    -c full_page_writes=off >/dev/null

  printf 'waiting for %s' "${NAME}"
  for _ in $(seq 1 40); do
    if [ "$(docker inspect "${NAME}" --format '{{.State.Health.Status}}' 2>/dev/null)" = "healthy" ]; then
      echo " ready on ${PORT}"
      return 0
    fi
    printf .
    sleep 2
  done
  echo
  echo "ERROR: ${NAME} did not become healthy" >&2
  docker logs --tail 20 "${NAME}" >&2 || true
  return 1
}

case "${1:-up}" in
  up)   up ;;
  down) docker rm -f "${NAME}" >/dev/null 2>&1 && echo "removed ${NAME}" || echo "${NAME} not running" ;;
  dsn)  echo "export OPENWATCH_TEST_DSN='$(dsn)'"; echo "export OPENWATCH_TEST_DSN_ALLOW_NONTEST=no" ;;
  test) up
        export OPENWATCH_TEST_DSN="$(dsn)"
        export OPENWATCH_TEST_DSN_ALLOW_NONTEST=no
        echo "running the full DB-backed suite against ${DB} on ${PORT}"
        go test ./internal/... ;;
  *)    echo "usage: $0 {up|down|dsn|test}" >&2; exit 2 ;;
esac
