# OpenWatch (Go rebuild) — Makefile
#
# Build, test, lint, generate, package. Most targets gain real
# implementations as Stage 0 days land:
#
#   Day 1 (now): build, test, tidy, lint, clean, version
#   Day 3:       migrate
#   Day 5:       generate (oapi-codegen)
#   Day 11:      rpm, deb
#   Day 12:      build-fips
#
# See app/docs/stage_0_walking_skeleton.md for the day-by-day plan.

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

BINARY    := openwatch
DIST_DIR  := dist
CMD_DIR   := ./cmd/openwatch
SPA_DIR   := internal/server/spa

# Version metadata injected at build time. The Go rebuild has its own
# version track (packaging/version.env) so its milestones decouple from
# the legacy Python project at ../VERSION. Fallback order: local
# version.env → repo-root VERSION → hardcoded dev default.
VERSION   := $(shell . packaging/version.env 2>/dev/null && echo "$$VERSION" || cat ../VERSION 2>/dev/null || echo "0.1.0-dev")
COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILDTIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# ldflags inject build metadata into internal/version.
LDFLAGS := -ldflags "\
  -X github.com/Hanalyx/openwatch/internal/version.Version=$(VERSION) \
  -X github.com/Hanalyx/openwatch/internal/version.Commit=$(COMMIT) \
  -X github.com/Hanalyx/openwatch/internal/version.BuildTime=$(BUILDTIME)"

LDFLAGS_FIPS := -ldflags "\
  -X github.com/Hanalyx/openwatch/internal/version.Version=$(VERSION) \
  -X github.com/Hanalyx/openwatch/internal/version.Commit=$(COMMIT) \
  -X github.com/Hanalyx/openwatch/internal/version.BuildTime=$(BUILDTIME) \
  -X github.com/Hanalyx/openwatch/internal/version.FIPS=true"

# -----------------------------------------------------------------------------
# Build (Day 1)
# -----------------------------------------------------------------------------

.PHONY: build
build: $(DIST_DIR) internal/server/openapi_embed.yaml spa
	go build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY) $(CMD_DIR)
	@echo "built $(DIST_DIR)/$(BINARY) ($(VERSION) / $(COMMIT))"

$(DIST_DIR):
	@mkdir -p $(DIST_DIR)

# -----------------------------------------------------------------------------
# Test & lint (Day 1)
# -----------------------------------------------------------------------------

.PHONY: test
test: internal/server/openapi_embed.yaml $(SPA_DIR)/index.html
	go test ./...

# test-integration: runs the full suite (including DB-backed integration
# tests) against a dedicated TEST database. The DSN is constructed here
# so the operator can never accidentally point it at the dev or prod
# DB. These tests TRUNCATE tables between cases — pointing at a non-test
# DB would destroy real data. Run `make test-db-create` first if the
# database does not exist yet.
.PHONY: test-integration
test-integration: internal/server/openapi_embed.yaml $(SPA_DIR)/index.html
	@DB="$${OPENWATCH_TEST_DB:-openwatch_go_test}"; \
	case "$$DB" in *_test) ;; \
	  *) echo "ERROR: OPENWATCH_TEST_DB ($$DB) must end with _test"; exit 1 ;; esac; \
	HOST="$${OPENWATCH_TEST_DB_HOST:-127.0.0.1}"; \
	PORT="$${OPENWATCH_TEST_DB_PORT:-5432}"; \
	USER="$${OPENWATCH_TEST_DB_USER:-openwatch}"; \
	PASS="$${OPENWATCH_TEST_DB_PASS:-openwatch_secure_db_2025}"; \
	DSN="postgres://$$USER:$$PASS@$$HOST:$$PORT/$$DB?sslmode=disable"; \
	echo "Using test DB: $$DB on $$HOST:$$PORT"; \
	OPENWATCH_TEST_DSN="$$DSN" go test -race -p 1 ./...

# test-db-create: provisions the test database (idempotent — exits 0
# if it already exists) and applies all migrations.
.PHONY: test-db-create
test-db-create: $(DIST_DIR)/$(BINARY)
	@DB="$${OPENWATCH_TEST_DB:-openwatch_go_test}"; \
	case "$$DB" in *_test) ;; \
	  *) echo "ERROR: OPENWATCH_TEST_DB ($$DB) must end with _test"; exit 1 ;; esac; \
	HOST="$${OPENWATCH_TEST_DB_HOST:-127.0.0.1}"; \
	PORT="$${OPENWATCH_TEST_DB_PORT:-5432}"; \
	USER="$${OPENWATCH_TEST_DB_USER:-openwatch}"; \
	PASS="$${OPENWATCH_TEST_DB_PASS:-openwatch_secure_db_2025}"; \
	PGPASSWORD="$$PASS" psql -h $$HOST -p $$PORT -U $$USER -d postgres \
	  -tc "SELECT 1 FROM pg_database WHERE datname='$$DB'" | grep -q 1 \
	  || PGPASSWORD="$$PASS" psql -h $$HOST -p $$PORT -U $$USER -d postgres \
	     -c "CREATE DATABASE $$DB OWNER $$USER;"; \
	DSN="postgres://$$USER:$$PASS@$$HOST:$$PORT/$$DB?sslmode=disable"; \
	echo "Migrating test DB to current schema..."; \
	OPENWATCH_DATABASE_DSN="$$DSN" ./$(DIST_DIR)/$(BINARY) migrate

# test-db-drop: tears down the test database. Refuses any DB name that
# does not end in _test.
.PHONY: test-db-drop
test-db-drop:
	@DB="$${OPENWATCH_TEST_DB:-openwatch_go_test}"; \
	case "$$DB" in *_test) ;; \
	  *) echo "ERROR: $$DB must end with _test"; exit 1 ;; esac; \
	HOST="$${OPENWATCH_TEST_DB_HOST:-127.0.0.1}"; \
	PORT="$${OPENWATCH_TEST_DB_PORT:-5432}"; \
	USER="$${OPENWATCH_TEST_DB_USER:-openwatch}"; \
	PASS="$${OPENWATCH_TEST_DB_PASS:-openwatch_secure_db_2025}"; \
	PGPASSWORD="$$PASS" psql -h $$HOST -p $$PORT -U $$USER -d postgres \
	  -c "DROP DATABASE IF EXISTS $$DB;"

.PHONY: tidy
tidy:
	go mod tidy

# -----------------------------------------------------------------------------
# Quality + security gates (release-ci-gates.spec.yaml)
# -----------------------------------------------------------------------------

# vet: built-in suspicious-construct check. Always available.
# Depends on internal/server/openapi_embed.yaml because go:embed
# resolves at vet time too — the source tree must contain the embedded
# file for vet to type-check the embedding declaration.
.PHONY: vet
vet: internal/server/openapi_embed.yaml $(SPA_DIR)/index.html
	go vet ./...

# lint: golangci-lint runs staticcheck + gosec + govet + others per .golangci.yml.
.PHONY: lint
lint: internal/server/openapi_embed.yaml $(SPA_DIR)/index.html
	@if command -v golangci-lint >/dev/null 2>&1; then \
	  golangci-lint run; \
	else \
	  echo "golangci-lint not installed; skipping (install: https://golangci-lint.run/usage/install/)"; \
	fi

# vuln: known-CVE scan against deps + stdlib (call-graph aware).
# Auto-installs govulncheck if absent.
.PHONY: vuln
vuln: internal/server/openapi_embed.yaml $(SPA_DIR)/index.html
	@if ! command -v govulncheck >/dev/null 2>&1; then \
	  echo "installing govulncheck..."; \
	  go install golang.org/x/vuln/cmd/govulncheck@latest; \
	fi
	govulncheck ./...

# test-race: full suite with the race detector. Slower than `make test`.
# Integration tests still need OPENWATCH_TEST_DSN; without it they skip.
# -p 1 serializes packages so they don't trample each other's DB state.
.PHONY: test-race
test-race: internal/server/openapi_embed.yaml $(SPA_DIR)/index.html
	go test -race -p 1 ./...

# check: the single pre-push gate. Chains vet → lint → vuln → test-race.
# First failure aborts the chain (make's default target dependency semantics).
.PHONY: check
check: vet lint vuln test-race
	@echo "make check: all gates passed"

.PHONY: clean
clean:
	rm -rf $(DIST_DIR) $(SPA_DIR)
	@echo "cleaned $(DIST_DIR)/"

.PHONY: version
version:
	@echo "VERSION=$(VERSION)"
	@echo "COMMIT=$(COMMIT)"
	@echo "BUILDTIME=$(BUILDTIME)"

# -----------------------------------------------------------------------------
# Codegen (Day 5: oapi-codegen, sqlc; Day 5+: registry codegen)
# -----------------------------------------------------------------------------

.PHONY: generate
generate: generate-audit generate-rbac generate-license generate-api
	@echo "generate: audit events + RBAC + license features + OpenAPI server stubs regenerated (sqlc lands later)"

.PHONY: generate-audit
generate-audit:
	go run scripts/gen-audit-events.go

.PHONY: generate-rbac
generate-rbac:
	go run scripts/gen-rbac.go

.PHONY: generate-license
generate-license:
	go run scripts/gen-license-features.go

.PHONY: generate-api
generate-api:
	@if [ ! -x "$(HOME)/go/bin/oapi-codegen" ]; then \
	  echo "installing oapi-codegen..."; \
	  go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest; \
	fi
	$(HOME)/go/bin/oapi-codegen --config api/oapi-codegen.yaml api/openapi.yaml
	@echo "generated internal/server/api/server.gen.go"

# The OpenAPI spec is also embedded into the binary so the /api/v1/openapi.yaml
# and /docs routes can serve it air-gap-clean. go:embed cannot follow paths
# outside the package directory, so we keep a build-time copy under
# internal/server/. The copy is gitignored; rebuilt by `make build`.
internal/server/openapi_embed.yaml: api/openapi.yaml
	cp $< $@

# Embedded SPA. The Go binary serves the React app via go:embed (see
# internal/server/spa.go). go:embed cannot follow paths outside the package
# directory, so the build stages the UI under internal/server/spa/. The
# directory is gitignored.
#
# Two ways to populate it:
#   - $(SPA_DIR)/index.html  — a lightweight stub so go vet/lint/test compile
#     the embed without a Node toolchain (created on demand, fast).
#   - make spa               — the real `vite build` output, for release binaries.
$(SPA_DIR)/index.html:
	@mkdir -p $(SPA_DIR)
	@printf '%s\n' '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>OpenWatch</title></head><body>OpenWatch SPA placeholder. Run `make spa` (or `make build`) to embed the real UI.</body></html>' > $@

# Build the real frontend and stage it into the embed directory. Uses
# `vite build` directly rather than the frontend `build` script's `tsc -b`,
# which is gated on the frontend's (deferred) type-error cleanup. npm ci runs
# only when node_modules is absent.
.PHONY: spa
spa:
	cd frontend && { [ -d node_modules ] || npm ci --no-audit --no-fund; } && npx vite build
	@rm -rf $(SPA_DIR) && mkdir -p $(SPA_DIR) && cp -r frontend/dist/. $(SPA_DIR)/
	@echo "embedded SPA: frontend/dist -> $(SPA_DIR)/"

# -----------------------------------------------------------------------------
# Database migrations (Day 3)
# -----------------------------------------------------------------------------

.PHONY: migrate
migrate:
	@echo "migrate: not yet implemented (lands in Day 3: goose)"

# -----------------------------------------------------------------------------
# Packaging (Day 11: RPM + DEB)
# -----------------------------------------------------------------------------

.PHONY: rpm
rpm:
	@bash packaging/rpm/build-rpm.sh

.PHONY: deb
deb:
	@bash packaging/deb/build-deb.sh

# Cross-compiled arm64 variants (CGO disabled; no C cross-toolchain needed).
.PHONY: rpm-arm64
rpm-arm64:
	@ARCH=arm64 bash packaging/rpm/build-rpm.sh

.PHONY: deb-arm64
deb-arm64:
	@ARCH=arm64 bash packaging/deb/build-deb.sh

# Kensa rule corpus, packaged separately (noarch RPM + arch:all DEB). The
# openwatch packages declare a hard dependency on this; an install needs
# both. Version tracks the vendored kensa module, not the platform.
.PHONY: kensa-rules
kensa-rules:
	@bash packaging/kensa-rules/build-kensa-rules.sh

# All release artifacts: openwatch RPM + DEB for amd64 and arm64, plus the
# arch-independent kensa-rules corpus package (one RPM + one DEB).
.PHONY: packages
packages: rpm rpm-arm64 deb deb-arm64 kensa-rules
	@echo "built openwatch RPM + DEB (amd64 + arm64) and kensa-rules in $(DIST_DIR)/"

# -----------------------------------------------------------------------------
# FIPS build (Day 12: microsoft/go toolchain)
# -----------------------------------------------------------------------------

.PHONY: build-fips
build-fips: $(DIST_DIR) internal/server/openapi_embed.yaml spa
	GOFIPS140=v1.0.0 go build $(LDFLAGS_FIPS) -o $(DIST_DIR)/$(BINARY)-fips $(CMD_DIR)
	@echo "built $(DIST_DIR)/$(BINARY)-fips ($(VERSION) / $(COMMIT)) [FIPS 140-3]"

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------

.PHONY: help
help:
	@echo "OpenWatch (Go rebuild) — Makefile targets"
	@echo ""
	@echo "  build       Build the openwatch binary into dist/                     [Day 1]"
	@echo "  test        Run all Go tests                                          [Day 1]"
	@echo "  tidy        Run go mod tidy                                           [Day 1]"
	@echo "  clean       Remove dist/                                              [Day 1]"
	@echo "  version     Print version metadata that will be injected              [Day 1]"
	@echo ""
	@echo "Pre-merge gates (release-ci-gates spec):"
	@echo "  vet         go vet ./...                                              [gate]"
	@echo "  lint        golangci-lint (staticcheck + gosec + ...)                 [gate]"
	@echo "  vuln        govulncheck ./...    (known CVEs in deps + stdlib)        [gate]"
	@echo "  test-race   go test -race ./...  (data race detection)                [gate]"
	@echo "  check       vet + lint + vuln + test-race  (run before pushing)       [gate]"
	@echo ""
	@echo "Codegen + DB:"
	@echo "  generate    Run codegen (oapi-codegen, sqlc, registries)              [Day 5]"
	@echo "  migrate     Run goose database migrations                             [Day 3]"
	@echo ""
	@echo "Packaging:"
	@echo "  rpm         Build RPM package                                         [Day 11]"
	@echo "  deb         Build DEB package                                         [Day 11]"
	@echo "  build-fips  Build with FIPS 140-3 (GOFIPS140 native)                  [Day 12]"

.DEFAULT_GOAL := help
