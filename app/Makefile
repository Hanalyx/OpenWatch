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
build: $(DIST_DIR) internal/server/openapi_embed.yaml
	go build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY) $(CMD_DIR)
	@echo "built $(DIST_DIR)/$(BINARY) ($(VERSION) / $(COMMIT))"

$(DIST_DIR):
	@mkdir -p $(DIST_DIR)

# -----------------------------------------------------------------------------
# Test & lint (Day 1)
# -----------------------------------------------------------------------------

.PHONY: test
test:
	go test ./...

.PHONY: tidy
tidy:
	go mod tidy

# -----------------------------------------------------------------------------
# Quality + security gates (release-ci-gates.spec.yaml)
# -----------------------------------------------------------------------------

# vet: built-in suspicious-construct check. Always available.
.PHONY: vet
vet:
	go vet ./...

# lint: golangci-lint runs staticcheck + gosec + govet + others per .golangci.yml.
.PHONY: lint
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
	  golangci-lint run; \
	else \
	  echo "golangci-lint not installed; skipping (install: https://golangci-lint.run/usage/install/)"; \
	fi

# vuln: known-CVE scan against deps + stdlib (call-graph aware).
# Auto-installs govulncheck if absent.
.PHONY: vuln
vuln:
	@if ! command -v govulncheck >/dev/null 2>&1; then \
	  echo "installing govulncheck..."; \
	  go install golang.org/x/vuln/cmd/govulncheck@latest; \
	fi
	govulncheck ./...

# test-race: full suite with the race detector. Slower than `make test`.
# Integration tests still need OPENWATCH_TEST_DSN; without it they skip.
# -p 1 serializes packages so they don't trample each other's DB state.
.PHONY: test-race
test-race:
	go test -race -p 1 ./...

# check: the single pre-push gate. Chains vet → lint → vuln → test-race.
# First failure aborts the chain (make's default target dependency semantics).
.PHONY: check
check: vet lint vuln test-race
	@echo "make check: all gates passed"

.PHONY: clean
clean:
	rm -rf $(DIST_DIR)
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
generate: generate-audit generate-api
	@echo "generate: audit events + OpenAPI server stubs regenerated (sqlc lands later)"

.PHONY: generate-audit
generate-audit:
	go run scripts/gen-audit-events.go

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

# -----------------------------------------------------------------------------
# FIPS build (Day 12: microsoft/go toolchain)
# -----------------------------------------------------------------------------

.PHONY: build-fips
build-fips: $(DIST_DIR)
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
