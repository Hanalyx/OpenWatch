# OpenWatch Admin (owadm) Build Configuration
# Unified container management utility

# Build variables
APP_NAME := owadm
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Go build variables
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)
GO_VERSION := $(shell go version | cut -d ' ' -f 3)

# Build flags
LDFLAGS := -ldflags "-s -w \
	-X github.com/hanalyx/openwatch/internal/owadm/cmd.Version=$(VERSION) \
	-X github.com/hanalyx/openwatch/internal/owadm/cmd.Commit=$(COMMIT) \
	-X github.com/hanalyx/openwatch/internal/owadm/cmd.BuildTime=$(BUILD_TIME)"

# Directories
BIN_DIR := bin
DIST_DIR := dist
MAIN_FILE := cmd/owadm/main.go

# Default target
.DEFAULT_GOAL := build

# Build for current platform
.PHONY: build
build: clean
	@echo "🔨 Building $(APP_NAME) for $(GOOS)/$(GOARCH)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME) $(MAIN_FILE)
	@echo "✅ Built $(BIN_DIR)/$(APP_NAME)"

# Build for all platforms
.PHONY: build-all
build-all: clean
	@echo "🔨 Building $(APP_NAME) for all platforms..."
	@mkdir -p $(DIST_DIR)
	
	# Linux AMD64
	@echo "  📦 Building for linux/amd64..."
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-linux-amd64 $(MAIN_FILE)
	
	# Linux ARM64
	@echo "  📦 Building for linux/arm64..."
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-linux-arm64 $(MAIN_FILE)
	
	# macOS AMD64 (Intel)
	@echo "  📦 Building for darwin/amd64..."
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-darwin-amd64 $(MAIN_FILE)
	
	# macOS ARM64 (M1/M2)
	@echo "  📦 Building for darwin/arm64..."
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-darwin-arm64 $(MAIN_FILE)
	
	# Windows AMD64
	@echo "  📦 Building for windows/amd64..."
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-windows-amd64.exe $(MAIN_FILE)
	
	@echo "✅ Built all platform binaries in $(DIST_DIR)/"
	@ls -la $(DIST_DIR)/

# Install locally
.PHONY: install
install: build
	@echo "📦 Installing $(APP_NAME) to /usr/local/bin..."
	sudo cp $(BIN_DIR)/$(APP_NAME) /usr/local/bin/$(APP_NAME)
	sudo chmod +x /usr/local/bin/$(APP_NAME)
	@echo "✅ $(APP_NAME) installed successfully"
	@echo "🚀 Try: owadm --help"

# Install locally without sudo (to ~/bin)
.PHONY: install-user
install-user: build
	@echo "📦 Installing $(APP_NAME) to ~/bin..."
	@mkdir -p ~/bin
	cp $(BIN_DIR)/$(APP_NAME) ~/bin/$(APP_NAME)
	chmod +x ~/bin/$(APP_NAME)
	@echo "✅ $(APP_NAME) installed to ~/bin/"
	@echo "💡 Make sure ~/bin is in your PATH"
	@echo "🚀 Try: owadm --help"

# Development build with race detection
.PHONY: build-dev
build-dev: clean
	@echo "🔨 Building $(APP_NAME) for development..."
	@mkdir -p $(BIN_DIR)
	go build -race $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-dev $(MAIN_FILE)
	@echo "✅ Built $(BIN_DIR)/$(APP_NAME)-dev"

# Run tests
.PHONY: test
test:
	@echo "🧪 Running tests..."
	go test -v ./...
	@echo "✅ Tests completed"

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "🧪 Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report generated: coverage.html"

# Format code
.PHONY: fmt
fmt:
	@echo "🎨 Formatting code..."
	gofmt -s -w .
	go mod tidy
	@echo "✅ Code formatted"

# Lint code
.PHONY: lint
lint:
	@echo "🔍 Linting code..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		@echo "⚠️  golangci-lint not installed, using go vet..."; \
		go vet ./...; \
	fi
	@echo "✅ Linting completed"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf $(BIN_DIR) $(DIST_DIR)
	rm -f coverage.out coverage.html
	@echo "✅ Clean completed"

# Show build info
.PHONY: info
info:
	@echo "📋 Build Information:"
	@echo "  App Name:     $(APP_NAME)"
	@echo "  Version:      $(VERSION)"
	@echo "  Commit:       $(COMMIT)"
	@echo "  Go Version:   $(GO_VERSION)"
	@echo "  Target OS:    $(GOOS)"
	@echo "  Target Arch:  $(GOARCH)"
	@echo "  Build Time:   $(BUILD_TIME)"

# Development workflow
.PHONY: dev
dev: fmt lint test build
	@echo "✅ Development build completed"

# Release workflow  
.PHONY: release
release: fmt lint test build-all
	@echo "🚀 Release build completed"
	@echo "📦 Binaries available in $(DIST_DIR)/"

# Package management
.PHONY: package-rpm
package-rpm: build
	@echo "📦 Building RPM package..."
	cd packaging/rpm && ./build-rpm.sh
	@echo "✅ RPM package build completed"

.PHONY: package-deb
package-deb: build
	@echo "📦 Building DEB package..."
	cd packaging/deb && ./build-deb.sh
	@echo "✅ DEB package build completed"

.PHONY: package-all
package-all: package-rpm package-deb
	@echo "📦 All packages built successfully"

# Quick start for new users
.PHONY: quick-start
quick-start: build install
	@echo ""
	@echo "🎉 owadm is ready!"
	@echo ""
	@echo "Quick start commands:"
	@echo "  owadm start           # Start OpenWatch"
	@echo "  owadm status         # Check status"
	@echo "  owadm stop           # Stop services"
	@echo "  owadm --help         # Show help"
	@echo ""

# Help
.PHONY: help
help:
	@echo "OpenWatch Admin (owadm) Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  build           Build for current platform"
	@echo "  build-all       Build for all platforms"
	@echo "  build-dev       Build with race detection"
	@echo "  install         Install to /usr/local/bin (requires sudo)"
	@echo "  install-user    Install to ~/bin"
	@echo "  test            Run tests"
	@echo "  test-coverage   Run tests with coverage report"
	@echo "  fmt             Format code"
	@echo "  lint            Lint code"
	@echo "  clean           Clean build artifacts"
	@echo "  dev             Run development workflow"
	@echo "  release         Run release workflow"
	@echo "  quick-start     Build and install for new users"
	@echo "  info            Show build information"
	@echo "  help            Show this help message"