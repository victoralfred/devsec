.PHONY: all build test lint security clean coverage check

# Build settings
BINARY_NAME=devsec
BUILD_DIR=bin
COVERAGE_FILE=coverage.out
COVERAGE_THRESHOLD=80

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

# Linker flags for version injection
LDFLAGS = -s -w \
	-X 'github.com/victoralfred/devsec/internal/cli.Version=$(VERSION)' \
	-X 'github.com/victoralfred/devsec/internal/cli.GitCommit=$(GIT_COMMIT)' \
	-X 'github.com/victoralfred/devsec/internal/cli.BuildDate=$(BUILD_DATE)'

all: check build

# Build the binary
build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/devsec

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	@go tool cover -func=$(COVERAGE_FILE) | grep total | awk '{print "Total coverage: " $$3}'
	@go tool cover -func=$(COVERAGE_FILE) | grep total | awk '{gsub(/%/, "", $$3); if ($$3 < $(COVERAGE_THRESHOLD)) { print "Coverage " $$3 "% is below threshold $(COVERAGE_THRESHOLD)%"; exit 1 }}'

# Run linter
lint:
	@echo "Running linter..."
	golangci-lint run ./...

# Run security scanner
security:
	@echo "Running security scan..."
	gosec -quiet ./...

# Run all checks (lint, security, test)
check: lint security test
	@echo "All checks passed!"

# Format code
fmt:
	@echo "Formatting code..."
	gofmt -s -w .
	go mod tidy

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f $(COVERAGE_FILE)

# Install development tools
tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest

# Verify no direct os file I/O (must use gowritter)
verify-safepath:
	@echo "Checking for prohibited os file I/O..."
	@if grep -rn "os\.Open\|os\.Create\|os\.ReadFile\|os\.WriteFile\|os\.Remove\|os\.Mkdir\|ioutil\." --include="*.go" . | grep -v "_test.go" | grep -v "vendor/"; then \
		echo "ERROR: Direct os file I/O detected. Use github.com/victoralfred/gowritter instead."; \
		exit 1; \
	fi
	@echo "No prohibited file I/O found."
