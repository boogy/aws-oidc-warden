APP_NAME := aws-oidc-warden
BUILD_DIR := build
VERSION := $(shell git describe --tags 2>/dev/null || echo "v0.0.0")
BUILD_DATE := $(shell date +%Y-%m-%dT%H:%M:%S%z)
BUILD_COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")

# Go build options
GOOS ?= linux
GOARCH ?= arm64
GO_BUILD_FLAGS := -trimpath -ldflags="-s -w \
	-X github.com/boogy/aws-oidc-warden/pkg/version.Version=$(VERSION) \
	-X github.com/boogy/aws-oidc-warden/pkg/version.Commit=$(BUILD_COMMIT) \
	-X github.com/boogy/aws-oidc-warden/pkg/version.Date=$(BUILD_DATE)"

# Ko configuration
GITHUB_USER ?= $(shell git config user.name)
KO_DOCKER_REPO ?= ghcr.io/$(GITHUB_USER)/$(APP_NAME)

# -----------------------------------------------------------------------------
# Development targets
# -----------------------------------------------------------------------------

.PHONY: all
all: build-local

.PHONY: build
build: build-apigateway

.PHONY: build-local
build-local:
	@echo "Building local development binary..."
	@mkdir -p $(BUILD_DIR)
	@go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(APP_NAME)-local ./cmd/local

.PHONY: build-lambda
build-lambda: build-apigateway build-alb build-lambdaurl

.PHONY: build-apigateway
build-apigateway:
	@echo "Building API Gateway Lambda binary..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GO_BUILD_FLAGS) -tags=lambda.norpc -o $(BUILD_DIR)/bootstrap-apigateway ./cmd/apigateway

.PHONY: build-alb
build-alb:
	@echo "Building ALB Lambda binary..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GO_BUILD_FLAGS) -tags=lambda.norpc -o $(BUILD_DIR)/bootstrap-alb ./cmd/alb

.PHONY: build-lambdaurl
build-lambdaurl:
	@echo "Building Lambda URL binary..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GO_BUILD_FLAGS) -tags=lambda.norpc -o $(BUILD_DIR)/bootstrap-lambdaurl ./cmd/lambdaurl

.PHONY: run
run: build-local
	@echo "Running local development server..."
	@$(BUILD_DIR)/$(APP_NAME)-local --port=8080 --log-level=debug --config=./example-config.yaml

.PHONY: clean
clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR) coverage.out coverage.html

# -----------------------------------------------------------------------------
# Code quality targets
# -----------------------------------------------------------------------------

.PHONY: fmt
fmt:
	@echo "Formatting code..."
	@go fmt ./...

.PHONY: lint
lint:
	@echo "Running linter..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo >&2 "golangci-lint not installed"; exit 1; }
	@golangci-lint run ./...

.PHONY: check
check: fmt lint test
	@echo "All checks passed!"

# -----------------------------------------------------------------------------
# Test targets
# -----------------------------------------------------------------------------

.PHONY: test
test:
	@echo "Running tests..."
	@go test ./...

.PHONY: test-verbose
test-verbose:
	@echo "Running tests with verbose output..."
	@go test -v ./...

.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# -----------------------------------------------------------------------------
# Container build targets
# -----------------------------------------------------------------------------

.PHONY: ko-build
ko-build: verify-ko
	@echo "Building container images with ko locally..."
	@KO_DOCKER_REPO=ko.local ko build ./cmd/apigateway ./cmd/alb ./cmd/lambdaurl --tags=$(VERSION),latest

.PHONY: ko-publish
ko-publish: verify-ko
	@echo "Publishing container images to $(KO_DOCKER_REPO)..."
	@KO_DOCKER_REPO=$(KO_DOCKER_REPO) ko publish ./cmd/apigateway ./cmd/alb ./cmd/lambdaurl --bare --tags=$(VERSION),latest

# -----------------------------------------------------------------------------
# Utility targets
# -----------------------------------------------------------------------------

.PHONY: verify-ko
verify-ko:
	@command -v ko >/dev/null 2>&1 || { \
		echo "ko not installed. Installing..."; \
		go install github.com/google/ko@latest; \
	}

.PHONY: help
help:
	@echo "AWS OIDC Warden - Makefile Commands:"
	@echo ""
	@echo "Development:"
	@echo "  make build-local          Build local development binary"
	@echo "  make build-lambda         Build all Lambda binaries"
	@echo "  make build-apigateway     Build API Gateway Lambda binary"
	@echo "  make build-alb            Build ALB Lambda binary"
	@echo "  make build-lambdaurl      Build Lambda URL binary"
	@echo "  make run                  Run local development server"
	@echo "  make clean                Remove build artifacts"
	@echo ""
	@echo "Code quality:"
	@echo "  make fmt                  Format code"
	@echo "  make lint                 Run linter"
	@echo "  make check                Run all quality checks and tests"
	@echo ""
	@echo "Testing:"
	@echo "  make test                 Run tests"
	@echo "  make test-verbose         Run tests with verbose output"
	@echo "  make test-coverage        Run tests with coverage report"
	@echo ""
	@echo "Container builds:"
	@echo "  make ko-build             Build container images locally"
	@echo "  make ko-publish           Publish container images"
	@echo ""
	@echo "Configuration variables:"
	@echo "  GOOS                      Go OS target (default: $(GOOS))"
	@echo "  GOARCH                    Go architecture target (default: $(GOARCH))"
	@echo "  GITHUB_USER               GitHub username (default: $(GITHUB_USER))"
	@echo "  KO_DOCKER_REPO            Container repository (default: $(KO_DOCKER_REPO))"
