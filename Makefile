APP_NAME := aws-oidc-warden
BINARY := bootstrap
BUILD_DIR := build
VERSION=$(shell git describe --tags 2>/dev/null || echo "v0.0.0")
BUILD_DATE := $(shell date +%Y-%m-%dT%H:%M:%S%z)
BUILD_COMMIT := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")

# Go build options
GOOS ?= linux
GOARCH ?= arm64
GO_BUILD_FLAGS := -trimpath -ldflags="-s -w \
	-X main.buildVersion=$(VERSION) \
	-X main.buildCommit=$(BUILD_COMMIT) \
	-X main.buildDate=$(BUILD_DATE)"

# Ko configuration
GITHUB_USER ?= $(shell git config user.name)
KO_DOCKER_REPO_GHCR ?= ghcr.io/$(GITHUB_USER)/$(APP_NAME)
KO_DOCKER_REPO_DOCKERHUB ?= $(GITHUB_USER)/$(APP_NAME)

# -----------------------------------------------------------------------------
# Development targets
# -----------------------------------------------------------------------------

.PHONY: all
all: build

.PHONY: build
build:
	@echo "Building Go binary for AWS Lambda..."
	@mkdir -p $(BUILD_DIR)
	@go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY) main.go

.PHONY: build-local
build-local:
	@echo "Building Go binary for local development..."
	@mkdir -p $(BUILD_DIR)
	@go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(APP_NAME)-local ./cmd/local

.PHONY: run
run: build-local
	@echo "Running local development server..."
	@$(BUILD_DIR)/$(APP_NAME)-local --port=8080 --log-level=debug --config=./example-config.yaml

.PHONY: clean
clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR)

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
	@echo "Building container with ko locally..."
	@VERSION=$(VERSION) KO_DOCKER_REPO=ko.local ko build . --tags=$(VERSION),latest

.PHONY: ko-publish-ghcr
ko-publish-ghcr: verify-ko verify-docker-auth
	@echo "Publishing container with ko to GitHub Container Registry..."
	@VERSION=$(VERSION) KO_DOCKER_REPO=$(KO_DOCKER_REPO_GHCR) ko publish . --bare --tags=$(VERSION),latest

.PHONY: ko-publish-dockerhub
ko-publish-dockerhub: verify-ko
	@echo "Publishing container with ko to Docker Hub..."
	@VERSION=$(VERSION) KO_DOCKER_REPO=$(KO_DOCKER_REPO_DOCKERHUB) ko publish . --tags=$(VERSION),latest

.PHONY: ko-publish-all
ko-publish-all: ko-publish-ghcr ko-publish-dockerhub
	@echo "Container published to both GitHub Container Registry and Docker Hub"

# Simple publish with timeout handling
.PHONY: ko-publish-simple
ko-publish-simple: verify-ko verify-docker-auth
	@echo "Publishing container with ko to GitHub Container Registry (simple)..."
	@KO_DOCKER_REPO=$(KO_DOCKER_REPO_GHCR) ko publish --sbom=none --bare . || { \
		echo "Build failed. Retrying..."; \
		KO_DOCKER_REPO=$(KO_DOCKER_REPO_GHCR) ko publish --sbom=none --bare .; \
	}

# Alternative publish method with classic mode
.PHONY: ko-publish-classic
ko-publish-classic: verify-ko verify-docker-auth
	@echo "Publishing container with ko using classic mode..."
	@KO_DOCKER_REPO=$(KO_DOCKER_REPO_GHCR) ko publish --sbom=none --image-refs=/tmp/ko-refs.txt .

.PHONY: setup-ghcr-auth
setup-ghcr-auth:
	@echo "Setting up GitHub Container Registry authentication..."
	@echo ""
	@echo "You need a GitHub Personal Access Token with these scopes:"
	@echo "  ✓ repo"
	@echo "  ✓ write:packages"
	@echo "  ✓ read:packages"
	@echo ""
	@echo "Create one at: https://github.com/settings/tokens/new"
	@echo ""
	@echo "Then run these commands:"
	@echo "  export GITHUB_TOKEN=your_token_here"
	@echo "  echo \$$GITHUB_TOKEN | docker login ghcr.io -u $(GITHUB_USER) --password-stdin"
	@echo ""
	@echo "Or use GitHub CLI to create a token:"
	@echo "  gh auth refresh --scopes write:packages,read:packages"

# -----------------------------------------------------------------------------
# Utility targets
# -----------------------------------------------------------------------------

.PHONY: verify-ko
verify-ko:
	@echo "Verifying ko installation..."
	@command -v ko >/dev/null 2>&1 || { \
		echo "ko not installed. Installing..."; \
		go install github.com/google/ko@latest; \
	}

.PHONY: verify-docker-auth
verify-docker-auth:
	@echo "Verifying Docker daemon and authentication..."
	@docker info >/dev/null 2>&1 || { \
		echo "Docker daemon not running. Please start Docker and try again."; \
		exit 1; \
	}
	@docker system info | grep -q "Registry:" || { \
		echo "Authenticating with GitHub Container Registry..."; \
		gh auth token | docker login ghcr.io -u $(GITHUB_USER) --password-stdin; \
	}

.PHONY: help
help:
	@echo "AWS OIDC Warden - Makefile Commands:"
	@echo ""
	@echo "Development:"
	@echo "  make build                Build the local development binary"
	@echo "  make build-local          Build the local development binary"
	@echo "  make run                  Run the local development server"
	@echo "  make clean                Remove build artifacts"
	@echo ""
	@echo "Code quality:"
	@echo "  make fmt                  Format code"
	@echo "  make lint                 Run linter"
	@echo "  make check                Run all code quality checks and tests"
	@echo ""
	@echo "Testing:"
	@echo "  make test                 Run tests"
	@echo "  make test-verbose         Run tests with verbose output"
	@echo "  make test-coverage        Run tests with coverage report"
	@echo ""
	@echo "Container builds:"
	@echo "  make ko-build             Build container image locally using ko"
	@echo "  make ko-publish-ghcr      Build and publish container image to GitHub Container Registry"
	@echo "  make ko-publish-dockerhub Build and publish container image to Docker Hub"
	@echo "  make ko-publish-all       Build and publish container image to both registries"
	@echo ""
	@echo "Utilities:"
	@echo "  make verify-ko            Verify ko installation and install if needed"
	@echo ""
	@echo "Authentication:"
	@echo "  make setup-ghcr-auth      Set up GitHub Container Registry authentication"
	@echo ""
	@echo "Configuration variables:"
	@echo "  GOOS                      Go OS target (default: $(GOOS))"
	@echo "  GOARCH                    Go architecture target (default: $(GOARCH))"
	@echo "  GITHUB_USER               GitHub username (default: $(GITHUB_USER))"
	@echo "  KO_DOCKER_REPO_GHCR       GitHub Container Registry repository (default: $(KO_DOCKER_REPO_GHCR))"
	@echo "  KO_DOCKER_REPO_DOCKERHUB  Docker Hub repository (default: $(KO_DOCKER_REPO_DOCKERHUB))"
