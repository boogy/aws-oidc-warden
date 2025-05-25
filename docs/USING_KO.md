# Building and Deploying with ko

This project can be built and deployed using [ko](https://ko.build), a simple, fast container image builder for Go applications.

## Prerequisites

- [ko](https://ko.build/install/) installed on your system (or use `make verify-ko` to auto-install)
- Docker installed on your system
- AWS CLI configured with appropriate permissions (for Lambda deployment)
- GitHub Container Registry or Docker Hub access (for publishing images)

## Configuration

The ko configuration is stored in `.ko.yaml` in the root of the project. This configuration:

- Sets up the build with appropriate flags for AWS Lambda
- Uses the AWS Lambda base image
- Configures multi-architecture support (arm64/amd64)
- Sets appropriate container labels

## Available Make Commands

The project includes several make targets to simplify working with ko:

```sh
# Verify ko installation and install if needed
make verify-ko

# Build a container image locally with ko
make ko-build

# Publish container image to GitHub Container Registry
make ko-publish-ghcr

# Publish container image to Docker Hub
make ko-publish-dockerhub

# Publish container image to both registries
make ko-publish-all
```

## Environment Variables

You can customize the behavior by setting the following environment variables:

- `GITHUB_USER`: GitHub username (default: detected from git config)
- `KO_DOCKER_REPO_GHCR`: GitHub Container Registry repository (default: `ghcr.io/$(GITHUB_USER)/$(APP_NAME)`)
- `KO_DOCKER_REPO_DOCKERHUB`: Docker Hub repository (default: `$(GITHUB_USER)/$(APP_NAME)`)
- `VERSION`: Version tag for the container image (default: git describe --tags)
- `GOOS`: Go OS target (default: linux)
- `GOARCH`: Go architecture target (default: arm64)

## Examples

### Build a local container image

```sh
make ko-build
```

### Publish to GitHub Container Registry

```sh
# Push to your GitHub Container Registry (using git config user.name)
make ko-publish-ghcr

# Push with custom GitHub username
GITHUB_USER=myusername make ko-publish-ghcr
```

### Publish to Docker Hub

```sh
# Push to your Docker Hub (using git config user.name)
make ko-publish-dockerhub

# Push with custom Docker Hub username
GITHUB_USER=myusername make ko-publish-dockerhub
```

### Publish to both registries

```sh
# Push to both GitHub Container Registry and Docker Hub
make ko-publish-all
```

### Custom configuration

```sh
# Build with custom parameters
GITHUB_USER=myusername \
VERSION=v1.0.0 \
GOARCH=amd64 \
make ko-build
```

## Advantages of using ko

1. **Simplicity**: ko automatically builds your Go application and creates an optimized container image
2. **Speed**: Much faster than traditional Docker builds
3. **Multi-arch support**: Easy building for multiple architectures
4. **OCI compliance**: Creates standards-compliant container images
5. **Integration**: Works well with existing Docker and Kubernetes workflows
