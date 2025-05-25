# Build and Deployment Guide

This guide covers all the different ways to build and deploy the AWS OIDC Warden, including local development, container images, and AWS Lambda deployment.

## Quick Reference

| Method                | Command                         | Purpose                              |
| --------------------- | ------------------------------- | ------------------------------------ |
| **Local Development** | `make build`                    | Build Lambda binary locally          |
|                       | `make build-local`              | Build local development server       |
|                       | `make run`                      | Run local development server         |
| **Container Images**  | `make ko-build`                 | Build container image locally        |
|                       | `make ko-publish-ghcr`          | Publish to GitHub Container Registry |
|                       | `make ko-publish-dockerhub`     | Publish to Docker Hub                |
|                       | `make ko-publish-all`           | Publish to both registries           |
| **Releases**          | `goreleaser release --clean`    | Create official release              |
|                       | `goreleaser release --snapshot` | Test release locally                 |
| **Code Quality**      | `make check`                    | Run all checks (format, lint, test)  |
|                       | `make test-coverage`            | Generate test coverage report        |

## Development Workflow

### 1. Local Development

```bash
# Clone and setup
git clone https://github.com/boogy/aws-oidc-warden.git
cd aws-oidc-warden
go mod tidy

# Build and run locally
make build-local
make run

# Test the service
curl -X POST http://localhost:8080/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "your-github-oidc-token", "role": "your-aws-role-arn"}'
```

### 2. Code Quality Checks

```bash
# Format code
make fmt

# Run linter
make lint

# Run tests
make test

# Generate coverage report
make test-coverage

# Run all checks
make check
```

### 3. Build Lambda Binary

```bash
# Build bootstrap binary for AWS Lambda
make build

# The binary will be in build/bootstrap
ls -la build/bootstrap
```

## Container Image Development

### Building Locally

```bash
# Auto-install ko if needed
make verify-ko

# Build container image locally
make ko-build

# Test the container locally
docker run --rm -p 8080:8080 ko.local/aws-oidc-warden:latest
```

### Publishing Images

```bash
# Publish to GitHub Container Registry
make ko-publish-ghcr

# Publish to Docker Hub (requires Docker Hub login)
make ko-publish-dockerhub

# Publish to both registries
make ko-publish-all
```

### Custom Configuration

```bash
# Build with custom settings
GITHUB_USER=myusername \
VERSION=v1.0.0 \
GOARCH=amd64 \
make ko-build

# Publish with custom repository
GITHUB_USER=myusername \
make ko-publish-ghcr
```

## AWS Lambda Deployment

### Option 1: Using Pre-built Container Images

**Recommended for production deployments.**

```bash
# Create Lambda function with container image
aws lambda create-function \
  --function-name aws-oidc-warden \
  --package-type Image \
  --code ImageUri=ghcr.io/boogy/aws-oidc-warden:latest \
  --role arn:aws:iam::123456789012:role/lambda-execution-role \
  --architectures arm64 \
  --timeout 30 \
  --memory-size 256

# Update existing function
aws lambda update-function-code \
  --function-name aws-oidc-warden \
  --image-uri ghcr.io/boogy/aws-oidc-warden:v1.0.0
```

### Option 2: Using Lambda ZIP Package

```bash
# Build Lambda binary
make build

# Create ZIP package
cd build && zip lambda-deployment.zip bootstrap

# Create Lambda function with ZIP
aws lambda create-function \
  --function-name aws-oidc-warden \
  --runtime provided.al2023 \
  --role arn:aws:iam::123456789012:role/lambda-execution-role \
  --handler bootstrap \
  --zip-file fileb://lambda-deployment.zip \
  --architectures arm64
```

### Option 3: Using GoReleaser Package

```bash
# Download pre-built Lambda package from GitHub releases
wget https://github.com/boogy/aws-oidc-warden/releases/download/v1.0.0/aws-oidc-warden_lambda_v1.0.0_linux_arm64.zip

# Deploy to Lambda
aws lambda create-function \
  --function-name aws-oidc-warden \
  --runtime provided.al2023 \
  --role arn:aws:iam::123456789012:role/lambda-execution-role \
  --handler bootstrap \
  --zip-file fileb://aws-oidc-warden_lambda_v1.0.0_linux_arm64.zip \
  --architectures arm64
```

### Option 4: Using AWS ECR Pull-Through Cache

**Recommended for avoiding rate limits and improving performance.**

```bash
# Setup ECR pull-through cache
aws ecr create-pull-through-cache-rule \
  --ecr-repository-prefix ghcr-io \
  --upstream-registry-url ghcr.io \
  --region us-east-1

# Deploy Lambda with ECR pull-through cache
aws lambda create-function \
  --function-name aws-oidc-warden \
  --package-type Image \
  --code ImageUri=123456789012.dkr.ecr.us-east-1.amazonaws.com/ghcr-io/boogy/aws-oidc-warden:latest \
  --role arn:aws:iam::123456789012:role/lambda-execution-role \
  --architectures arm64
```

## Release Management

### Creating a Release

```bash
# Create and push a tag
git tag v1.0.1
git push origin v1.0.1

# This automatically triggers:
# 1. GitHub Actions workflow to build and publish container images
# 2. GitHub Actions workflow to create GitHub release with GoReleaser
```

### Manual Release with GoReleaser

```bash
# Install GoReleaser
go install github.com/goreleaser/goreleaser@latest

# Create a release (requires GITHUB_TOKEN)
export GITHUB_TOKEN=your_github_token
goreleaser release --clean

# Test release locally (no GitHub release created)
goreleaser release --snapshot --clean
```

## Environment Variables

You can customize the build and deployment process using these environment variables:

### Build Configuration
- `GOOS`: Target operating system (default: `linux`)
- `GOARCH`: Target architecture (default: `arm64`)
- `VERSION`: Version tag (default: git describe --tags)

### Container Configuration
- `GITHUB_USER`: GitHub username (default: `boogy`)
- `KO_DOCKER_REPO_GHCR`: GitHub Container Registry repository
- `KO_DOCKER_REPO_DOCKERHUB`: Docker Hub repository

### Release Configuration
- `GITHUB_TOKEN`: GitHub token for creating releases
- `GITHUB_REPOSITORY_OWNER`: Repository owner (set automatically in GitHub Actions)

## Troubleshooting

### Common Build Issues

1. **Go version mismatch**
   ```bash
   # Check Go version
   go version
   # Should be 1.23 or later
   ```

2. **Missing dependencies**
   ```bash
   # Clean and reinstall dependencies
   go mod tidy
   go mod download
   ```

3. **ko not found**
   ```bash
   # Auto-install ko
   make verify-ko
   ```

### Container Issues

1. **Docker not running**
   ```bash
   # Start Docker Desktop or Docker service
   sudo systemctl start docker  # Linux
   open -a Docker              # macOS
   ```

2. **Registry authentication**
   ```bash
   # Login to GitHub Container Registry
   echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

   # Login to Docker Hub
   docker login
   ```

### Lambda Deployment Issues

1. **IAM permissions**
   - Ensure Lambda execution role has proper permissions
   - Check AWS CLI credentials and permissions

2. **Architecture mismatch**
   ```bash
   # Build for correct architecture
   GOARCH=arm64 make build  # For ARM64 Lambda
   GOARCH=amd64 make build  # For x86_64 Lambda
   ```

3. **Container image too large**
   - Use multi-stage Docker builds
   - Consider using ZIP deployment for smaller functions

## Best Practices

### Development
1. **Always run tests** before committing: `make check`
2. **Use conventional commits** for better changelog generation
3. **Test locally** before deploying: `make run`

### Container Images
1. **Use specific tags** instead of `latest` in production
2. **Enable ECR pull-through cache** for better performance
3. **Monitor image sizes** and optimize if needed

### Lambda Deployment
1. **Use ARM64 architecture** for better price/performance
2. **Set appropriate memory and timeout** based on your workload
3. **Monitor CloudWatch metrics** for performance optimization
4. **Use container images** for larger deployments, ZIP for smaller ones

### Security
1. **Scan container images** for vulnerabilities
2. **Use least privilege** IAM roles
3. **Enable logging** for audit trails
4. **Regularly update dependencies**
