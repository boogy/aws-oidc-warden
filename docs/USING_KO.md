# Building and Deploying with ko

This project can be built and deployed using [ko](https://ko.build), a simple, fast container image builder for Go applications.

## Prerequisites

- [ko](https://ko.build/install/) installed on your system
- AWS CLI configured with appropriate permissions
- Docker installed on your system

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

# Publish container image to the repository specified in KO_DOCKER_REPO
make ko-publish

# Publish container image to AWS ECR
make ko-publish-ecr

# Build, publish to ECR and deploy to AWS Lambda
make ko-deploy-lambda
```

## Environment Variables

You can customize the behavior by setting the following environment variables:

- `KO_DOCKER_REPO`: Docker registry to push images to (default: ko.local)
- `KO_TAGS`: Tags for the container image (default: git version tag)
- `AWS_REGION`: AWS region to deploy to (default: us-east-1)
- `LAMBDA_FUNCTION_NAME`: AWS Lambda function name (default: aws-oidc-warden)
- `LAMBDA_MEMORY`: Lambda memory allocation in MB (default: 128)
- `LAMBDA_TIMEOUT`: Lambda timeout in seconds (default: 10)
- `LAMBDA_ROLE`: IAM role for Lambda execution (default: aws-oidc-warden-role)

## Examples

### Build a local container image

```sh
make ko-build
```

### Deploy to AWS Lambda

```sh
# Deploy using default settings
make ko-deploy-lambda

# Deploy with custom settings
AWS_REGION=us-west-2 LAMBDA_MEMORY=256 LAMBDA_TIMEOUT=30 make ko-deploy-lambda
```

### Publish to a specific registry

```sh
# Push to Docker Hub
KO_DOCKER_REPO=docker.io/yourusername/aws-oidc-warden make ko-publish

# Push to GitHub Container Registry
KO_DOCKER_REPO=ghcr.io/yourusername/aws-oidc-warden make ko-publish
```

## Advantages of using ko

1. **Simplicity**: ko automatically builds your Go application and creates an optimized container image
2. **Speed**: Much faster than traditional Docker builds
3. **Multi-arch support**: Easy building for multiple architectures
4. **OCI compliance**: Creates standards-compliant container images
5. **Integration**: Works well with existing Docker and Kubernetes workflows
