# Release Management

This project uses [GoReleaser](https://goreleaser.com/) for automated release management, creating Lambda deployment packages and GitHub releases with proper changelog generation.

## Prerequisites

- [GoReleaser](https://goreleaser.com/install/) installed on your system
- GitHub token with repository permissions (for GitHub releases)
- Git repository with proper tags

## Release Configuration

The GoReleaser configuration is stored in `.goreleaser.yaml` in the root of the project. This configuration:

- Builds Lambda-optimized binaries with the `bootstrap` name
- Creates ZIP archives for direct Lambda deployment
- Generates checksums for all release artifacts
- Creates GitHub releases with automated changelogs
- Supports multi-architecture builds (amd64/arm64)

## Creating a Release

### 1. Tag a Release

```bash
# Create and push a new tag
git tag v1.0.0
git push origin v1.0.0
```

### 2. Run GoReleaser

```bash
# Create a release (requires GITHUB_TOKEN environment variable)
goreleaser release --clean

# Create a snapshot release (for testing, no GitHub release)
goreleaser release --snapshot --clean
```

### 3. Automated Releases

The project includes GitHub Actions workflow that automatically runs GoReleaser when a new tag is pushed:

- Located in `.github/workflows/release.yml`
- Triggered on tag push
- Creates GitHub release with binaries and changelog
- Uploads Lambda deployment packages

## Release Artifacts

Each release includes:

### Lambda Deployment Packages
- `aws-oidc-warden_lambda_v1.0.0_linux_amd64.zip` - Lambda package for x86_64
- `aws-oidc-warden_lambda_v1.0.0_linux_arm64.zip` - Lambda package for ARM64

### Checksums
- `aws-oidc-warden_v1.0.0_SHA256SUMS` - SHA256 checksums for all artifacts

### Changelog
- Automatically generated based on conventional commits
- Categorized by:
  - Features (`feat:`)
  - Bug fixes (`fix:`)
  - Security (`sec:`)
  - Others

## Deploying Lambda from Release

### Option 1: Download and Deploy Manually

```bash
# Download the release package
wget https://github.com/yourusername/aws-oidc-warden/releases/download/v1.0.0/aws-oidc-warden_lambda_v1.0.0_linux_arm64.zip

# Create Lambda function
aws lambda create-function \
  --function-name aws-oidc-warden \
  --runtime provided.al2023 \
  --role arn:aws:iam::123456789012:role/lambda-execution-role \
  --handler bootstrap \
  --zip-file fileb://aws-oidc-warden_lambda_v1.0.0_linux_arm64.zip \
  --architectures arm64

# Update existing Lambda function
aws lambda update-function-code \
  --function-name aws-oidc-warden \
  --zip-file fileb://aws-oidc-warden_lambda_v1.0.0_linux_arm64.zip
```

### Option 2: Direct URL Deploy

```bash
# Create Lambda function from GitHub release URL
aws lambda create-function \
  --function-name aws-oidc-warden \
  --runtime provided.al2023 \
  --role arn:aws:iam::123456789012:role/lambda-execution-role \
  --handler bootstrap \
  --code ZipFile=fileb://<(curl -sL https://github.com/yourusername/aws-oidc-warden/releases/download/v1.0.0/aws-oidc-warden_lambda_v1.0.0_linux_arm64.zip) \
  --architectures arm64
```

## Versioning Strategy

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version when making incompatible API changes
- **MINOR** version when adding functionality in a backwards compatible manner
- **PATCH** version when making backwards compatible bug fixes

### Tag Format
- Release tags: `v1.0.0`, `v1.1.0`, `v2.0.0`
- Pre-release tags: `v1.0.0-rc.1`, `v1.0.0-beta.1`

## Changelog Format

The changelog is automatically generated using conventional commits:

```
## Features
- feat: add support for custom session policies
- feat(cache): implement S3 caching backend

## Bug fixes
- fix: resolve JWT validation edge case
- fix(config): handle missing environment variables

## Security
- sec: update dependencies to fix CVE-2023-12345

## Others
- docs: update installation instructions
- ci: improve release workflow
```

## Environment Variables for Releases

- `GITHUB_TOKEN`: Required for creating GitHub releases
- `GITHUB_REPOSITORY_OWNER`: Set automatically in GitHub Actions
- `GORELEASER_CURRENT_TAG`: Current tag being released (set by GoReleaser)

## Best Practices

1. **Use conventional commits** for better changelog generation
2. **Test releases** using `--snapshot` flag before creating actual releases
3. **Review generated changelog** before publishing
4. **Tag releases** from the main branch for consistency
5. **Include breaking changes** in commit messages for major version bumps
