# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking Changes

- **S3/JSON config files must use `snake_case` keys** — `PascalCase` keys (`RepoRoleMappings`, `RoleSessionName`, etc.) are no longer accepted. Migrate any S3-hosted JSON configs to `snake_case` before upgrading (#230)
- **`workflow_ref` constraint regex is now auto-anchored** — previously matched as a substring; now compiled as `^(?:...)$` like all other constraints. Patterns relying on partial matching must be updated (#237)

### Added

- Cross-account tag-based authorization (hub/spoke) — spoke accounts delegate role assumption decisions to a hub via ABAC session tags (#236)
- Transitive session tags + target-account allow-list — session tags now flow across assumed roles; a per-repo `target_accounts` allow-list restricts which accounts a token may reach (#233)
- Short `aow`/`repo` session tags via `tag_auth.default_org` — when a default org is set, the org prefix is stripped from session tag values to stay within the 256-char STS limit (#234)
- EC key support restored (ES256/384/512) — EC tokens were incorrectly rejected in prior versions (#230)
- Hot-reload now propagates to the AWS consumer — `allowed_accounts`, tag-auth enable/disable, spoke role, and external-id changes take effect without a Lambda cold start (#237)
- Validator reads issuer/audiences from the live config on every call — revoked audiences are enforced immediately after an S3 config reload (#230)
- `jwt_validation.mode` config option (`"self"` / `"apigw"` / `"alb"`) to delegate JWT verification to API Gateway HTTP API v2 JWT Authorizer or ALB OIDC.
- `ClaimsExtractorInterface` in `internal/validator/` with `SelfExtractor`, `APIGWExtractor`, and `ALBExtractor` implementations.
- `AwsApiGatewayV2` Lambda adapter (`internal/handler/apigatewayv2.go`) and `cmd/apigatewayv2/` entry point for HTTP API v2 deployments.
- `ParseRoleOnlyRequestBody` for delegated-mode requests (only `role` ARN required in body).
- `AOW_JWT_VALIDATION_MODE` and `AOW_JWT_VALIDATION_ALB_EXPECTED_SIGNER` environment variables.
- In-memory ALB public key cache (5-minute TTL) in `ALBExtractor` to avoid per-request HTTP latency.

### Fixed

- ALB and API Gateway delegated modes now enforce token expiration (`exp` required) and reject future-`iat` tokens, matching self-mode strictness.
- RSA JWKS keys shorter than 2048 bits are now rejected, and EC JWKS keys are validated to lie on their declared curve (defense-in-depth against a compromised JWKS source).
- Malformed role ARNs now return the dedicated `ErrInvalidRoleFormat` sentinel (still HTTP 400) instead of being misreported as an empty role.
- Frontend adapters (`alb`, `apigateway`, `lambdaurl`) now share the `classifyError` helper, removing duplicated/dead error-classification switches.
- Invalid `LOG_LEVEL` now logs a well-formed structured warning instead of a malformed printf-style line; full claims log at Debug rather than Info.
- JWT validation failures now return HTTP 401 instead of HTTP 500 (#230)
- S3 config hot-reload no longer triggers N concurrent fetches at the interval boundary — exactly one fetch per interval (#230)
- `AOW_*` env-var overrides are preserved across S3 hot-reloads (#230)
- S3Logger now initialises after the config provider so `log_bucket`/`log_prefix` from remote config are respected (#230)

### Changed

- Moved `pkg/` to `internal/` — all shared packages are now under `internal/` in line with Go conventions
- `ProcessRequest` signature now accepts `validator.ExtractionInput` to carry per-request extraction data.
- `RequestProcessor` holds `ClaimsExtractorInterface` instead of `TokenValidatorInterface` directly.

### Dependencies

- actions/checkout 6.0.3 → 7.0.0
- securego/gosec 2.26.1 → 2.27.1
- codecov/codecov-action 6.0.1 → 7.0.0
- github/codeql-action 4.36.0 → 4.36.2
- docker/login-action 4.1.0 → 4.2.0
- golangci/golangci-lint-action 9.2.0 → 9.2.1
- goreleaser/goreleaser-action 7.2.1 → 7.2.2
- aquasecurity/trivy-action 0.35.0 → 0.36.0
- securego/gosec 2.25.0 → 2.26.1

---

## [1.3.6] - 2026-01-25

### Changed

- Updated dependencies and documentation (#125)

### Dependencies

- actions/setup-go 6.1.0 → 6.2.0
- golangci/golangci-lint-action 9.1.0 → 9.2.0
- github/codeql-action 4.31.4 → 4.31.11
- actions/checkout 6.0.0 → 6.0.1
- codecov/codecov-action 5.5.1 → 5.5.2
- securego/gosec 2.22.10 → 2.22.11

---

## [1.3.5] - 2025-11-30

### Dependencies

- Updated Go dependencies (#109)
- actions/setup-go 6.0.0 → 6.1.0
- golangci/golangci-lint-action 8.0.0 → 9.1.0
- github/codeql-action 4.31.2 → 4.31.4
- actions/checkout 5.0.0 → 6.0.0

---

## [1.3.4] - 2025-11-06

### Dependencies

- Updated Go dependencies (#98)
- github/codeql-action 3.30.5 → 4.31.2
- docker/login-action 3.5.0 → 3.6.0

---

## [1.3.3] - 2025-09-19

### Dependencies

- Updated Go version and dependencies (#71)
- actions/setup-go 5.5.0 → 6.0.0
- aquasecurity/trivy-action 0.32.0 → 0.33.1
- github/codeql-action 3.29.11 → 3.30.3

---

## [1.3.2] - 2025-08-29

### Dependencies

- Bumped golang module (#60)
- github.com/aws/aws-sdk-go-v2/service/sts
- actions/checkout 4.2.2 → 5.0.0
- goreleaser/goreleaser-action 6.3.0 → 6.4.0

---

## [1.3.1] - 2025-08-18

### Fixed

- Replaced deprecated `builds` with `ids` in goreleaser archives (#25)
- Fixed goreleaser configuration issues (#53)

### Dependencies

- Bumped golang modules (#53)
- docker/login-action 3.4.0 → 3.5.0
- aquasecurity/trivy-action 0.31.0 → 0.32.0
- github/codeql-action 3.29.0 → 3.29.8

---

## [1.3.0] - 2025-07-14

### Performance

- Optimized Lambda bootstrap initialization — moved AWS client construction out of the hot path; Lambda cold starts reduced (#24)

### Dependencies

- github/codeql-action 3.28.19 → 3.29.0

---

## [1.2.0] - 2025-06-10

### Added

- Multi-audience support for OIDC token validation — `audience` config field now accepts a list; all values are checked against the token's `aud` claim (#6)
- CodeQL security analysis workflow and badge

### Changed

- Improved example configuration with better security patterns
- Updated GoReleaser archive format to modern syntax

---

## [1.1.0] - 2025-06-07

### Added

- `make build` command and improved CI workflow (#5)

---

## [1.0.0] - 2025-06-07

### Added

- Initial release — modular architecture with Lambda (API Gateway, ALB, Lambda URL) and local HTTP server deployment targets
- OIDC JWT validation with JWKS signature verification
- AWS STS AssumeRole with ABAC session tagging from token claims
- Repository + constraint matching with anchored regex
- Multi-tier JWKS cache (memory / DynamoDB / S3)
- Container image published to GHCR and Docker Hub
- CodeQL, Trivy, and gosec security scanning in CI

[Unreleased]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.6...HEAD
[1.3.6]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.5...v1.3.6
[1.3.5]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.4...v1.3.5
[1.3.4]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.3...v1.3.4
[1.3.3]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/boogy/aws-oidc-warden/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/boogy/aws-oidc-warden/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/boogy/aws-oidc-warden/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/boogy/aws-oidc-warden/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/boogy/aws-oidc-warden/releases/tag/v1.0.0
