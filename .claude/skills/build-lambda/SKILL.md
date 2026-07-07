---
name: build-lambda
description: Use when building Lambda deployment binaries or zips for any frontend variant (apigateway, apigatewayv2, alb, lambdaurl), or when a Lambda deploy fails to start.
---

# Build Lambda

Build the Lambda variants. Non-negotiables: the binary inside a deploy zip
must be named `bootstrap` (`provided.al2023` requirement) and the default
target is ARM64.

## Steps

1. `make clean`
2. `make build-lambda` — builds all variants:
   - `build/bootstrap-apigateway` — API Gateway REST (self mode)
   - `build/bootstrap-apigatewayv2` — API Gateway HTTP v2 (apigw mode)
   - `build/bootstrap-alb` — ALB
   - `build/bootstrap-lambdaurl` — Lambda URL
3. Verify: `ls -la build/ && file build/bootstrap-*` — report sizes and
   architectures (expect ARM64).

## Single targets

```bash
make build-apigateway    # REST (self mode)
make build-apigatewayv2  # HTTP v2 (apigw mode)
make build-alb
make build-lambdaurl
make build-local         # local dev binary
```

## Container images

```bash
make ko-build            # local
make ko-publish          # ghcr.io
```

## Pitfalls

- Zip for direct upload must contain the binary renamed to `bootstrap`
  (`deploy/opentofu/build.sh` does this correctly — reuse it).
- Pick the binary matching `jwt_validation.mode`: self → `apigateway`,
  apigw → `apigatewayv2`.
- Run `make check` before committing build-related changes.
