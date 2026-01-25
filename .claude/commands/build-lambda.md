Build Lambda binaries for deployment.

## Steps

1. Clean previous builds:
   ```bash
   make clean
   ```

2. Build all Lambda variants:
   ```bash
   make build-lambda
   ```

   This builds:
   - `build/bootstrap-apigateway` - API Gateway handler
   - `build/bootstrap-alb` - ALB handler
   - `build/bootstrap-lambdaurl` - Lambda URL handler

3. Verify build artifacts:
   ```bash
   ls -la build/
   file build/bootstrap-*
   ```

4. Report binary sizes and architectures.

## Build Options

For specific targets:
```bash
make build-apigateway    # API Gateway only
make build-alb           # ALB only
make build-lambdaurl     # Lambda URL only
make build-local         # Local development binary
```

## Container Build

For container-based deployment:
```bash
make ko-build            # Build locally
make ko-publish          # Publish to ghcr.io
```

## Pre-Build Checks

Before building:
1. Run `make fmt` to format code
2. Run `make lint` to check for issues
3. Run `make test` to ensure tests pass
