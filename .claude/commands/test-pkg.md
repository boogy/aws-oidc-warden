Run tests for a specific package: $ARGUMENTS

## Steps

1. If no package specified, ask which package to test from:
   - `pkg/handler`
   - `pkg/validator`
   - `pkg/config`
   - `pkg/aws`
   - `pkg/cache`
   - `pkg/s3logger`
   - All packages

2. Run the appropriate test command:
   ```bash
   # Single package
   go test -v ./pkg/<package>/...

   # All packages
   go test -v ./...
   ```

3. If tests fail:
   - Analyze the failure output
   - Identify the root cause
   - Suggest fixes based on codebase patterns

4. If tests pass:
   - Show coverage summary if requested
   - Identify any uncovered code paths

## Coverage Report

To generate coverage:
```bash
go test -coverprofile=coverage.out ./pkg/<package>/...
go tool cover -func=coverage.out
```
