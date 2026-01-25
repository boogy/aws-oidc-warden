Analyze and fix GitHub issue: $ARGUMENTS

## Workflow

### 1. Understand the Issue
```bash
gh issue view $ARGUMENTS
```

Read the issue description, labels, and comments to understand:
- What is the expected behavior?
- What is the actual behavior?
- Are there reproduction steps?
- Which components are affected?

### 2. Locate Relevant Code

Based on issue context, search for relevant files:

```bash
# Find files by component
rg -n "<search term>" pkg/

# Find handler logic
rg -n "func.*Handle" pkg/handler/

# Find validation logic
rg -n "Validate" pkg/validator/

# Find config patterns
rg -n "mapstructure:" pkg/config/
```

### 3. Read CLAUDE.md Files

Before making changes, read the relevant package's CLAUDE.md:
- `pkg/handler/CLAUDE.md` for request processing
- `pkg/validator/CLAUDE.md` for token validation
- `pkg/config/CLAUDE.md` for configuration
- `pkg/aws/CLAUDE.md` for AWS operations

### 4. Implement Fix

Following established patterns from the codebase:
- Use interfaces for testability
- Follow error handling conventions
- Use structured logging with `slog`
- Pre-compile regex patterns
- Validate external input

### 5. Write/Update Tests

Create or update tests for the fix:
- Add test case to existing table-driven tests
- Create new test file if needed
- Ensure edge cases are covered

### 6. Verify Fix

```bash
make fmt          # Format code
make lint         # Check linting
make test         # Run tests
make build-local  # Verify build
```

### 7. Create Commit

Use Conventional Commits format:
```
fix: <brief description of fix>

Fixes #<issue number>

- <bullet point of change>
- <bullet point of change>
```

### 8. Create PR (if requested)

```bash
gh pr create --title "fix: <description>" --body "Fixes #$ARGUMENTS"
```
