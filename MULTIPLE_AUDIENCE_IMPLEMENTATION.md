# Multiple Audience Support Implementation Summary

## Changes Made

### 1. Configuration Updates (`pkg/config/config.go`)
- Added `Audiences []string` field alongside existing `Audience string` for backward compatibility
- Added environment variable binding for `AOW_AUDIENCES`
- Implemented validation logic to handle backward compatibility:
  - If both `audience` and `audiences` are specified, `audiences` takes precedence
  - If only `audience` is specified, it's automatically converted to `audiences: [audience]`
  - If neither is specified, validation fails

### 2. TokenValidator Updates (`pkg/validator/validator.go`)
- Added `ExpectedAudiences []string` field to TokenValidator struct
- Updated constructor to use both single and multiple audiences
- Modified `Validate()` method to check token audiences against all expected audiences
- Updated `ParseToken()` method to handle JWT parser limitations with multiple audiences

### 3. Example Configuration (`example-config.yaml`)
- Added examples showing multiple audience configuration
- Marked single `audience` field as deprecated with migration guidance
- Provided clear examples of different audience types (AWS STS, custom APIs, etc.)

### 4. README Updates (`README.md`)
- Updated GitHub Actions workflow examples to show proper usage of `@actions/core` getIDToken function
- Added three different methods for obtaining OIDC tokens:
  1. **Recommended**: Using `@actions/core` getIDToken with specific audiences
  2. **Multi-service**: Example for multiple audiences
  3. **Legacy**: Backwards compatible curl approach
- Updated environment variable examples to show multiple audience support

### 5. Documentation Updates (`docs/CONFIGURATION.md`)
- Added comprehensive section about audience configuration
- Explained backward compatibility approach
- Provided use cases for different audience configurations
- Added GitHub Actions integration examples

### 6. Test Updates
- Updated all existing tests to use the new `Audiences` field
- Added test cases for backward compatibility
- Added test cases for multiple audience validation
- All tests pass successfully

## Features Implemented

### Backward Compatibility
- Existing configurations using `audience` continue to work unchanged
- Automatic conversion from single `audience` to `audiences` array
- No breaking changes for existing users

### Multiple Audience Support
- Can configure multiple expected audiences in OIDC tokens
- Validation succeeds if token audience matches any of the expected audiences
- Environment variable support with comma-separated values

### GitHub Actions Integration
- Examples showing how to use `@actions/core` getIDToken with specific audiences
- Support for requesting tokens for different services (AWS STS, custom APIs, etc.)
- Clear migration path from legacy token acquisition methods

## Usage Examples

### Environment Variables
```bash
# Single audience (legacy)
export AOW_AUDIENCE=sts.amazonaws.com

# Multiple audiences (recommended)
export AOW_AUDIENCES=sts.amazonaws.com,https://api.mycompany.com,internal.mycompany.com
```

### Configuration File
```yaml
# Multiple audiences
audiences:
  - sts.amazonaws.com
  - https://api.mycompany.com
  - internal.mycompany.com

# Legacy single audience (still supported)
audience: sts.amazonaws.com
```

### GitHub Actions
```javascript
const core = require('@actions/core');

// Request token for specific audience
const token = await core.getIDToken('sts.amazonaws.com');
```

## Benefits

1. **Flexibility**: Support for multiple OIDC audiences in a single deployment
2. **Backward Compatibility**: No breaking changes for existing users
3. **Best Practices**: Encourages use of `@actions/core` getIDToken function
4. **Documentation**: Comprehensive examples and migration guidance
5. **Testing**: Full test coverage for all scenarios

## Migration Path

For existing users:
1. Current configurations continue to work unchanged
2. Can gradually migrate to `audiences` field when convenient
3. Can start using `@actions/core` getIDToken for better reliability
4. Clear documentation and examples provided for all scenarios
