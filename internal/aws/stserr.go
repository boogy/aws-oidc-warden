package aws

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aws/smithy-go"
)

// ErrAssumeRoleDenied marks an sts:AssumeRole failure AWS refused on
// authorization grounds. AccessDenied cannot separate a target trust policy
// that rejected the request from this service's own role missing
// sts:AssumeRole/sts:TagSession; only the wrapped STS message can.
var ErrAssumeRoleDenied = errors.New("sts:AssumeRole denied by AWS authorization")

// deniedCodes: STS error codes meaning "authorization refused" rather than a
// transport, throttling, credential or policy-document failure. Lower-cased
// because the SDK's own deserializer matches wire codes with EqualFold.
var deniedCodes = map[string]struct{}{
	"accessdenied":          {},
	"accessdeniedexception": {},
}

// stsErrorCode returns the AWS API error code, or "" when err is not an API error.
func stsErrorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

// classifyAssumeRoleError wraps an authorization refusal in ErrAssumeRoleDenied
// so the handler can map it to a 403; every other failure passes through
// unchanged and stays a 5xx.
func classifyAssumeRoleError(err error) error {
	if _, denied := deniedCodes[strings.ToLower(stsErrorCode(err))]; denied {
		return fmt.Errorf("%w: %w", ErrAssumeRoleDenied, err)
	}
	return err
}
