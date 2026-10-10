package utils

import (
	"fmt"
	"strings"

	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
)

// ParseRoleARN returns the account ID and role name (final path segment) of an IAM role ARN.
func ParseRoleARN(roleARN string) (account, roleName string, err error) {
	a, err := awsarn.Parse(roleARN)
	if err != nil {
		return "", "", fmt.Errorf("invalid role ARN %q: %w", roleARN, err)
	}
	if a.Service != "iam" || !strings.HasPrefix(a.Resource, "role/") {
		return "", "", fmt.Errorf("ARN is not an IAM role: %q", roleARN)
	}
	resource := strings.TrimPrefix(a.Resource, "role/") // may contain a path
	segments := strings.Split(resource, "/")
	name := segments[len(segments)-1]
	if a.AccountID == "" || name == "" {
		return "", "", fmt.Errorf("role ARN missing account or name: %q", roleARN)
	}
	return a.AccountID, name, nil
}
