package aws

import (
	"fmt"
	"strings"

	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
)

// ParseRoleARN extracts the account ID and IAM role name from a role ARN.
// The role name is the final path segment (iam:GetRole takes the name without
// path). Returns an error for non-IAM-role ARNs.
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
