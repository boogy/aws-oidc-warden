package aws

import "github.com/boogy/aws-oidc-warden/internal/utils"

// ParseRoleARN delegates to utils.ParseRoleARN.
func ParseRoleARN(roleARN string) (string, string, error) { return utils.ParseRoleARN(roleARN) }
