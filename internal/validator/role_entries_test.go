package validator_test

import "github.com/boogy/aws-oidc-warden/internal/config"

func roleEntries(arns ...string) []config.RoleEntry {
	out := make([]config.RoleEntry, len(arns))
	for i, arn := range arns {
		out[i] = config.RoleEntry{Role: arn}
	}
	return out
}
