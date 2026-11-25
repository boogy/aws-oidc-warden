package config

func roleEntries(arns ...string) []RoleEntry {
	out := make([]RoleEntry, len(arns))
	for i, arn := range arns {
		out[i] = RoleEntry{Role: arn}
	}
	return out
}
