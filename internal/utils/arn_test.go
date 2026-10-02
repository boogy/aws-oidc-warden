package utils

import "testing"

func TestParseRoleARN(t *testing.T) {
	tests := []struct {
		name, arn, account, role string
		wantErr                  bool
	}{
		{"plain", "arn:aws:iam::123456789012:role/app", "123456789012", "app", false},
		{"path", "arn:aws:iam::123456789012:role/path/to/app", "123456789012", "app", false},
		{"govcloud", "arn:aws-us-gov:iam::222222222222:role/x", "222222222222", "x", false},
		{"china", "arn:aws-cn:iam::333333333333:role/y", "333333333333", "y", false},
		{"not an arn", "not-an-arn", "", "", true},
		{"user arn", "arn:aws:iam::123:user/bob", "", "", true},
		{"empty name", "arn:aws:iam::123456789012:role/", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acct, role, err := ParseRoleARN(tt.arn)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got (%q,%q)", acct, role)
				}
				return
			}
			if err != nil || acct != tt.account || role != tt.role {
				t.Fatalf("got (%q,%q,%v)", acct, role, err)
			}
		})
	}
}
