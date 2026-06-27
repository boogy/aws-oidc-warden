package aws

import "testing"

func TestParseRoleARN(t *testing.T) {
	cases := []struct {
		arn, account, role string
		wantErr            bool
	}{
		{"arn:aws:iam::123456789012:role/app", "123456789012", "app", false},
		{"arn:aws:iam::123456789012:role/path/to/app", "123456789012", "app", false},
		{"arn:aws-us-gov:iam::222222222222:role/x", "222222222222", "x", false},
		{"not-an-arn", "", "", true},
		{"arn:aws:iam::123:user/bob", "", "", true},
	}
	for _, c := range cases {
		acct, role, err := ParseRoleARN(c.arn)
		if c.wantErr {
			if err == nil {
				t.Fatalf("%s: expected error", c.arn)
			}
			continue
		}
		if err != nil || acct != c.account || role != c.role {
			t.Fatalf("%s: got (%q,%q,%v)", c.arn, acct, role, err)
		}
	}
}
