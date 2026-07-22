package aws

import (
	"strings"
	"testing"
)

// IAM's 64-character cap applies to the role NAME, not to the whole identifier:
// a role may carry a path (`/team/sub/Name`, up to 512 characters) and the name
// is the final segment. Measuring the full string would reject valid roles with
// deep paths — so these cases pin that the length is taken after the last '/'.
func TestValidateRoleNameLength_PathIsNotCountedTowardTheNameCap(t *testing.T) {
	name64 := strings.Repeat("a", 64)
	name65 := strings.Repeat("a", 65)
	deepPath := "/" + strings.Repeat("segment/", 20) // 160 chars of path alone

	cases := []struct {
		desc    string
		input   string
		wantErr bool
	}{
		{"plain name at the cap", name64, false},
		{"plain name one over the cap", name65, true},
		{"short name behind a deep path", deepPath + "Deploy", false},
		{"name at the cap behind a deep path", deepPath + name64, false},
		{"name over the cap behind a deep path", deepPath + name65, true},
		{"single path segment, short name", "team/Deploy", false},
		{"empty (rejected earlier by the caller, not here)", "", false},
		{"trailing slash yields an empty name", "team/", false},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := validateRoleNameLength(tc.input)
			if tc.wantErr && err == nil {
				t.Fatalf("expected rejection for %q (len %d)", tc.input, len(tc.input))
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected rejection for %q (len %d): %v", tc.input, len(tc.input), err)
			}
		})
	}
}

// The whole point of rejecting instead of truncating: the previous code silently
// rewrote an over-long identifier to its first 64 characters and looked THAT up,
// so tag-based authorization read a different role's tags than the caller named.
// The error must therefore name the offending role rather than quietly succeed.
func TestValidateRoleNameLength_RejectionNamesTheRole(t *testing.T) {
	over := strings.Repeat("b", 70)
	err := validateRoleNameLength("path/to/" + over)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), over) {
		t.Fatalf("error should identify the role name, got: %v", err)
	}
	if strings.Contains(err.Error(), "path/to/") {
		t.Fatalf("error should report the NAME, not the full path, got: %v", err)
	}
}
