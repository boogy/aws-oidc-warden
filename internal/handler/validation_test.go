package handler

import (
	"errors"
	"testing"
)

func TestValidateRole(t *testing.T) {
	tests := []struct {
		role    string
		wantErr error
	}{
		{"arn:aws:iam::123456789012:role/MyRole", nil},
		{"arn:aws:iam::123456789012:role/path/to/MyRole", nil},
		{"arn:aws-us-gov:iam::123456789012:role/MyRole", nil},
		{"arn:aws-cn:iam::123456789012:role/MyRole", nil},
		{"", ErrEmptyRole},
		{"arn:aws:s3:::bucket", ErrInvalidRoleFormat},
		{"arn:aws:iam::123456789012:user/ci", ErrInvalidRoleFormat},
		{"arn:aws:iam::123456789012:roles/MyRole", ErrInvalidRoleFormat},
		{"arn:aws:iam::123456789012:role/", ErrInvalidRoleFormat},
		{"arn:aws:iam:::role/MyRole", ErrInvalidRoleFormat},
		{"arn:aws:iam::123456789012", ErrInvalidRoleFormat},
	}
	for _, tc := range tests {
		t.Run(tc.role, func(t *testing.T) {
			err := validateRole(tc.role)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("validateRole(%q) = %v, want %v", tc.role, err, tc.wantErr)
			}
		})
	}
}
