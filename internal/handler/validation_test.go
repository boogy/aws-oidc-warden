package handler

import (
	"errors"
	"strings"
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

func TestParseRequestBodySizeCap(t *testing.T) {
	role := "arn:aws:iam::123456789012:role/MyRole"
	body := func(token string) string { return `{"token":"` + token + `","role":"` + role + `"}` }

	tests := []struct {
		name    string
		body    string
		parse   func(string) (*RequestData, error)
		wantErr error
	}{
		{"max token fits", body(strings.Repeat("a", MaxTokenLength)), ParseRequestBody, nil},
		{"token over field limit keeps its own error", body(strings.Repeat("a", MaxTokenLength+1)), ParseRequestBody, ErrTokenTooLarge},
		{"body at cap parses", body("t") + strings.Repeat(" ", maxBodyBytes-len(body("t"))), ParseRequestBody, nil},
		{"body over cap rejected", body("t") + strings.Repeat(" ", maxBodyBytes-len(body("t"))+1), ParseRequestBody, ErrInvalidJSON},
		{"role-only body over cap rejected", `{"role":"` + role + `"}` + strings.Repeat(" ", maxBodyBytes), ParseRoleOnlyRequestBody, ErrInvalidJSON},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.parse(tc.body)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestMaxBodyBytesCoversLegitimateBody(t *testing.T) {
	legit := `{"token":"` + strings.Repeat("a", MaxTokenLength) + `","role":"` + strings.Repeat("r", MaxRoleLength) +
		`","durationSeconds":43200,"sessionName":"` + strings.Repeat("s", 64) + `"}`
	if len(legit) >= maxBodyBytes {
		t.Fatalf("legitimate body %d bytes does not fit the %d cap", len(legit), maxBodyBytes)
	}
	if maxBodyBytes >= 64*1024 {
		t.Errorf("maxBodyBytes = %d, want well under 64 KiB", maxBodyBytes)
	}
}
