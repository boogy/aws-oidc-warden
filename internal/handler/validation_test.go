package handler

import (
	"encoding/base64"
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
		{"body at cap parses", body("t") + strings.Repeat(" ", MaxBodyBytes-len(body("t"))), ParseRequestBody, nil},
		{"body over cap rejected", body("t") + strings.Repeat(" ", MaxBodyBytes-len(body("t"))+1), ParseRequestBody, ErrInvalidJSON},
		{"role-only body over cap rejected", `{"role":"` + role + `"}` + strings.Repeat(" ", MaxBodyBytes), ParseRoleOnlyRequestBody, ErrInvalidJSON},
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
	if len(legit) >= MaxBodyBytes {
		t.Fatalf("legitimate body %d bytes does not fit the %d cap", len(legit), MaxBodyBytes)
	}
	if MaxBodyBytes >= 64*1024 {
		t.Errorf("MaxBodyBytes = %d, want well under 64 KiB", MaxBodyBytes)
	}
}

func TestEventBody(t *testing.T) {
	over := base64.StdEncoding.EncodeToString(make([]byte, MaxBodyBytes+3))
	cases := []struct {
		name    string
		body    string
		b64     bool
		want    string
		wantErr bool
	}{
		{"plain passes through", "{}", false, "{}", false},
		{"base64 decoded", "e30=", true, "{}", false},
		{"invalid base64", "e30", true, "", true},
		{"oversized encoding rejected before decode", over, true, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := eventBody(tc.body, tc.b64)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidJSON) {
					t.Fatalf("err = %v, want ErrInvalidJSON", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}
