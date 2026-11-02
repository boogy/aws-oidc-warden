package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdPSourceIdentityTemplateValidate(t *testing.T) {
	tests := []struct {
		name    string
		tmpl    string
		issuers int
		wantErr string
	}{
		{"request_id, single issuer", "{request_id}", 1, ""},
		{"subject, single issuer", "{subject}", 1, ""},
		{"claim", "{claim:repository}", 1, ""},
		{"literal and claim", "repo={claim:repository}", 1, ""},
		{"issuer placeholder", "{issuer}:{subject}", 2, ""},
		{"issuer placeholder single", "{issuer}:{subject}", 1, ""},
		{"two issuers, no issuer placeholder", "{subject}", 2, "{issuer}"},
		{"two issuers, claim only", "{claim:repository}", 3, "{issuer}"},
		{"unknown placeholder", "{actor}", 1, "unknown placeholder"},
		{"bad literal slash", "a/b{request_id}", 1, "literal"},
		{"bad literal plus", "a+{subject}", 1, "literal"},
		{"empty claim name", "{claim:}", 1, "claim name"},
		{"unbalanced brace", "{request_id", 1, "literal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSourceIdentityTemplate(tt.tmpl, tt.issuers)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestIdPSubjectTemplateValidate(t *testing.T) {
	tests := []struct {
		name    string
		tmpl    string
		wantErr string
	}{
		{"role_arn only", "{role_arn}", ""},
		{"account prefix", "warden:{account_id}:{role_arn}", ""},
		{"full", "{source_issuer}#{source_subject}#{role_arn}", ""},
		{"missing source_issuer", "{source_subject}#{role_arn}", "{source_issuer}"},
		{"issuer after subject", "{source_subject}#{source_issuer}#{role_arn}", "{source_issuer}"},
		{"no separator", "{source_issuer}{source_subject}#{role_arn}", "#"},
		{"account and role name", "{account_id}/{role_name}", "end with {role_arn}"},
		{"role_arn not last", "{role_arn}#{source_subject}", "end with {role_arn}"},
		{"role_arn twice", "{role_arn}{role_arn}", "exactly once"},
		{"unknown placeholder", "{actor}{role_arn}", "unknown placeholder"},
		{"bad literal", "a b{role_arn}", "literal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSubjectTemplate(tt.tmpl)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestIdPValidateTemplates(t *testing.T) {
	tests := []struct {
		name            string
		issuers         int
		sourceIdentity  string
		subjectTemplate string
		wantErr         string
	}{
		{"2 issuers subject only", 2, "{subject}", "", "{issuer}"},
		{"2 issuers issuer placeholder", 2, "{issuer}:{subject}", "", ""},
		{"1 issuer", 1, "{subject}", "", ""},
		{"2 issuers + default", 2, "", "", ""},
		{"bad subject template", 1, "", "{account_id}/{role_name}", "must end with {role_arn}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AWS_LAMBDA_FUNCTION_NAME", "")
			inbound := make([]IssuerConfig, tt.issuers)
			for i := range inbound {
				inbound[i] = IssuerConfig{Issuer: "https://issuer" + string(rune('a'+i)) + ".example.com"}
			}
			c := validIdP()
			c.SourceIdentity = tt.sourceIdentity
			c.SubjectTemplate = tt.subjectTemplate
			c.applyDefaults()
			err := c.validate(false, inbound)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestIdPDefaultsSourceIdentity(t *testing.T) {
	c := &IdPConfig{Issuer: "https://h.example.com"}
	c.applyDefaults()
	require.Equal(t, "{issuer}:{subject}", c.SourceIdentity)
}
