package idp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMintSubjectTemplate(t *testing.T) {
	const (
		role = "arn:aws:iam::123456789012:role/team/Deploy"
		gh   = "https://token.actions.githubusercontent.com"
		full = "{source_issuer}#{source_subject}#{role_arn}"
	)
	tests := []struct {
		name    string
		tmpl    string
		role    string
		srcSub  string
		want    string
		wantErr error
	}{
		{"role arn only", "{role_arn}", role, "org/repo", role, nil},
		{"issuer and subject", full, role, "org/repo", gh + "#org/repo#" + role, nil},
		{"account and name", "warden:{account_id}:{role_name}:{role_arn}", role, "org/repo", "warden:123456789012:Deploy:" + role, nil},
		{"space in source subject", full, role, "org/re po", "", ErrInvalidSubject},
		{"oversized subject", full, role, strings.Repeat("a", 250), "", ErrInvalidSubject},
		{"empty template", "", role, "x", "", ErrInvalidSubject},
		{"missing role arn suffix", "{account_id}", role, "x", "", ErrInvalidSubject},
		{"colon in role path", "{role_arn}", "arn:aws:iam::123456789012:role/a:b", "x", "", ErrInvalidSubject},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, ks := mintSetup(t)
			cfg.SubjectTemplate = tt.tmpl
			tok, err := mint(context.Background(), cfg, ks, MintRequest{RoleARN: tt.role, SourceIssuer: gh, SourceSubject: tt.srcSub}, time.Now())
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, decodeClaims(t, tok.Value)["sub"])
		})
	}
}

func TestMintSubjectTemplateEmitsOnlyAllowedAWSNamespaceClaims(t *testing.T) {
	cfg, ks := mintSetup(t)
	cfg.SubjectTemplate = "{source_issuer}#{source_subject}#{role_arn}"
	tok, err := mint(context.Background(), cfg, ks, MintRequest{
		RoleARN: testRole, SourceIssuer: "https://token.actions.githubusercontent.com",
		SourceSubject: "https://aws.amazon.com/tags/principal_tags/admin",
	}, time.Now())
	require.NoError(t, err)
	for k := range decodeClaims(t, tok.Value) {
		if strings.HasPrefix(k, "https://aws.amazon.com/") {
			require.Contains(t, []string{"https://aws.amazon.com/tags", "https://aws.amazon.com/source_identity"}, k)
		}
	}
}

func TestRenderSubjectMatchesReplacer(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/team/Deploy"
	tmpls := []string{
		"{role_arn}", "{source_issuer}#{source_subject}#{role_arn}", "w:{account_id}:{role_name}:{role_arn}",
		"{unknown}|{role_arn}", "{{role_arn}", "{role_arn}{role_arn}", "{role_ar{role_arn}", "x{", "{",
		"{source_subject}{source_subject}/{role_arn}", "a{role_name}{account_id}b{role_arn}",
	}
	for _, tmpl := range tmpls {
		t.Run(tmpl, func(t *testing.T) {
			want := strings.NewReplacer("{role_arn}", role, "{account_id}", "123456789012", "{role_name}", "Deploy",
				"{source_issuer}", "https://iss", "{source_subject}", "org/repo").Replace(tmpl)
			got, err := renderSubject(tmpl, role, "https://iss", "org/repo")
			if strings.HasSuffix(want, role) {
				require.NoError(t, err)
				require.Equal(t, want, got)
			} else {
				require.ErrorIs(t, err, ErrInvalidSubject)
			}
		})
	}
}

func TestRenderSubjectDoesNotReExpandClaimValues(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/Deploy"
	got, err := renderSubject("{source_issuer}#{source_subject}#{role_arn}", role, "{role_arn}", "{role_name}{account_id}{source_issuer}")
	require.NoError(t, err)
	require.Equal(t, "{role_arn}#{role_name}{account_id}{source_issuer}#"+role, got)
}
