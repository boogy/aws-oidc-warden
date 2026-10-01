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
