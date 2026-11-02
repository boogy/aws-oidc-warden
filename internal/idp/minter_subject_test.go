package idp

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/boogy/aws-oidc-warden/internal/utils"
)

func TestSubjectPlaceholdersMatchConfigValidator(t *testing.T) {
	var got []string
	for _, p := range subjectPlaceholders {
		got = append(got, p.token)
	}
	slices.Sort(got)
	require.Equal(t, config.IdPSubjectPlaceholders(), got)
}

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
			tok, err := mintT(cfg, ks, MintRequest{RoleARN: tt.role, SourceIssuer: gh, SourceSubject: tt.srcSub}, time.Now())
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
	tok, err := mintT(cfg, ks, MintRequest{
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

func FuzzRenderSubjectMatchesReplacer(f *testing.F) {
	const role = "arn:aws:iam::123456789012:role/team/Deploy"
	for _, tmpl := range []string{
		"{role_arn}", "{source_issuer}#{source_subject}#{role_arn}", "w:{account_id}:{role_name}:{role_arn}",
		"{unknown}|{role_arn}", "{{role_arn}", "{role_arn}{role_arn}", "{role_ar{role_arn}", "x{", "{",
		"{source_subject}{source_subject}/{role_arn}", "a{role_name}{account_id}b{role_arn}",
	} {
		f.Add(tmpl, role, "https://iss", "org/repo")
	}
	f.Add("{source_issuer}#{source_subject}#{role_arn}", role, "{role_arn}", "{role_name}{account_id}{source_issuer}")
	for _, sub := range []string{"a b", "a\x7f", "a\x1f", "a\x80"} {
		f.Add("{source_subject}#{role_arn}", role, "i", sub)
	}
	f.Add("{role_arn}", "arn:aws:iam::1:role/a:b", "i", "s")
	f.Fuzz(func(t *testing.T, tmpl, roleARN, iss, sub string) {
		got, err := renderSubject(compileSubjectTemplate(tmpl), roleARN, iss, sub)
		account, name, perr := utils.ParseRoleARN(roleARN)
		if perr != nil || strings.Count(roleARN, ":") != 5 {
			require.ErrorIs(t, err, ErrInvalidSubject)
			return
		}
		want := strings.NewReplacer("{role_arn}", roleARN, "{account_id}", account, "{role_name}", name,
			"{source_issuer}", iss, "{source_subject}", sub).Replace(tmpl)
		valid := len(want) <= maxSubjectBytes && strings.HasSuffix(want, roleARN)
		for i := 0; valid && i < len(want); i++ {
			valid = want[i] >= 0x21 && want[i] <= 0x7e
		}
		if !valid {
			require.ErrorIs(t, err, ErrInvalidSubject)
			return
		}
		require.NoError(t, err)
		require.Equal(t, want, got)
	})
}

func TestRenderSubjectDoesNotReExpandClaimValues(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/Deploy"
	got, err := renderSubject(compileSubjectTemplate("{source_issuer}#{source_subject}#{role_arn}"), role, "{role_arn}", "{role_name}{account_id}{source_issuer}")
	require.NoError(t, err)
	require.Equal(t, "{role_arn}#{role_name}{account_id}{source_issuer}#"+role, got)
}
