package idp

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const testRole = "arn:aws:iam::123456789012:role/R"

func mintSetup(tb testing.TB) (config.IdPConfig, *KeySet) {
	tb.Helper()
	cfg := testCfg()
	cfg.TokenTTL = 5 * time.Minute
	cfg.SubjectTemplate = config.IdPDefaultSubjectTemplate
	ks, err := NewKeySet(cfg, []LoadedKey{{Signer: newTestSigner(tb), Status: config.IdPKeyActive}})
	if err != nil {
		tb.Fatal(err)
	}
	return cfg, ks
}

func decodeClaims(t *testing.T, value string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(value, claims)
	require.NoError(t, err)
	return claims
}

func TestMintVerifiesWithPublicKey(t *testing.T) {
	cfg, ks := mintSetup(t)
	now := time.Unix(1_800_000_000, 0)
	tok, err := mint(context.Background(), cfg, ks, MintRequest{
		RoleARN: testRole, SourceIssuer: "https://token.actions.githubusercontent.com",
		SourceSubject: "org/repo", RequestID: "req-1", SourceIdentity: "req-1",
		Tags:           []ststypes.Tag{{Key: aws.String("repo"), Value: aws.String("org/repo")}},
		TransitiveKeys: []string{"repo"},
	}, now)
	require.NoError(t, err)
	require.Equal(t, now.Add(5*time.Minute), tok.ExpiresAt)

	parsed, err := jwt.Parse(tok.Value, func(tk *jwt.Token) (any, error) {
		require.Equal(t, ks.Active().KeyID(), tk.Header["kid"])
		return ks.Active().Public(), nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithTimeFunc(func() time.Time { return now }),
		jwt.WithIssuer("https://idp.example.com"), jwt.WithAudience("sts.amazonaws.com"))
	require.NoError(t, err)
	c := parsed.Claims.(jwt.MapClaims)
	require.Equal(t, testRole, c["sub"])
	require.Equal(t, "sts.amazonaws.com", c["aud"])
	require.Equal(t, tok.ID, c["jti"])
	require.Equal(t, "org/repo", c["src_sub"])
	require.Equal(t, "req-1", c["https://aws.amazon.com/source_identity"])
	require.NotContains(t, c, "role_arn")
	tags := c["https://aws.amazon.com/tags"].(map[string]any)
	require.Equal(t, []any{"org/repo"}, tags["principal_tags"].(map[string]any)["repo"])
	require.Equal(t, []any{"repo"}, tags["transitive_tag_keys"])
}

func TestMintAudienceRoleARN(t *testing.T) {
	cfg, ks := mintSetup(t)
	cfg.AudienceMode = config.IdPAudienceRoleARN
	tok, err := mint(context.Background(), cfg, ks, MintRequest{RoleARN: testRole}, time.Now())
	require.NoError(t, err)
	require.Equal(t, testRole, decodeClaims(t, tok.Value)["aud"])
}

func TestMintSourceIdentity(t *testing.T) {
	cfg, ks := mintSetup(t)
	const key = "https://aws.amazon.com/source_identity"

	_, err := mint(context.Background(), cfg, ks, MintRequest{RoleARN: testRole, SourceIdentity: "bad id!"}, time.Now())
	require.ErrorIs(t, err, ErrInvalidSourceIdentity)

	tok, err := mint(context.Background(), cfg, ks, MintRequest{RoleARN: testRole, SourceIdentity: "ab"}, time.Now())
	require.NoError(t, err)
	require.Contains(t, decodeClaims(t, tok.Value), key)

	f := false
	cfg.IncludeSourceIdentity = &f
	tok, err = mint(context.Background(), cfg, ks, MintRequest{RoleARN: testRole, SourceIdentity: "ab"}, time.Now())
	require.NoError(t, err)
	require.NotContains(t, decodeClaims(t, tok.Value), key)
}

func TestMintSourceIdentityPatternRows(t *testing.T) {
	cfg, ks := mintSetup(t)
	tests := []struct {
		name, id string
		wantErr  bool
	}{
		{"min length", "ab", false},
		{"all punctuation", "a@b.c=d,e+f-g", false},
		{"too short", "a", true},
		{"too long", strings.Repeat("a", 65), true},
		{"space", "a b", true},
		{"colon", "a:b", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mint(context.Background(), cfg, ks, MintRequest{RoleARN: testRole, SourceIdentity: tt.id}, time.Now())
			if tt.wantErr {
				require.ErrorIs(t, err, ErrInvalidSourceIdentity)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestMintEmitsOnlyAllowedAWSNamespaceClaims(t *testing.T) {
	cfg, ks := mintSetup(t)
	tok, err := mint(context.Background(), cfg, ks, MintRequest{
		RoleARN: testRole, SourceIssuer: "https://token.actions.githubusercontent.com",
		SourceSubject: "https://aws.amazon.com/tags/principal_tags/admin", RequestID: "req-1", SourceIdentity: "req-1",
		Tags: []ststypes.Tag{{Key: aws.String("repo"), Value: aws.String("org/repo")}},
	}, time.Now())
	require.NoError(t, err)
	allowed := map[string]bool{"https://aws.amazon.com/tags": true, "https://aws.amazon.com/source_identity": true}
	for name := range decodeClaims(t, tok.Value) {
		if strings.HasPrefix(name, "https://aws.amazon.com/") {
			require.True(t, allowed[name], "unexpected AWS-namespace claim %q", name)
		}
	}
}

type countingSigner struct {
	Signer
	calls int
}

func (c *countingSigner) Sign(ctx context.Context, in []byte) ([]byte, error) {
	c.calls++
	return c.Signer.Sign(ctx, in)
}

func TestMintRejectsOversizedToken(t *testing.T) {
	cfg := testCfg()
	cfg.TokenTTL = 5 * time.Minute
	cs := &countingSigner{Signer: newTestSigner(t)}
	ks, err := NewKeySet(cfg, []LoadedKey{{Signer: cs, Status: config.IdPKeyActive}})
	require.NoError(t, err)
	var tags []ststypes.Tag
	for i := range 50 {
		tags = append(tags, ststypes.Tag{Key: aws.String(fmt.Sprintf("%03d", i) + strings.Repeat("k", 125)), Value: aws.String(strings.Repeat("v", 256))})
	}
	_, err = mint(context.Background(), cfg, ks, MintRequest{RoleARN: testRole, Tags: tags}, time.Now())
	require.ErrorIs(t, err, ErrTokenTooLarge)
	require.Zero(t, cs.calls)
}

func TestMintSizeEstimateIsUpperBound(t *testing.T) {
	signers := map[string]Signer{"ES256": newTestSigner(t), "RS256": newTestRSASigner(t)}
	for alg, s := range signers {
		cfg := testCfg()
		cfg.TokenTTL = 5 * time.Minute
		ks, err := NewKeySet(cfg, []LoadedKey{{Signer: s, Status: config.IdPKeyActive}})
		require.NoError(t, err)
		for _, n := range []int{0, 5, 40} {
			t.Run(fmt.Sprintf("%s/%d tags", alg, n), func(t *testing.T) {
				var tags []ststypes.Tag
				for i := range n {
					tags = append(tags, ststypes.Tag{Key: aws.String(fmt.Sprintf("k%d", i)), Value: aws.String(strings.Repeat("v", 100))})
				}
				tok, err := mint(context.Background(), cfg, ks, MintRequest{RoleARN: testRole, Tags: tags}, time.Now())
				require.NoError(t, err)
				parts := strings.Split(tok.Value, ".")
				h, err := b64.DecodeString(parts[0])
				require.NoError(t, err)
				p, err := b64.DecodeString(parts[1])
				require.NoError(t, err)
				require.GreaterOrEqual(t, estimateTokenLen(h, p, alg), len(tok.Value))
			})
		}
	}
}

func TestMintClaimsMatchDiscovery(t *testing.T) {
	cfg, ks := mintSetup(t)
	tok, err := mint(context.Background(), cfg, ks, MintRequest{
		RoleARN: testRole, SourceIssuer: "https://token.actions.githubusercontent.com", SourceSubject: "org/repo",
		RequestID: "req-1", SourceIdentity: "req-1",
		Tags: []ststypes.Tag{{Key: aws.String("repo"), Value: aws.String("org/repo")}},
	}, time.Now())
	require.NoError(t, err)
	var got []string
	for name := range decodeClaims(t, tok.Value) {
		got = append(got, name)
	}
	require.ElementsMatch(t, mintedClaims, got)
}

func TestMintTimes(t *testing.T) {
	cfg, ks := mintSetup(t)
	now := time.Unix(1_800_000_000, 999)
	tok, err := mint(context.Background(), cfg, ks, MintRequest{RoleARN: testRole}, now)
	require.NoError(t, err)
	require.True(t, tok.IssuedAt.Equal(now.Truncate(time.Second)))
	c := decodeClaims(t, tok.Value)
	iat, nbf, exp := c["iat"].(float64), c["nbf"].(float64), c["exp"].(float64)
	require.Equal(t, nbfSkew, time.Duration(iat-nbf)*time.Second)
	require.Equal(t, cfg.TokenTTL, time.Duration(exp-iat)*time.Second)
}

func TestMintUniqueJTI(t *testing.T) {
	cfg, ks := mintSetup(t)
	a, err := mint(context.Background(), cfg, ks, MintRequest{RoleARN: testRole}, time.Now())
	require.NoError(t, err)
	b, err := mint(context.Background(), cfg, ks, MintRequest{RoleARN: testRole}, time.Now())
	require.NoError(t, err)
	require.NotEqual(t, a.ID, b.ID)
}

func TestMintSubjectIsExactRoleARN(t *testing.T) {
	cfg, ks := mintSetup(t)
	for _, role := range []string{
		testRole,
		"arn:aws:iam::123456789012:role/team/deploy/R",
		"arn:aws-us-gov:iam::123456789012:role/R",
	} {
		tok, err := mint(context.Background(), cfg, ks, MintRequest{RoleARN: role, SourceSubject: "org/repo"}, time.Now())
		require.NoError(t, err)
		require.Equal(t, role, tok.Subject)
	}
}

func TestMintRejectsBadRoleARN(t *testing.T) {
	cfg, ks := mintSetup(t)
	for name, role := range map[string]string{
		"empty":         "",
		"not a role":    "arn:aws:iam::123456789012:user/U",
		"too long":      "arn:aws:iam::123456789012:role/" + strings.Repeat("p/", 120) + "R",
		"colon in path": "arn:aws:iam::2:role/x/arn:aws:iam::1:role/R",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := mint(context.Background(), cfg, ks, MintRequest{RoleARN: role}, time.Now())
			require.ErrorIs(t, err, ErrInvalidSubject)
		})
	}
}

func TestMintOmitsTagsClaimWhenNoTags(t *testing.T) {
	cfg, ks := mintSetup(t)
	const key = "https://aws.amazon.com/tags"
	tok, err := mint(context.Background(), cfg, ks, MintRequest{RoleARN: "arn:aws:iam::1:role/R"}, time.Now())
	require.NoError(t, err)
	require.NotContains(t, decodeClaims(t, tok.Value), key)

	tok, err = mint(context.Background(), cfg, ks, MintRequest{RoleARN: "arn:aws:iam::1:role/R",
		Tags: []ststypes.Tag{{Key: aws.String("a"), Value: aws.String("b")}}}, time.Now())
	require.NoError(t, err)
	require.Contains(t, decodeClaims(t, tok.Value), key)
}

func TestMintTagsOnlyPrincipalTags(t *testing.T) {
	cfg, ks := mintSetup(t)
	tags := []ststypes.Tag{{Key: aws.String("a"), Value: aws.String("1")}, {Key: aws.String("b"), Value: aws.String("2")}}
	tests := []struct {
		name      string
		transitiv []string
	}{
		{"with transitive keys", []string{"a"}},
		{"nil transitive keys", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, err := mint(context.Background(), cfg, ks, MintRequest{RoleARN: testRole, Tags: tags, TransitiveKeys: tt.transitiv}, time.Now())
			require.NoError(t, err)
			at := decodeClaims(t, tok.Value)["https://aws.amazon.com/tags"].(map[string]any)
			pt := at["principal_tags"].(map[string]any)
			require.Len(t, pt, 2)
			require.Contains(t, pt, "a")
			require.Contains(t, pt, "b")
			if tt.transitiv == nil {
				require.NotContains(t, at, "transitive_tag_keys")
				return
			}
			require.Equal(t, []any{"a"}, at["transitive_tag_keys"])
		})
	}
}

type badSigner struct{ Signer }

func (badSigner) Sign(context.Context, []byte) ([]byte, error) { return make([]byte, 64), nil }

func TestMintFailsClosedOnBadSignature(t *testing.T) {
	cfg, ks := mintSetup(t)
	ks.active = badSigner{ks.active}
	_, err := mint(context.Background(), cfg, ks, MintRequest{RoleARN: "arn:aws:iam::1:role/R"}, time.Now())
	require.ErrorContains(t, err, "self-verification")
}

func BenchmarkMintPEM(b *testing.B) {
	cfg, ks := mintSetup(b)
	req := MintRequest{RoleARN: testRole, SourceSubject: "org/repo"}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := mint(context.Background(), cfg, ks, req, time.Now()); err != nil {
			b.Fatal(err)
		}
	}
}
