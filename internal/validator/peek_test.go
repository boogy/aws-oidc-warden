package validator

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func benchToken() string {
	payload := `{"iss":"https://token.actions.githubusercontent.com","sub":"repo:org/repo:ref:refs/heads/main","aud":"sts.amazonaws.com","exp":1999999999,"iat":1700000000,"nbf":1700000000,"jti":"abc","repository":"org/repo","repository_owner":"org","ref":"refs/heads/main","sha":"0123456789abcdef0123456789abcdef01234567","workflow":"ci","actor":"someone","run_id":"123456","run_number":"7","job_workflow_ref":"org/repo/.github/workflows/ci.yml@refs/heads/main","runner_environment":"github-hosted"}`
	return b64(`{"alg":"RS256","kid":"k1","typ":"JWT"}`) + "." + b64(payload) + "." + strings.Repeat("s", 342)
}

func BenchmarkIssuerPeek(b *testing.B) {
	tok := benchToken()
	b.Run("ParseUnverified", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			m := jwt.MapClaims{}
			if _, _, err := jwt.NewParser().ParseUnverified(tok, m); err != nil {
				b.Fatal(err)
			}
			if iss, _ := m.GetIssuer(); iss == "" {
				b.Fatal("no iss")
			}
		}
	})
	b.Run("peekIssuer", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if iss, err := peekIssuer(tok); err != nil || iss == "" {
				b.Fatal("no iss", err)
			}
		}
	})
}

func TestPeekIssuer(t *testing.T) {
	hdr := b64(`{"alg":"RS256"}`)
	tests := []struct {
		name          string
		token         string
		wantIss       string
		wantMalformed bool
		wantNoIss     bool
	}{
		{"valid", hdr + "." + b64(`{"iss":"https://a"}`) + ".sig", "https://a", false, false},
		{"empty signature segment", hdr + "." + b64(`{"iss":"https://a"}`) + ".", "https://a", false, false},
		{"extra claims ignored", hdr + "." + b64(`{"sub":"x","iss":"https://a","n":1,"o":{"iss":"nested"}}`) + ".sig", "https://a", false, false},
		{"empty token", "", "", true, false},
		{"no dots", "abc", "", true, false},
		{"one dot", hdr + "." + b64(`{"iss":"a"}`), "", true, false},
		{"four segments", hdr + "." + b64(`{"iss":"a"}`) + ".sig.extra", "", true, false},
		{"trailing dot makes four", hdr + "." + b64(`{"iss":"a"}`) + ".sig.", "", true, false},
		{"bad base64 payload", hdr + ".!!!!." + "sig", "", true, false},
		{"padded base64 payload rejected", hdr + "." + base64.URLEncoding.EncodeToString([]byte(`{"iss":"abc"}`)) + ".sig", "", true, false},
		{"payload not json", hdr + "." + b64(`not json`) + ".sig", "", true, false},
		{"payload json array", hdr + "." + b64(`["iss"]`) + ".sig", "", true, false},
		{"payload json string", hdr + "." + b64(`"iss"`) + ".sig", "", true, false},
		{"empty payload", hdr + ".." + "sig", "", true, false},
		{"missing iss", hdr + "." + b64(`{"sub":"x"}`) + ".sig", "", false, true},
		{"empty iss", hdr + "." + b64(`{"iss":""}`) + ".sig", "", false, true},
		{"null payload", hdr + "." + b64(`null`) + ".sig", "", false, true},
		{"numeric iss", hdr + "." + b64(`{"iss":5}`) + ".sig", "", false, true},
		{"array iss", hdr + "." + b64(`{"iss":["https://a"]}`) + ".sig", "", false, true},
		{"object iss", hdr + "." + b64(`{"iss":{"a":1}}`) + ".sig", "", false, true},
		{"null iss", hdr + "." + b64(`{"iss":null}`) + ".sig", "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iss, err := peekIssuer(tt.token)
			switch {
			case tt.wantMalformed:
				require.Error(t, err)
				assert.ErrorIs(t, err, jwt.ErrTokenMalformed)
				assert.False(t, errors.Is(err, ErrUnknownIssuer))
			case tt.wantNoIss:
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrUnknownIssuer)
			default:
				require.NoError(t, err)
				assert.Equal(t, tt.wantIss, iss)
			}
		})
	}
}

// The peek must classify exactly like the ParseUnverified path it replaced.
func TestPeekIssuer_ClassifiesLikeParseUnverified(t *testing.T) {
	hdr := b64(`{"alg":"RS256"}`)
	for _, tok := range []string{
		"", "abc", "a.b", "a.b.c.d",
		hdr + ".!!!!.sig", hdr + "." + b64(`not json`) + ".sig", hdr + "." + b64(`[1]`) + ".sig",
		hdr + "." + b64(`{"iss":5}`) + ".sig", hdr + "." + b64(`{"sub":"x"}`) + ".sig",
		hdr + "." + b64(`{"iss":"https://a"}`) + ".sig",
	} {
		m := jwt.MapClaims{}
		_, _, oldErr := jwt.NewParser().ParseUnverified(tok, m)
		_, newErr := peekIssuer(tok)
		if oldErr != nil {
			assert.ErrorIs(t, newErr, jwt.ErrTokenMalformed, "token %q", tok)
			continue
		}
		iss, ierr := m.GetIssuer()
		assert.Equal(t, ierr != nil || iss == "", errors.Is(newErr, ErrUnknownIssuer), "token %q", tok)
	}
}
