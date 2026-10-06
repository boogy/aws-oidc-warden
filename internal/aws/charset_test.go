package aws

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	refTagCharset   = regexp.MustCompile(`^[A-Za-z0-9 _.:/=+@-]*$`)
	refSessionChars = regexp.MustCompile(`^[[:word:]+=,.@-]*$`)
)

// charsetInputs covers every rune through U+024F plus edge strings, invalid UTF-8 and trailing newlines.
func charsetInputs() []string {
	var in []string
	for r := rune(0); r <= 0x24F; r++ {
		in = append(in, string(r), "a"+string(r)+"b")
	}
	in = append(in,
		"", "abc", "owner/repo", "refs/heads/main", "a b", "a\n", "\na", "a\r\n", "é", "世界", "😀",
		"\xff", "ab\xc3", "a\x00b", "ａ", "٣", "_", "-", "+", "=", ",", ".", "@", ":", "/", " ",
		"{}", "a*b", "a#b", "a;b", "a\\b", "a'b", "a\"b", "a<b>", "a?b", "a&b", "a%b", "a|b", "a~b", "a^b", "a`b", "a$b", "a!b", "a(b)", "a[b]",
		strings.Repeat("a", 300),
	)
	return in
}

func TestValidSessionTagString_MatchesRegex(t *testing.T) {
	for _, s := range charsetInputs() {
		assert.Equal(t, refTagCharset.MatchString(s), validSessionTagString(s), "input %q", s)
	}
}

func TestValidSessionName_MatchesRegex(t *testing.T) {
	for _, s := range charsetInputs() {
		assert.Equal(t, refSessionChars.MatchString(s), validSessionName(s), "input %q", s)
	}
}

func TestSessionName_FastPathEquivalentToSlowPath(t *testing.T) {
	slow := func(name string) string {
		name = invalidSessionNameChars.ReplaceAllLiteralString(name, "-")
		if len(name) > 64 {
			return name[len(name)-64:]
		}
		return name
	}
	a := &AwsConsumer{}
	inputs := append(charsetInputs(),
		strings.Repeat("a", 64), strings.Repeat("a", 65), strings.Repeat("é", 33), "ok-name_1.2@x=y,z+w",
		strings.Repeat("a", 63)+"/", strings.Repeat("a", 64)+"/",
	)
	for _, s := range inputs {
		assert.Equal(t, slow(s), a.SessionName(context.Background(), s), "input %q", s)
	}
}

func BenchmarkSessionName(b *testing.B) {
	a := &AwsConsumer{}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		a.SessionName(ctx, "aow-acme-api-1234567890")
	}
}

func BenchmarkBuildSessionTags(b *testing.B) {
	raw := map[string]any{"repository": "acme/api", "actor": "octocat", "ref": "refs/heads/main", "run_id": float64(1234567890), "sha": "0123456789abcdef0123456789abcdef01234567"}
	spec := map[string]string{"repo": "repository", "actor": "actor", "ref": "ref", "run": "run_id", "sha": "sha"}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		BuildSessionTags(ctx, raw, spec)
	}
}
