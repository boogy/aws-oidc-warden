package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Patterns that only compile once wrapped in "^(?:...)$" would escape the anchor.
var anchorEscapes = []string{
	`refs/heads/main)|(x`,
	`org/repo)|(.*`,
	`a)(b`,
	`(a`,
	`a)`,
}

func TestAnchorRejectsUnbalancedPatterns(t *testing.T) {
	for _, p := range anchorEscapes {
		t.Run(p, func(t *testing.T) {
			_, err := regexCache{}.anchor(p)
			require.Error(t, err)
			_, err = regexCache(nil).anchor(p)
			require.Error(t, err)
		})
	}
}

func TestSubjectPatternCannotEscapeAnchor(t *testing.T) {
	for _, p := range anchorEscapes {
		t.Run(p, func(t *testing.T) {
			err := wildcardCfg(p).Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid subject pattern")
		})
	}
}

func TestConditionPatternCannotEscapeAnchor(t *testing.T) {
	for _, p := range anchorEscapes {
		t.Run(p, func(t *testing.T) {
			cfg := wildcardCfg("acme/repo")
			cfg.RoleMappings[0].Conditions = &Condition{Ref: Patterns{p}}
			err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid pattern")

			cfg = wildcardCfg("acme/repo")
			cfg.RoleMappings[0].Conditions = &Condition{NoneOf: []*Condition{{Claims: map[string]Patterns{"x": {p}}}}}
			require.Error(t, cfg.Validate())
		})
	}
}

func TestAnchorStillAcceptsValidPatterns(t *testing.T) {
	for _, p := range []string{`refs/heads/main`, `(a|b)`, `a|b`, `(?i)acme/.*`, `refs/tags/v[0-9]+\.[0-9]+`} {
		m, err := regexCache{}.anchor(p)
		require.NoError(t, err, p)
		assert.False(t, m.match("zzz/evil"), p)
	}
}

var universalPatterns = []string{
	`.*`, `.+`, `.*.*`, `(?s).*`, `[\s\S]*`, `[\d\D]+`, `(.*)`, `(?:.*)?`, `.{0,}`, `.{1,}`,
	`^.*$`, `a|.*`, `(.+)+`, `(?i).*`, `.*?`, `(?s:.+)`, `[^\n]*`, `(?:)(.*)`, `(a|.*)`,
}

var specificPatterns = []string{
	`repo:org/.*`, `.*@x\.com`, `[^@]*`, `.{2,}`, `.`, `.?`, `a*`, `a|b`, `x.*|y.*`, `.*x`,
	`(?i)acme/.*`, `[a-z]*`, `.{0,5}`, `.*/shared-lib`, `^acme$`, `\d+`,
}

func TestIsUniversalAST(t *testing.T) {
	for _, p := range universalPatterns {
		re, err := parsePattern(p)
		require.NoError(t, err, p)
		assert.True(t, isUniversal(re), "%q should be universal", p)
	}
	for _, p := range specificPatterns {
		re, err := parsePattern(p)
		require.NoError(t, err, p)
		assert.False(t, isUniversal(re), "%q should not be universal", p)
	}
}

func TestUniversalPatternsRejectedEverywhere(t *testing.T) {
	for _, p := range universalPatterns {
		t.Run(p, func(t *testing.T) {
			err := wildcardCfg(p).Validate()
			require.Error(t, err, "subject")
			assert.Contains(t, err.Error(), "too permissive")

			cfg := wildcardCfg("acme/repo")
			cfg.RoleMappings[0].Conditions = &Condition{Ref: Patterns{p}}
			err = cfg.Validate()
			require.Error(t, err, "condition")
			assert.Contains(t, err.Error(), "too permissive")

			cfg = wildcardCfg("acme/repo")
			cfg.RoleMappings[0].Conditions = &Condition{AnyOf: []*Condition{{Claims: map[string]Patterns{"x": {"y", p}}}}}
			require.Error(t, cfg.Validate(), "nested condition list")
		})
	}
}

func TestSpecificPatternsStillAccepted(t *testing.T) {
	for _, p := range specificPatterns {
		t.Run(p, func(t *testing.T) {
			require.NoError(t, wildcardCfg(p).Validate(), "subject")

			cfg := wildcardCfg("acme/repo")
			cfg.RoleMappings[0].Conditions = &Condition{Ref: Patterns{p}}
			require.NoError(t, cfg.Validate(), "condition")
		})
	}
}
