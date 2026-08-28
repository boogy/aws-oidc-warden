package config

import (
	"fmt"
	"log/slog"
	"reflect"
	"strings"

	"github.com/boogy/aws-oidc-warden/internal/types"
)

// This file holds Validate()'s one advisory check: a condition key naming a
// claim the issuer never issues (WARN-only, typo detection).

// githubClaimNames is the claim vocabulary of a GitHub Actions OIDC token:
// every json tag on types.Claims (what the github provider unmarshals into)
// plus GitHub claims with no struct field.
var githubClaimNames = buildGitHubClaimNames()

func buildGitHubClaimNames() map[string]bool {
	names := make(map[string]bool, 32)
	var walk func(reflect.Type)
	walk = func(t reflect.Type) {
		for i := range t.NumField() {
			f := t.Field(i)
			if f.Anonymous && f.Type.Kind() == reflect.Struct {
				walk(f.Type)
				continue
			}
			tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if tag != "" && tag != "-" {
				names[tag] = true
			}
		}
	}
	walk(reflect.TypeOf(types.Claims{}))

	// Claims GitHub issues that types.Claims does not model as a field.
	for _, extra := range []string{"environment", "enterprise", "enterprise_id", "issuer_scope"} {
		names[extra] = true
	}
	return names
}

// knownClaimsFor returns the claim vocabulary for the unknown-claim check, or
// nil to skip it. Only `provider: github` has a fixed vocabulary; a generic
// issuer's claims are whatever its provider mints.
func knownClaimsFor(iss *IssuerConfig) map[string]bool {
	if iss == nil || iss.Provider != "github" {
		return nil
	}
	known := make(map[string]bool, len(githubClaimNames)+8)
	for name := range githubClaimNames {
		known[name] = true
	}
	for _, claim := range iss.ClaimMappings {
		known[claim] = true
	}
	for _, claim := range iss.RequiredClaims {
		known[claim] = true
	}
	for _, claim := range iss.SessionTags {
		known[claim] = true
	}
	return known
}

// warnConditionKeys walks a whole condition tree warning once per unknown
// claim name. where identifies the mapping, path the node within it.
func warnConditionKeys(cond *Condition, path, where string, known map[string]bool) {
	warnConditionKeysAt(cond, path, where, known, false)
}

// warnConditionKeysAt tracks underNoneOf: a typo there is a veto that can
// never fire (fail-open), vs. never-matches (fail-closed) elsewhere.
func warnConditionKeysAt(cond *Condition, path, where string, known map[string]bool, underNoneOf bool) {
	if cond == nil {
		return
	}

	if known != nil {
		warnUnknownClaims(cond.Claims, path, where, known, underNoneOf)
		warnUnknownClaims(cond.ExplicitClaims, path+".claims", where, known, underNoneOf)
	}

	warnConditionGroup(cond.AllOf, path, "all_of", where, known, underNoneOf)
	warnConditionGroup(cond.AnyOf, path, "any_of", where, known, underNoneOf)
	warnConditionGroup(cond.NoneOf, path, "none_of", where, known, true)
}

// warnUnknownClaims flags a claim name the issuer does not issue.
func warnUnknownClaims(claims map[string]Patterns, prefix, where string, known map[string]bool, underNoneOf bool) {
	msg := "condition references a claim this issuer does not issue; it can never match — check the spelling"
	if underNoneOf {
		msg = "none_of references a claim this issuer does not issue; it can never match, so this member can never veto and the mapping authorizes what it was meant to refuse — check the spelling"
	}
	for _, claim := range sortedKeys(claims) {
		if !known[claim] {
			slog.Warn(msg,
				slog.String("mapping", where),
				slog.String("key", prefix+"."+claim))
		}
	}
}

func warnConditionGroup(nodes []*Condition, path, name, where string, known map[string]bool, underNoneOf bool) {
	for i, child := range nodes {
		warnConditionKeysAt(child, fmt.Sprintf("%s.%s[%d]", path, name, i), where, known, underNoneOf)
	}
}
