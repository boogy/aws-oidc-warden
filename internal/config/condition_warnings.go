package config

import (
	"fmt"
	"log/slog"
	"reflect"
	"strings"

	"github.com/boogy/aws-oidc-warden/internal/types"
)

// This file holds the one advisory check Validate() runs over a condition
// tree: a condition key that names a claim the issuer never issues. Such a key
// can never match, so the mapping simply stops authorizing — fail-closed
// already, but silently, which is precisely the typo worth surfacing. It is
// WARN-only and fires on nothing else: every condition key is spelled exactly
// like its claim, so a correct config is never warned about.

// githubClaimNames is the claim vocabulary of a GitHub Actions OIDC token: every
// json tag on types.Claims (which is what the github provider unmarshals into,
// so it cannot drift from the validator) plus the registered JWT claims it
// embeds and the handful of GitHub claims that have no struct field.
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

// knownClaimsFor returns the claim names a condition on this issuer may
// reasonably reference, or nil when no vocabulary is known — in which case the
// unknown-claim check is skipped entirely.
//
// Only `provider: github` has a fixed vocabulary. A generic issuer's claims are
// whatever its provider mints, so warning there would fire on every legitimate
// condition; its own declared claim names are not a complete set either.
func knownClaimsFor(iss *IssuerConfig) map[string]bool {
	if iss == nil || iss.Provider != "github" {
		return nil
	}
	known := make(map[string]bool, len(githubClaimNames)+8)
	for name := range githubClaimNames {
		known[name] = true
	}
	// A github issuer may still project or require extra claims (e.g. an
	// enterprise-specific one); those are declared, so they are not typos.
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

// warnConditionKeys walks a whole condition tree — nested groups included —
// warning once per unknown claim name. where identifies the mapping (e.g.
// `role_mappings[2] (acme/app)`) and path the node within it, so an operator
// can go straight to the line. known may be nil to skip the unknown-claim
// check.
func warnConditionKeys(cond *Condition, path, where string, known map[string]bool) {
	if cond == nil {
		return
	}

	if known != nil {
		warnUnknownClaims(cond.Claims, path, where, known)
		warnUnknownClaims(cond.ExplicitClaims, path+".claims", where, known)
	}

	warnConditionGroup(cond.AllOf, path, "all_of", where, known)
	warnConditionGroup(cond.AnyOf, path, "any_of", where, known)
	warnConditionGroup(cond.NoneOf, path, "none_of", where, known)
}

// warnUnknownClaims flags a claim name the issuer does not issue — a typo that
// denies silently. prefix is the operator-facing path of the map's own node.
func warnUnknownClaims(claims map[string]Patterns, prefix, where string, known map[string]bool) {
	for claim := range claims {
		if !known[claim] {
			slog.Warn("condition references a claim this issuer does not issue; it can never match — check the spelling",
				slog.String("mapping", where),
				slog.String("key", prefix+"."+claim))
		}
	}
}

func warnConditionGroup(nodes []*Condition, path, name, where string, known map[string]bool) {
	for i, child := range nodes {
		warnConditionKeys(child, fmt.Sprintf("%s.%s[%d]", path, name, i), where, known)
	}
}
