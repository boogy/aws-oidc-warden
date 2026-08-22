package config

import (
	"errors"
	"fmt"
	"regexp"
)

// This file is the condition engine: the shape of a `conditions:` block, how it
// is cloned and compiled at Validate() time, and how it is evaluated against a
// request's raw verified claims. It is deliberately separate from config.go so
// the authorization gate can be read in one sitting.

// Condition defines claim predicates that must be met for a role to be
// assumed. The named fields below are provider-neutral sugar over the same
// generic mechanism: each compiles to an auto-anchored regex checked against
// one raw verified claim (see compileCondition/satisfiesConditions). Extra
// carries arbitrary claimName->regex entries not covered by a named field,
// so `conditions: {my_claim: "regex"}` works without a nested key.
type Condition struct {
	Branch       string   `mapstructure:"branch"        json:"branch,omitempty"`        // Regex against the 'ref' claim (e.g., "main", "dev")
	Ref          string   `mapstructure:"ref"           json:"ref,omitempty"`           // Regex against the 'ref' claim (e.g., "refs/heads/main", "refs/tags/v.*")
	RefType      string   `mapstructure:"ref_type"      json:"ref_type,omitempty"`      // Regex against 'ref_type' (e.g., "branch", "tag")
	EventName    string   `mapstructure:"event_name"    json:"event_name,omitempty"`    // Regex against 'event_name' (e.g., "push", "pull_request")
	WorkflowRef  string   `mapstructure:"workflow_ref"  json:"workflow_ref,omitempty"`  // Regex against 'workflow_ref' (e.g., "owner/repo/.github/workflows/workflow.yml")
	Environment  string   `mapstructure:"environment"   json:"environment,omitempty"`   // Regex against 'runner_environment' (e.g., "production")
	ActorMatches []string `mapstructure:"actor_matches" json:"actor_matches,omitempty"` // Regexes against 'actor'; OR within the list

	// Extra holds generic claimName->regex entries (raw verified claim names)
	// not covered by a named field above. Populated via mapstructure's
	// remain-fields so no nested key is required in config.
	Extra map[string]string `mapstructure:",remain" json:"extra,omitempty"`

	// Cached compiled patterns (not serialized)
	compiled      []compiledCondition `mapstructure:"-" json:"-"` // AND'd claimName/pattern pairs (named single-value fields + Extra)
	actorPatterns []*regexp.Regexp    `mapstructure:"-" json:"-"` // OR'd within this one dimension
}

// compiledCondition is one AND'd (claim name, anchored pattern) pair compiled
// from either a named Condition field or an Extra entry.
type compiledCondition struct {
	claim   string
	pattern *regexp.Regexp
}

// compileCondition compiles every pattern on a Condition (nil is valid: no
// conditions means unconditional match) into the AND'd (claim, pattern) list
// checked by satisfiesConditions. Every named field compiles through the same
// anchored-regex mechanism as Extra, so "same mechanism" (D4) holds even for
// fields that used to be plain string equality (ref_type/event_name/
// environment) — an anchored regex over a literal string matches identically
// to `==`, so this is a pure widening, not a behavior change for existing
// literal configs.
func compileCondition(cond *Condition) error {
	if cond == nil {
		return nil
	}

	cond.compiled = cond.compiled[:0]
	add := func(claim, pattern string) error {
		if pattern == "" {
			return nil
		}
		re, err := compileAnchoredCondition(pattern)
		if err != nil {
			return fmt.Errorf("invalid pattern for %q: %w", claim, err)
		}
		cond.compiled = append(cond.compiled, compiledCondition{claim: claim, pattern: re})
		return nil
	}

	// NOTE: Branch and Ref intentionally both check the raw "ref" claim; this
	// mirrors pre-existing behavior.
	if err := add("ref", cond.Branch); err != nil {
		return err
	}
	if err := add("ref", cond.Ref); err != nil {
		return err
	}
	if err := add("ref_type", cond.RefType); err != nil {
		return err
	}
	if err := add("event_name", cond.EventName); err != nil {
		return err
	}
	if err := add("workflow_ref", cond.WorkflowRef); err != nil {
		return err
	}
	if err := add("runner_environment", cond.Environment); err != nil {
		return err
	}

	for claim, pattern := range cond.Extra {
		if err := add(claim, pattern); err != nil {
			return err
		}
	}

	if len(cond.ActorMatches) > 0 {
		cond.actorPatterns = make([]*regexp.Regexp, len(cond.ActorMatches))
		for i, pattern := range cond.ActorMatches {
			re, err := compileAnchoredCondition(pattern)
			if err != nil {
				return fmt.Errorf("invalid actor_matches pattern %q: %w", pattern, err)
			}
			cond.actorPatterns[i] = re
		}
	}

	return nil
}

// cloneCondition returns a deep copy of c with fresh, unshared compiled state.
// The input slices/maps (ActorMatches, Extra) are copied so the clone shares no
// backing storage with c, and the derived compiled/actorPatterns fields are
// reset to nil so compileCondition rebuilds them into freshly allocated memory
// rather than reslicing a backing array another snapshot may be reading.
// Returns nil for a nil input (a mapping with no conditions).
func cloneCondition(c *Condition) *Condition {
	if c == nil {
		return nil
	}
	nc := *c
	nc.compiled = nil
	nc.actorPatterns = nil
	if c.ActorMatches != nil {
		nc.ActorMatches = append([]string(nil), c.ActorMatches...)
	}
	if c.Extra != nil {
		nc.Extra = make(map[string]string, len(c.Extra))
		for k, v := range c.Extra {
			nc.Extra[k] = v
		}
	}
	return &nc
}

// bareWildcards are patterns that match every possible value. They must never
// gate an authorization decision — as a condition OR as a subject — because
// they reduce that gate to "always true".
//
// This is a literal check on the two shapes operators actually reach for, not
// a general "does this regex match everything" analysis: that is not something
// we can decide cheaply, and a determined operator can still write an
// equivalent pattern (`(.*)`, `.*.*`, `[\s\S]*`). It closes the documented
// footgun and makes the accident loud; it is not a proof of specificity.
var bareWildcards = map[string]bool{".*": true, ".+": true}

// compileAnchoredCondition compiles pattern as an auto-anchored regex,
// rejecting empty patterns and bare wildcards that would match anything
// (security conditions must be specific, never `.*`).
func compileAnchoredCondition(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, errors.New("pattern must not be empty")
	}
	if bareWildcards[pattern] {
		return nil, fmt.Errorf("pattern %q is too permissive; use a specific pattern", pattern)
	}
	return regexp.Compile("^(?:" + pattern + ")$")
}

// valueMatches reports whether one raw verified claim VALUE satisfies pattern
// (already anchored at compile time).
//
// A string value matches when the pattern matches it. An ARRAY value — a
// GitLab/Okta/Entra group, scope, or role list — matches when ANY string
// element matches; this is the only place list semantics exist on the claim
// side, and it is deliberately ANY rather than ALL, since "the caller is in
// group X" is what a list claim means.
//
// Every other shape denies: a nil (absent or null), a number, a bool, an
// object, and a non-string element inside an array. Conditions gate an
// authorization decision, so an unmatched or unexpected shape is false, never
// true. Numbers stay unmatched on purpose — regexing a float64 would mean
// operators writing patterns against Go's %v rendering of a JSON number.
//
// Cost is bounded without an element cap: the token is already length-capped
// upstream by max_token_bytes (default 8192), so the number of array elements
// a request can carry is bounded by the same limit that bounds the claim set.
func valueMatches(v any, pattern *regexp.Regexp) bool {
	switch t := v.(type) {
	case string:
		return pattern.MatchString(t)
	case []any:
		for _, el := range t {
			if s, ok := el.(string); ok && pattern.MatchString(s) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// claimMatches looks the named claim up and applies valueMatches. Call sites
// that check several patterns against the SAME claim (actor_matches) should
// hoist the lookup and call valueMatches directly instead of calling this in a
// loop, so the map lookup and the type switch happen once.
func claimMatches(claims map[string]any, claim string, pattern *regexp.Regexp) bool {
	return valueMatches(claims[claim], pattern)
}

// satisfiesConditions reports whether claims satisfy every AND'd condition
// (both the named-field conditions and any generic Extra entries), plus the
// OR'd actor_matches dimension. A nil Condition always satisfies (no gate).
func satisfiesConditions(cond *Condition, claims map[string]any) bool {
	if cond == nil {
		return true
	}

	for _, cc := range cond.compiled {
		if !claimMatches(claims, cc.claim, cc.pattern) {
			return false
		}
	}

	if len(cond.actorPatterns) > 0 {
		actor := claims["actor"] // hoisted: one lookup + one type switch, as today
		matched := false
		for _, pattern := range cond.actorPatterns {
			if valueMatches(actor, pattern) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}
