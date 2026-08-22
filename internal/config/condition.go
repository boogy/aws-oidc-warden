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
// assumed. There is ONE mechanism: every key under `conditions:` other than
// the three reserved boolean groups names a raw verified claim, and its value
// is one regex pattern or a list of patterns OR'd together. Keys are spelled
// exactly like the claim they check (`repository`, `actor`, `project_path`,
// `groups`), which is what makes the same syntax work for GitHub and for any
// other issuer without new struct fields.
//
// The named fields below exist only so the most common GitHub claims are
// discoverable in code and docs; they compile to exactly what an entry in
// Claims compiles to. The three deprecated keys are the one exception — they
// are spelled differently from the claim they check, which is why they are
// deprecated (see deprecatedConditionKeys).
type Condition struct {
	Ref         Patterns `mapstructure:"ref"          json:"ref,omitempty"`          // Patterns against the 'ref' claim (e.g., "refs/heads/main", "refs/tags/v.*")
	RefType     Patterns `mapstructure:"ref_type"     json:"ref_type,omitempty"`     // Patterns against 'ref_type' (e.g., "branch", "tag")
	EventName   Patterns `mapstructure:"event_name"   json:"event_name,omitempty"`   // Patterns against 'event_name' (e.g., "push", "pull_request")
	WorkflowRef Patterns `mapstructure:"workflow_ref" json:"workflow_ref,omitempty"` // Patterns against 'workflow_ref' (e.g., "owner/repo/.github/workflows/release.yml@.*")

	// Deprecated keys. Each keeps its exact pre-2.5.0 meaning; Validate()
	// warns and names the replacement. See deprecatedConditionKeys.
	Branch       Patterns `mapstructure:"branch"        json:"branch,omitempty"`        // Deprecated: use `ref` (checks the same 'ref' claim)
	Environment  Patterns `mapstructure:"environment"   json:"environment,omitempty"`   // Deprecated: use `runner_environment` (the claim it actually checks)
	ActorMatches Patterns `mapstructure:"actor_matches" json:"actor_matches,omitempty"` // Deprecated: use `actor` (a list is OR'd there too)

	// Boolean groups. Each holds nested conditions evaluated with its own
	// operator; all three are AND'd with the flat fields above and with each
	// other on the same node, so the top level stays an implicit AND and every
	// pre-existing config keeps its exact meaning.
	//
	// These three keys are RESERVED under `conditions:`. Claims is a
	// mapstructure remain-map, so it only ever collected keys no field claimed;
	// a raw claim literally named "all_of"/"any_of"/"none_of" decodes as a
	// group instead.
	//
	// all_of/any_of/none_of plus nesting is functionally complete (any boolean
	// expression is expressible as nested any_of-of-all_of), which is why there
	// is no `not` (a one-element none_of) and no `xor`.
	AllOf  []*Condition `mapstructure:"all_of"  json:"all_of,omitempty"`  // every member must be satisfied
	AnyOf  []*Condition `mapstructure:"any_of"  json:"any_of,omitempty"`  // at least one member must be satisfied
	NoneOf []*Condition `mapstructure:"none_of" json:"none_of,omitempty"` // no member may be satisfied

	// Claims holds every claimName->patterns entry not covered by a named
	// field above, keyed by the RAW verified claim name. Populated via
	// mapstructure's remain-fields, so `conditions: {project_path: "grp/prj"}`
	// works with no nested key and no provider-specific schema.
	Claims map[string]Patterns `mapstructure:",remain" json:"claims,omitempty"`

	// Cached compiled patterns (not serialized): one entry per claim, AND'd.
	compiled []compiledCondition `mapstructure:"-" json:"-"`
}

// compiledCondition is one claim's compiled predicate: the anchored patterns
// are OR'd with each other, and every compiledCondition on a node is AND'd.
type compiledCondition struct {
	claim    string
	patterns []*regexp.Regexp
}

const (
	// maxConditionDepth bounds how deeply boolean groups may nest. The
	// top-level `conditions:` block is depth 1, each nested group adds one.
	//
	// The cap exists for readability first and cost second. A gate a reviewer
	// cannot hold in their head is a gate nobody reviews, and five levels is
	// already more structure than any real authorization rule needs. It also
	// keeps satisfiesConditions' recursion depth a property of this constant
	// rather than of a config file.
	maxConditionDepth = 5

	// maxConditionNodes bounds the total number of condition nodes in ONE
	// mapping's tree. Depth alone does not bound the work: a single any_of can
	// list arbitrarily many members, and every candidate mapping is evaluated
	// on every request. This keeps the per-request cost of the authorization
	// gate bounded by a constant the code owns.
	maxConditionNodes = 64
)

// compileCondition compiles every pattern on a condition tree (nil is valid: no
// conditions means unconditional match) into the pre-compiled form checked by
// satisfiesConditions. Called once per effective mapping at Validate() time,
// never per request.
func compileCondition(cond *Condition) error {
	budget := 0
	return compileConditionAt(cond, "conditions", 1, &budget)
}

// compileConditionAt compiles one node of the condition tree and recurses into
// its groups. path is the operator-facing location of this node (e.g.
// "conditions.any_of[1].all_of[0]") and appears in every error, so a rejected
// config names the exact entry to fix. depth is 1 for the top-level node.
// budget counts nodes compiled so far across the whole tree.
//
// Every named field compiles through the same anchored-regex mechanism as a
// generic claim entry, so an anchored regex over a literal string matches
// identically to `==` — a pure widening, not a behavior change for literal
// configs.
func compileConditionAt(cond *Condition, path string, depth int, budget *int) error {
	if cond == nil {
		return nil
	}
	if depth > maxConditionDepth {
		return fmt.Errorf("%s: exceeds the maximum condition nesting depth of %d levels; flatten the expression", path, maxConditionDepth)
	}
	*budget++
	if *budget > maxConditionNodes {
		return fmt.Errorf("%s: more than %d condition nodes in one mapping; split it across mappings or simplify the expression", path, maxConditionNodes)
	}

	cond.compiled = cond.compiled[:0]
	// key is the config key being compiled and claim the raw verified claim it
	// checks; the two differ only for the deprecated keys, and errors quote the
	// key the operator actually wrote.
	add := func(key, claim string, patterns Patterns) error {
		if patterns == nil {
			return nil
		}
		if len(patterns) == 0 {
			return fmt.Errorf("%s: %q must list at least one pattern", path, key)
		}
		compiled := make([]*regexp.Regexp, 0, len(patterns))
		for _, pattern := range patterns {
			re, err := compileAnchoredCondition(pattern)
			if err != nil {
				return fmt.Errorf("%s: invalid pattern for %q: %w", path, key, err)
			}
			compiled = append(compiled, re)
		}
		cond.compiled = append(cond.compiled, compiledCondition{claim: claim, patterns: compiled})
		return nil
	}

	// NOTE: `branch` and `ref` intentionally both check the raw "ref" claim,
	// and `environment` checks "runner_environment"; this mirrors pre-existing
	// behavior. Both spellings on one node are AND'd like any two claims.
	if err := add("branch", "ref", cond.Branch); err != nil {
		return err
	}
	if err := add("ref", "ref", cond.Ref); err != nil {
		return err
	}
	if err := add("ref_type", "ref_type", cond.RefType); err != nil {
		return err
	}
	if err := add("event_name", "event_name", cond.EventName); err != nil {
		return err
	}
	if err := add("workflow_ref", "workflow_ref", cond.WorkflowRef); err != nil {
		return err
	}
	if err := add("environment", "runner_environment", cond.Environment); err != nil {
		return err
	}
	if err := add("actor_matches", "actor", cond.ActorMatches); err != nil {
		return err
	}

	for claim, patterns := range cond.Claims {
		if err := add(claim, claim, patterns); err != nil {
			return err
		}
	}

	if err := compileGroup("all_of", cond.AllOf, path, depth, budget); err != nil {
		return err
	}
	if err := compileGroup("any_of", cond.AnyOf, path, depth, budget); err != nil {
		return err
	}
	return compileGroup("none_of", cond.NoneOf, path, depth, budget)
}

// compileGroup compiles one boolean group's members and rejects the two shapes
// that would defeat the gate they appear in:
//
//   - an empty list (`any_of: []`) — vacuously false for any_of, vacuously true
//     for all_of/none_of, and in neither case what the operator meant;
//   - a member that declares no predicate (`- {}` or a null entry) — always
//     true, so a single one makes an any_of always pass and a none_of always
//     fail. An empty TOP-LEVEL condition stays legal (it has always meant "no
//     gate", identical to omitting the key); only group members are rejected.
func compileGroup(name string, nodes []*Condition, path string, depth int, budget *int) error {
	if nodes == nil {
		return nil
	}
	if len(nodes) == 0 {
		return fmt.Errorf("%s.%s: must list at least one condition", path, name)
	}
	for i, child := range nodes {
		childPath := fmt.Sprintf("%s.%s[%d]", path, name, i)
		if child == nil {
			return fmt.Errorf("%s: declares no predicate; an empty condition is always true and would defeat the %s it is in", childPath, name)
		}
		if err := compileConditionAt(child, childPath, depth+1, budget); err != nil {
			return err
		}
		if conditionIsEmpty(child) {
			return fmt.Errorf("%s: declares no predicate; an empty condition is always true and would defeat the %s it is in", childPath, name)
		}
	}
	return nil
}

// conditionIsEmpty reports whether c gates nothing at all. Called AFTER the
// node is compiled, so it reads the compiled form: an absent key is not a
// predicate, and an empty pattern list never compiles (compileConditionAt
// rejects it).
func conditionIsEmpty(c *Condition) bool {
	return len(c.compiled) == 0 &&
		len(c.AllOf) == 0 &&
		len(c.AnyOf) == 0 &&
		len(c.NoneOf) == 0
}

// cloneCondition returns a DEEP copy of c with fresh, unshared compiled state.
// The input pattern lists and the Claims map are copied, every nested group
// member is itself cloned, and the derived compiled field is reset to nil so
// compileCondition rebuilds it into freshly allocated memory rather than
// reslicing a backing array another snapshot may be reading.
// Returns nil for a nil input (a mapping with no conditions).
//
// The recursion is load-bearing, not tidiness: a shallow copy would leave every
// nested node shared across snapshots, and compileConditionAt mutates each node
// in place. A concurrent reader could then observe a nested node's compiled
// list transiently empty — and an empty node is TRUE, so the whole gate would
// silently pass. See TestHotReloadNestedConditionRace.
func cloneCondition(c *Condition) *Condition {
	if c == nil {
		return nil
	}
	nc := *c
	nc.compiled = nil
	nc.Ref = clonePatterns(c.Ref)
	nc.RefType = clonePatterns(c.RefType)
	nc.EventName = clonePatterns(c.EventName)
	nc.WorkflowRef = clonePatterns(c.WorkflowRef)
	nc.Branch = clonePatterns(c.Branch)
	nc.Environment = clonePatterns(c.Environment)
	nc.ActorMatches = clonePatterns(c.ActorMatches)
	if c.Claims != nil {
		nc.Claims = make(map[string]Patterns, len(c.Claims))
		for k, v := range c.Claims {
			nc.Claims[k] = clonePatterns(v)
		}
	}
	nc.AllOf = cloneConditions(c.AllOf)
	nc.AnyOf = cloneConditions(c.AnyOf)
	nc.NoneOf = cloneConditions(c.NoneOf)
	return &nc
}

// cloneConditions deep-copies one group's members. It preserves the nil vs
// empty-slice distinction: nil means the key was absent (no gate), an empty
// non-nil slice means the operator wrote `any_of: []`, which compileGroup
// rejects.
func cloneConditions(in []*Condition) []*Condition {
	if in == nil {
		return nil
	}
	out := make([]*Condition, len(in))
	for i, c := range in {
		out[i] = cloneCondition(c)
	}
	return out
}

// clonePatterns copies one claim's pattern list, preserving the nil vs
// empty-slice distinction (nil means the key was absent; an empty non-nil
// slice means the operator wrote `ref: []`, which compileConditionAt rejects).
func clonePatterns(in Patterns) Patterns {
	if in == nil {
		return nil
	}
	// make+copy, not append(nil, ...): appending zero elements to a nil slice
	// yields nil, which would turn a rejected `ref: []` into an absent key.
	out := make(Patterns, len(in))
	copy(out, in)
	return out
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

// claimMatches looks the named claim up and reports whether ANY of the entry's
// patterns match it. The lookup is hoisted out of the pattern loop so the map
// access happens once per claim, not once per pattern.
func claimMatches(claims map[string]any, cc compiledCondition) bool {
	v := claims[cc.claim]
	for _, pattern := range cc.patterns {
		if valueMatches(v, pattern) {
			return true
		}
	}
	return false
}

// satisfiesConditions reports whether claims satisfy cond. A nil Condition
// always satisfies (no gate).
//
// One node is satisfied when ALL of these hold, in short-circuit order:
//   - every flat leaf matches its claim on at least one of its patterns
//     (OR within one claim's list, AND across claims);
//   - every all_of member is satisfied;
//   - at least one any_of member is satisfied, if any_of is present;
//   - no none_of member is satisfied.
//
// none_of is exact negation: a member naming an ABSENT claim cannot match, so
// its negation holds and the none_of passes.
//
// The walk allocates nothing and compiles nothing — every pattern was compiled
// at Validate() time — and its depth is bounded by the config, never by request
// input.
func satisfiesConditions(cond *Condition, claims map[string]any) bool {
	if cond == nil {
		return true
	}

	for _, cc := range cond.compiled {
		if !claimMatches(claims, cc) {
			return false
		}
	}

	for _, child := range cond.AllOf {
		if !satisfiesConditions(child, claims) {
			return false
		}
	}

	if len(cond.AnyOf) > 0 {
		matched := false
		for _, child := range cond.AnyOf {
			if satisfiesConditions(child, claims) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	for _, child := range cond.NoneOf {
		if satisfiesConditions(child, claims) {
			return false
		}
	}

	return true
}
