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

	// Boolean groups. Each holds nested conditions evaluated with its own
	// operator; all three are AND'd with the flat fields above and with each
	// other on the same node, so the top level stays an implicit AND and every
	// pre-existing config keeps its exact meaning.
	//
	// These three keys are RESERVED under `conditions:`. Extra is a
	// mapstructure remain-map, so it only ever collected keys no field claimed;
	// a raw claim literally named "all_of"/"any_of"/"none_of" now decodes as a
	// group instead. The only shape that previously worked was a STRING value
	// (Extra is map[string]string and the package registers no decode hooks or
	// WeaklyTypedInput, so a list value never decoded at all) — and such a
	// config now fails to decode loudly rather than changing meaning silently.
	//
	// all_of/any_of/none_of plus nesting is functionally complete (any boolean
	// expression is expressible as nested any_of-of-all_of), which is why there
	// is no `not` (a one-element none_of) and no `xor`.
	AllOf  []*Condition `mapstructure:"all_of"  json:"all_of,omitempty"`  // every member must be satisfied
	AnyOf  []*Condition `mapstructure:"any_of"  json:"any_of,omitempty"`  // at least one member must be satisfied
	NoneOf []*Condition `mapstructure:"none_of" json:"none_of,omitempty"` // no member may be satisfied

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
// Every named field compiles through the same anchored-regex mechanism as
// Extra, so an anchored regex over a literal string matches identically to
// `==` — this is a pure widening, not a behavior change for literal configs.
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
	add := func(claim, pattern string) error {
		if pattern == "" {
			return nil
		}
		re, err := compileAnchoredCondition(pattern)
		if err != nil {
			return fmt.Errorf("%s: invalid pattern for %q: %w", path, claim, err)
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
				return fmt.Errorf("%s: invalid actor_matches pattern %q: %w", path, pattern, err)
			}
			cond.actorPatterns[i] = re
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
// node is compiled, so it reads the compiled form: a field set to "" is not a
// predicate (compileConditionAt skips it), and neither is an Extra entry with
// an empty value.
func conditionIsEmpty(c *Condition) bool {
	return len(c.compiled) == 0 &&
		len(c.actorPatterns) == 0 &&
		len(c.AllOf) == 0 &&
		len(c.AnyOf) == 0 &&
		len(c.NoneOf) == 0
}

// cloneCondition returns a DEEP copy of c with fresh, unshared compiled state.
// The input slices/maps (ActorMatches, Extra) are copied, every nested group
// member is itself cloned, and the derived compiled/actorPatterns fields are
// reset to nil so compileCondition rebuilds them into freshly allocated memory
// rather than reslicing a backing array another snapshot may be reading.
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

// satisfiesConditions reports whether claims satisfy cond. A nil Condition
// always satisfies (no gate).
//
// One node is satisfied when ALL of these hold, in short-circuit order:
//   - every flat leaf (named fields + Extra) matches its claim;
//   - actor_matches, if present, matches on at least one pattern (OR);
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
