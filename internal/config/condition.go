package config

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
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
// Claims compiles to, and every one of them is spelled exactly like its claim.
type Condition struct {
	Ref               Patterns `mapstructure:"ref"                json:"ref,omitempty"`                // Patterns against the 'ref' claim (e.g., "refs/heads/main", "refs/tags/v.*")
	RefType           Patterns `mapstructure:"ref_type"           json:"ref_type,omitempty"`           // Patterns against 'ref_type' (e.g., "branch", "tag")
	EventName         Patterns `mapstructure:"event_name"         json:"event_name,omitempty"`         // Patterns against 'event_name' (e.g., "push", "pull_request")
	WorkflowRef       Patterns `mapstructure:"workflow_ref"       json:"workflow_ref,omitempty"`       // Patterns against 'workflow_ref' (e.g., "owner/repo/.github/workflows/release.yml@.*")
	Actor             Patterns `mapstructure:"actor"              json:"actor,omitempty"`              // Patterns against 'actor' (the principal that triggered the run)
	RunnerEnvironment Patterns `mapstructure:"runner_environment" json:"runner_environment,omitempty"` // Patterns against 'runner_environment' ("github-hosted", "self-hosted")
	Environment       Patterns `mapstructure:"environment"        json:"environment,omitempty"`        // Patterns against 'environment' (the deployment environment a job declares)

	// Boolean groups. Each holds nested conditions evaluated with its own
	// operator; all three are AND'd with the flat fields above and with each
	// other on the same node, so the top level stays an implicit AND and every
	// pre-existing config keeps its exact meaning.
	//
	// These three keys are RESERVED under `conditions:`. Claims is a
	// mapstructure remain-map, so it only ever collected keys no field claimed;
	// a raw claim literally named "all_of"/"any_of"/"none_of" decodes as a
	// group instead, and is reachable under `claims:`.
	//
	// all_of/any_of/none_of plus nesting is functionally complete (any boolean
	// expression is expressible as nested any_of-of-all_of), which is why there
	// is no `not` (a one-element none_of) and no `xor`.
	AllOf  []*Condition `mapstructure:"all_of"  json:"all_of,omitempty"`  // every member must be satisfied
	AnyOf  []*Condition `mapstructure:"any_of"  json:"any_of,omitempty"`  // at least one member must be satisfied
	NoneOf []*Condition `mapstructure:"none_of" json:"none_of,omitempty"` // no member may be satisfied

	// ExplicitClaims holds the entries written under the reserved `claims:`
	// key. They mean exactly what a top-level entry means — claim name to
	// patterns — with one difference: no key is ever read as anything but a
	// raw claim name. That is the escape hatch for a claim whose name collides
	// with a key this schema reserves: `all_of`, `any_of`, `none_of`, and
	// `claims` itself. Nothing else needs it, since every other key already IS
	// its claim name.
	ExplicitClaims map[string]Patterns `mapstructure:"claims" json:"explicit_claims,omitempty"`

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
	// checks; the two differ only under claims: (key "claims.x", claim "x"), and
	// errors quote the key the operator actually wrote.
	add := func(key, claim string, patterns Patterns) error {
		if patterns == nil {
			return nil
		}
		if claim == "" {
			return fmt.Errorf("%s: a condition key must name a claim; the empty key is not a claim name", path)
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
	if err := add("actor", "actor", cond.Actor); err != nil {
		return err
	}
	if err := add("runner_environment", "runner_environment", cond.RunnerEnvironment); err != nil {
		return err
	}
	if err := add("environment", "environment", cond.Environment); err != nil {
		return err
	}

	// Both maps are walked in sorted key order. Map iteration order is random,
	// and without this the compiled order — and, more importantly, WHICH bad
	// entry a config with two of them reports — would differ run to run, so the
	// same broken config could produce a different error on each restart.
	//
	// A key present in the map with a nil value is `repository:` written with
	// nothing after it. add() treats nil as "not written" — correct for the
	// named fields above, where absent and nil are indistinguishable — so the
	// map keys are checked here, where presence IS observable. Left alone it
	// would compile to no predicate at all and silently widen the gate.
	for _, claim := range sortedKeys(cond.Claims) {
		if cond.Claims[claim] == nil {
			return errNoPatternForKey(path, claim)
		}
		if err := add(claim, claim, cond.Claims[claim]); err != nil {
			return err
		}
	}
	for _, claim := range sortedKeys(cond.ExplicitClaims) {
		if cond.ExplicitClaims[claim] == nil {
			return errNoPatternForKey(path, "claims."+claim)
		}
		if err := add("claims."+claim, claim, cond.ExplicitClaims[claim]); err != nil {
			return err
		}
	}

	if err := compileGroup("all_of", cond.AllOf, path, depth, budget); err != nil {
		return err
	}
	if err := compileGroup("any_of", cond.AnyOf, path, depth, budget); err != nil {
		return err
	}
	if err := compileGroup("none_of", cond.NoneOf, path, depth, budget); err != nil {
		return err
	}

	// A top-level node that gates nothing is rejected for the same reason a
	// group member that gates nothing is: it authorizes unconditionally. The
	// check has to be here, on the aggregate, because a named field written
	// with no value (`environment:`) decodes to exactly the same zero value as
	// a field that was never written, so the only place the mistake is visible
	// is that the whole block compiled to no predicate. Writing `conditions: {}`
	// deliberately is the same mistake typed on purpose: drop the key.
	if depth == 1 && conditionIsEmpty(cond) {
		return fmt.Errorf("%s: declares no predicate, so it would authorize every request that reaches it; remove the `conditions` key if the mapping is meant to be unconditional, or give the key you wrote a pattern", path)
	}
	return nil
}

// errNoPatternForKey reports a condition key written with no value at all.
// Distinct from the empty-list error: `repository: []` says "match nothing"
// and `repository:` says nothing at all, but both compile to no predicate,
// which is the one thing a gate must never do by accident.
func errNoPatternForKey(path, key string) error {
	return fmt.Errorf("%s: %q has no value; a condition key with no pattern gates nothing — give it a pattern or remove the key", path, key)
}

// sortedKeys returns m's keys in lexical order. Compilation walks the claim
// maps through it so error reporting is reproducible; it runs at Validate()
// time only, never per request.
func sortedKeys(m map[string]Patterns) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// compileGroup compiles one boolean group's members and rejects the two shapes
// that would defeat the gate they appear in:
//
//   - an empty list (`any_of: []`) — vacuously false for any_of, vacuously true
//     for all_of/none_of, and in neither case what the operator meant;
//   - a member that declares no predicate (`- {}` or a null entry) — always
//     true, so a single one makes an any_of always pass and a none_of always
//     fail.
//
// compileConditionAt applies the same no-predicate check to the top-level node
// once its groups are compiled, so `conditions: {}` is rejected too.
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
	nc.Actor = clonePatterns(c.Actor)
	nc.RunnerEnvironment = clonePatterns(c.RunnerEnvironment)
	nc.Environment = clonePatterns(c.Environment)
	nc.Claims = cloneClaimMap(c.Claims)
	nc.ExplicitClaims = cloneClaimMap(c.ExplicitClaims)
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

// cloneClaimMap deep-copies one claimName->patterns map, preserving the nil vs
// empty-map distinction so a cloned snapshot decodes and compiles identically.
func cloneClaimMap(in map[string]Patterns) map[string]Patterns {
	if in == nil {
		return nil
	}
	out := make(map[string]Patterns, len(in))
	for k, v := range in {
		out[k] = clonePatterns(v)
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

// foldedClaim is one entry of the case-folded claim index: the value, plus how
// many raw claims fold to that name. n > 1 is a collision, and a collision
// denies — see claimResolver.
type foldedClaim struct {
	value any
	n     int
}

// claimResolver resolves a compiled condition key to the token's claim value.
//
// It exists because the config loader cannot preserve the case an operator
// wrote. Viper lowercases every key it reads, from the main file, from
// MergeBytes, and from every fragment, so `isContractor:` reaches the compiler
// as `iscontractor` no matter how it was spelled. A plain map lookup against
// the raw claims would then miss the claim entirely — and a leaf that resolves
// to "no value" is not merely a denial: under none_of it is a veto that can
// never fire, which authorizes exactly what the config was written to refuse.
// GitHub never exposed this because every GitHub Actions claim is already
// lowercase; any issuer that mints camelCase claims does.
//
// Resolution is collision-first, then exact, then case-folded:
//   - if two or more raw claims fold to the key, the lookup is ambiguous and
//     the whole evaluation denies. This is checked BEFORE the exact match,
//     which is the whole point: the key reaching this code is already
//     lower-cased, so `iscontractor` may be what the operator wrote or may be
//     what `isContractor` was folded into. When a token carries both spellings
//     there is no way to tell which claim the config meant, and preferring the
//     exact one silently picks a claim the operator may never have named. That
//     is not academic — with `none_of` it disarms the veto, so a token that
//     adds a lower-case twin of the vetoed claim is authorized outright.
//   - otherwise a claim whose name matches the key exactly wins;
//   - otherwise the single claim that folds to the key is used.
//
// The original case is unrecoverable by the time the compiler sees the key, so
// guessing between two candidates is the one thing a gate must not do.
//
// Cost: the folded index is built at most once per authorization call, and not
// at all unless some raw claim name actually carries an upper-case letter. A
// token whose claim names are all lower-case — every GitHub Actions token —
// takes a scan that allocates nothing and then the same single map access it
// always made.
type claimResolver struct {
	raw    map[string]any
	folded map[string]foldedClaim // nil unless some claim name is mixed-case
	built  bool                   // folded has been computed (it may stay nil)
	// ambiguous records that some lookup during this evaluation hit a name two
	// differently-cased claims fold to. It is sticky for the whole walk: see
	// satisfiesConditions for why it cannot be handled at the leaf.
	ambiguous bool
}

func newClaimResolver(claims map[string]any) *claimResolver {
	return &claimResolver{raw: claims}
}

// lookup returns the value for claim name, or nil when no claim resolves to it.
// A name two differently-cased claims fold to sets r.ambiguous, which denies
// the whole evaluation once the walk finishes.
func (r *claimResolver) lookup(name string) any {
	if !r.built {
		r.buildFolded()
	}
	if r.folded != nil {
		// Collision check first, and deliberately not skipped when the exact
		// lookup below would succeed: an exact hit alongside a differently
		// cased twin is still two candidate claims for one folded key.
		if e := r.folded[strings.ToLower(name)]; e.n > 1 {
			r.ambiguous = true
		}
	}
	if v, ok := r.raw[name]; ok {
		return v
	}
	if r.folded == nil {
		return nil
	}
	if e := r.folded[strings.ToLower(name)]; e.n == 1 {
		return e.value
	}
	return nil
}

// buildFolded indexes every claim under its lower-cased name, counting how many
// claims fold to each. It runs once per resolver and leaves folded nil when no
// claim name has an upper-case letter, since without one no two names can fold
// together and exact lookup answers everything.
func (r *claimResolver) buildFolded() {
	r.built = true
	mixed := false
	for name := range r.raw {
		// strings.ToLower returns its argument unchanged when there is nothing
		// to lower, so this scan allocates nothing on the all-lower-case path.
		if strings.ToLower(name) != name {
			mixed = true
			break
		}
	}
	if !mixed {
		return
	}
	r.folded = make(map[string]foldedClaim, len(r.raw))
	for name, v := range r.raw {
		lowered := strings.ToLower(name)
		e := r.folded[lowered]
		e.n++
		if e.n == 1 {
			e.value = v
		}
		r.folded[lowered] = e
	}
}

// claimMatches looks the named claim up and reports whether ANY of the entry's
// patterns match it. The lookup is hoisted out of the pattern loop so the map
// access happens once per claim, not once per pattern.
func claimMatches(res *claimResolver, cc compiledCondition) bool {
	v := res.lookup(cc.claim)
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
	res := newClaimResolver(claims)
	ok := satisfiesConditionsWith(cond, res)
	// An ambiguous claim denies the whole mapping, not just its leaf. Denying
	// only the leaf is polarity-dependent: under none_of a leaf that cannot
	// match is a veto that cannot fire, so `none_of: [{isContractor: "true"}]`
	// would authorize precisely the caller it was written to refuse as soon as
	// the token carried a second casing of that claim — including a decoy
	// casing whose value does not even match the pattern. That is the exact
	// hazard the case-folded lookup above exists to close, so it cannot be
	// reintroduced by the branch that handles a collision.
	//
	// Absence and ambiguity are different: an absent claim genuinely gives a
	// veto nothing to fire on, while an ambiguous one means the gate cannot
	// determine the value it was told to gate on. A gate that cannot know must
	// deny. Checking after the walk rather than short-circuiting inside it is
	// what makes the deny independent of where in the tree the collision sat
	// and of how many negations enclose it.
	if res.ambiguous {
		return false
	}
	return ok
}

// satisfiesConditionsWith is the recursive walk. The resolver is threaded down
// the whole tree so its folded index is built at most once per evaluation
// rather than once per node.
func satisfiesConditionsWith(cond *Condition, res *claimResolver) bool {
	if cond == nil {
		return true
	}

	for _, cc := range cond.compiled {
		if !claimMatches(res, cc) {
			return false
		}
	}

	for _, child := range cond.AllOf {
		if !satisfiesConditionsWith(child, res) {
			return false
		}
	}

	if len(cond.AnyOf) > 0 {
		matched := false
		for _, child := range cond.AnyOf {
			if satisfiesConditionsWith(child, res) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	for _, child := range cond.NoneOf {
		if satisfiesConditionsWith(child, res) {
			return false
		}
	}

	return true
}
