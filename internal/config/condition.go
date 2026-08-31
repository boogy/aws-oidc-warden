package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/boogy/aws-oidc-warden/internal/types"
	"github.com/boogy/aws-oidc-warden/internal/utils"
)

// This file is the condition engine: shape, clone/compile at Validate() time,
// and evaluation against a request's raw verified claims.

// Condition defines claim predicates that must be met for a role to be
// assumed. Every key other than the three reserved boolean groups names a raw
// verified claim; its value is one regex pattern or a list OR'd together. The
// named fields below are discoverability sugar for common GitHub claims and
// compile identically to an entry in Claims.
type Condition struct {
	Ref               Patterns `mapstructure:"ref"                json:"ref,omitempty"`                // Patterns against the 'ref' claim (e.g., "refs/heads/main", "refs/tags/v.*")
	RefType           Patterns `mapstructure:"ref_type"           json:"ref_type,omitempty"`           // Patterns against 'ref_type' (e.g., "branch", "tag")
	EventName         Patterns `mapstructure:"event_name"         json:"event_name,omitempty"`         // Patterns against 'event_name' (e.g., "push", "pull_request")
	WorkflowRef       Patterns `mapstructure:"workflow_ref"       json:"workflow_ref,omitempty"`       // Patterns against 'workflow_ref' (e.g., "owner/repo/.github/workflows/release.yml@.*")
	Actor             Patterns `mapstructure:"actor"              json:"actor,omitempty"`              // Patterns against 'actor' (the principal that triggered the run)
	RunnerEnvironment Patterns `mapstructure:"runner_environment" json:"runner_environment,omitempty"` // Patterns against 'runner_environment' ("github-hosted", "self-hosted")
	Environment       Patterns `mapstructure:"environment"        json:"environment,omitempty"`        // Patterns against 'environment' (the deployment environment a job declares)

	// Boolean groups; AND'd with the flat fields above and each other on the
	// same node, so the top level is an implicit AND. Reserved under
	// `conditions:` — a claim literally named one of these is reachable under
	// `claims:` instead. Nesting makes this functionally complete, hence no
	// `not`/`xor`.
	AllOf  []*Condition `mapstructure:"all_of"  json:"all_of,omitempty"`  // every member must be satisfied
	AnyOf  []*Condition `mapstructure:"any_of"  json:"any_of,omitempty"`  // at least one member must be satisfied
	NoneOf []*Condition `mapstructure:"none_of" json:"none_of,omitempty"` // no member may be satisfied

	// ExplicitClaims: entries under the reserved `claims:` key, for a claim
	// whose name collides with a reserved key (all_of/any_of/none_of/claims).
	ExplicitClaims map[string]Patterns `mapstructure:"claims" json:"explicit_claims,omitempty"`

	// Claims holds every claimName->patterns entry not covered by a named
	// field above, keyed by the raw verified claim name (mapstructure remain).
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
	// maxConditionDepth bounds boolean-group nesting; top level is depth 1.
	maxConditionDepth = 5

	// maxConditionNodes bounds total condition nodes in one mapping's tree.
	maxConditionNodes = 64
)

// compileCondition compiles a condition tree (nil = unconditional match) into
// the pre-compiled form satisfiesConditions checks. Called once per effective
// mapping at Validate() time, never per request.
// rc may be nil, which disables pattern memoization.
func compileCondition(cond *Condition, rc regexCache) error {
	budget := 0
	return compileConditionAt(cond, "conditions", 1, &budget, rc)
}

// regexCache memoizes anchored-pattern compilation within one Validate() pass.
type regexCache map[string]*regexp.Regexp

// anchor compiles pattern as "^(?:pattern)$". Callers must run the empty and
// bare-wildcard guards first; only accepted patterns are memoized.
func (rc regexCache) anchor(pattern string) (*regexp.Regexp, error) {
	if re, ok := rc[pattern]; ok {
		return re, nil
	}
	re, err := regexp.Compile("^(?:" + pattern + ")$")
	if err != nil {
		return nil, err
	}
	if rc != nil {
		rc[pattern] = re
	}
	return re, nil
}

// namedPatterns pairs a shorthand condition key with its patterns.
type namedPatterns struct {
	claim    string
	patterns Patterns
}

// namedClaimPatterns returns the shorthand condition keys in compile order.
// The order is fixed so error reporting is reproducible across runs.
func (c *Condition) namedClaimPatterns() []namedPatterns {
	return []namedPatterns{
		{"ref", c.Ref},
		{"ref_type", c.RefType},
		{"event_name", c.EventName},
		{"workflow_ref", c.WorkflowRef},
		{"actor", c.Actor},
		{"runner_environment", c.RunnerEnvironment},
		{"environment", c.Environment},
	}
}

// compileConditionAt compiles one node and recurses into its groups. path is
// this node's location (e.g. "conditions.any_of[1].all_of[0]"), used in error
// messages. depth is 1 for the top-level node; budget counts nodes compiled
// so far across the whole tree. Every field compiles through the same
// anchored-regex mechanism as a generic claim entry.
func compileConditionAt(cond *Condition, path string, depth int, budget *int, rc regexCache) error {
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
	// key and claim differ only under claims: (key "claims.x", claim "x").
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
			re, err := compileAnchoredCondition(pattern, rc)
			if err != nil {
				return fmt.Errorf("%s: invalid pattern for %q: %w", path, key, err)
			}
			compiled = append(compiled, re)
		}
		cond.compiled = append(cond.compiled, compiledCondition{claim: claim, patterns: compiled})
		return nil
	}

	for _, np := range cond.namedClaimPatterns() {
		if err := add(np.claim, np.claim, np.patterns); err != nil {
			return err
		}
	}

	// Sorted iteration: reproducible error reporting across runs. A map key
	// with a nil value (`repository:` with nothing after it) is checked here,
	// where presence is observable — add() treats nil as "not written".
	for _, claim := range utils.SortedKeys(cond.Claims) {
		if cond.Claims[claim] == nil {
			return errNoPatternForKey(path, claim)
		}
		if err := add(claim, claim, cond.Claims[claim]); err != nil {
			return err
		}
	}
	for _, claim := range utils.SortedKeys(cond.ExplicitClaims) {
		if cond.ExplicitClaims[claim] == nil {
			return errNoPatternForKey(path, "claims."+claim)
		}
		if err := add("claims."+claim, claim, cond.ExplicitClaims[claim]); err != nil {
			return err
		}
	}

	if err := compileGroup("all_of", cond.AllOf, path, depth, budget, rc); err != nil {
		return err
	}
	if err := compileGroup("any_of", cond.AnyOf, path, depth, budget, rc); err != nil {
		return err
	}
	if err := compileGroup("none_of", cond.NoneOf, path, depth, budget, rc); err != nil {
		return err
	}

	// A top-level node that gates nothing would authorize unconditionally;
	// checked on the aggregate since a field written with no value decodes
	// the same as one never written.
	if depth == 1 && conditionIsEmpty(cond) {
		return fmt.Errorf("%s: declares no predicate, so it would authorize every request that reaches it; remove the `conditions` key if the mapping is meant to be unconditional, or give the key you wrote a pattern", path)
	}
	return nil
}

// errNoPatternForKey reports a condition key written with no value: distinct
// from `repository: []` ("match nothing"), but both compile to no predicate.
func errNoPatternForKey(path, key string) error {
	return fmt.Errorf("%s: %q has no value; a condition key with no pattern gates nothing — give it a pattern or remove the key", path, key)
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
func compileGroup(name string, nodes []*Condition, path string, depth int, budget *int, rc regexCache) error {
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
		if err := compileConditionAt(child, childPath, depth+1, budget, rc); err != nil {
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
func compileAnchoredCondition(pattern string, rc regexCache) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, errors.New("pattern must not be empty")
	}
	if bareWildcards[pattern] {
		return nil, fmt.Errorf("pattern %q is too permissive; use a specific pattern", pattern)
	}
	return rc.anchor(pattern)
}

// valueMatches reports whether one raw verified claim VALUE satisfies pattern
// (already anchored at compile time).
//
// A value is compared through its canonical text — utils.FormatClaimValue via
// claimText — so a condition decides on the same rendering the audit record
// and the session tag report. An ARRAY matches when ANY element's text
// matches, since "the caller is in group X" is what a list claim means. A
// shape with no text (an object, a list carrying one) and absence never match.
//
// This reads the VALUE, never the Go type, and in BOTH polarities: dispatching
// on type under none_of alone made the two spellings of a predicate disagree
// and broke NOT(NOT(x)) == x. types.OpaqueClaim is the one deliberate
// exception to that symmetry — see valueIsUndecidable.
//
// Cost is bounded without an element cap: the token is already length-capped
// upstream by max_token_bytes (default 8192), so the number of array elements
// a request can carry is bounded by the same limit that bounds the claim set.
func valueMatches(v any, pattern *regexp.Regexp) bool {
	switch t := v.(type) {
	case nil:
		return false
	case []any:
		for _, el := range t {
			if s, ok := claimText(el); ok && pattern.MatchString(s) {
				return true
			}
		}
		return false
	default:
		s, ok := claimText(v)
		return ok && pattern.MatchString(s)
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

// claimText renders a scalar claim VALUE as the text a pattern can be compared
// against, reporting false when the shape has no such rendering.
//
// It goes through utils.FormatClaimValue, so a value a condition decides on
// reads identically to the value the audit record reports. A JSON object —
// and nil, []any, and anything else structural — has no canonical text and
// returns false; those are handled by the caller. types.OpaqueClaim IS
// readable here and valueIsUndecidable still vetoes it: for that one type the
// two are deliberately not complements.
func claimText(v any) (string, bool) {
	switch t := v.(type) {
	case types.OpaqueClaim:
		return utils.FormatClaimValue(string(t)), true
	case string, bool, float64, float32,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		json.Number:
		return utils.FormatClaimValue(v), true
	}
	return "", false
}

// valueIsUndecidable reports whether a claim VALUE may not be trusted to
// answer a negated leaf. Under an odd number of none_of groups, "did not
// match" would disarm the veto and authorize exactly the caller the operator
// refused, so such a value counts as MATCHED and fires the veto instead.
//
// Three shapes qualify: an object, a list carrying a structural element, and
// types.OpaqueClaim — a claim whose JSON type an upstream stringifier
// destroyed (apigw mode), readable as text but no longer a reading of the real
// value. OpaqueClaim is the one place the gate refuses a claim by TYPE rather
// than by VALUE: claimText reads it, so positive polarity matches its verbatim
// text while negation vetoes, and NOT(NOT(x)) == x does NOT hold for it. That
// asymmetry is load-bearing — removing it reopens the apigw none_of fail-open
// (TestOpaqueClaimPositiveAndNoneOfAreNotComplements).
//
// Absence is deliberately NOT undecidable: nil, from a missing claim or a JSON
// null, is a known state, and none_of's exact-negation semantics depend on it.
func valueIsUndecidable(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case types.OpaqueClaim:
		// Must precede default, which defers to claimText and finds it readable.
		return true
	case []any:
		for _, el := range t {
			if _, ok := claimText(el); !ok {
				return true
			}
		}
		return false
	default:
		_, ok := claimText(v)
		return !ok
	}
}

// claimMatches looks the named claim up and reports whether ANY of the entry's
// patterns match it. The lookup is hoisted out of the pattern loop so the map
// access happens once per claim, not once per pattern.
//
// negated says whether an odd number of none_of groups encloses this leaf. It
// changes nothing for an ordinary readable value — both polarities decide on
// canonical text — and matters only for a value valueIsUndecidable rejects,
// types.OpaqueClaim included. See valueIsUndecidable.
func claimMatches(res *claimResolver, cc compiledCondition, negated bool) bool {
	v := res.lookup(cc.claim)
	for _, pattern := range cc.patterns {
		if valueMatches(v, pattern) {
			return true
		}
	}
	return negated && valueIsUndecidable(v)
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
// its negation holds and the none_of passes. A member naming a PRESENT claim is
// decided on the claim's value whatever JSON type it arrived as, and a value
// valueIsUndecidable rejects vetoes.
//
// The walk allocates nothing and compiles nothing — every pattern was compiled
// at Validate() time — and its depth is bounded by the config, never by request
// input.
func satisfiesConditions(cond *Condition, claims map[string]any) bool {
	if cond == nil {
		return true
	}
	res := newClaimResolver(claims)
	ok := satisfiesConditionsWith(cond, res, false)
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
//
// negated tracks polarity: it is false at the root and flips on every descent
// into a none_of member, so a none_of nested inside a none_of is positive again
// (double negation), which is what the operator wrote. all_of and any_of
// preserve polarity — they change how members combine, not whether the result
// is negated. Only claimMatches reads it, and only for a claim it cannot read
// at all; every other leaf answers identically in both polarities, which is
// what makes NOT(NOT(x)) == x hold for every value the gate can compare.
func satisfiesConditionsWith(cond *Condition, res *claimResolver, negated bool) bool {
	if cond == nil {
		return true
	}

	for _, cc := range cond.compiled {
		if !claimMatches(res, cc, negated) {
			return false
		}
	}

	for _, child := range cond.AllOf {
		if !satisfiesConditionsWith(child, res, negated) {
			return false
		}
	}

	if len(cond.AnyOf) > 0 {
		matched := false
		for _, child := range cond.AnyOf {
			if satisfiesConditionsWith(child, res, negated) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	for _, child := range cond.NoneOf {
		if satisfiesConditionsWith(child, res, !negated) {
			return false
		}
	}

	return true
}
