package config

import (
	"regexp/syntax"
	"strings"
)

// issuerIndex buckets one issuer's effective RoleMappings by subject-pattern
// specificity so AuthorizeRoles/FindSessionPolicy can skip mappings that
// provably cannot match. Owner and any candidates are re-verified against
// their compiledPattern (config.go); exact ones are proven by the map hit.
// Soundness of the bucket assignment itself is classifySubject's job.
type issuerIndex struct {
	exact   map[string][]*RoleMapping // subject pattern is a literal, whole string
	byOwner map[string][]*RoleMapping // subject pattern's first "owner/" segment is literal
	any     []*RoleMapping            // fully-generic pattern; always scanned
}

// authzIndex is the per-issuer index built by buildAuthzIndex.
type authzIndex map[string]*issuerIndex

// buildAuthzIndex classifies every mapping's Subject pattern and buckets it
// under its resolved Issuer. Order within each bucket is declaration order
// (RoleMapping.order), for first-match-wins callers.
func buildAuthzIndex(mappings []*RoleMapping) authzIndex {
	idx := make(authzIndex)

	for _, m := range mappings {
		bucket, ok := idx[m.Issuer]
		if !ok {
			bucket = &issuerIndex{
				exact:   make(map[string][]*RoleMapping),
				byOwner: make(map[string][]*RoleMapping),
			}
			idx[m.Issuer] = bucket
		}

		switch m.subjectClass {
		case subjectExact:
			bucket.exact[m.subjectKey] = append(bucket.exact[m.subjectKey], m)
		case subjectOwner:
			bucket.byOwner[m.subjectKey] = append(bucket.byOwner[m.subjectKey], m)
		default:
			bucket.any = append(bucket.any, m)
		}
	}

	return idx
}

// subjectClass classifies a subject pattern for index bucketing.
type subjectClass int

const (
	subjectAny subjectClass = iota
	subjectExact
	subjectOwner
)

// classifySubject buckets a subject pattern from its parse tree. A
// case-sensitive literal goes in exact under the string it matches; a concat
// whose leading case-sensitive literal contains '/' goes in byOwner under the
// text before that '/'; anything else (alternation, (?i), a quantified first
// slash, a leading group) is "any" and always scanned.
//
// The tree, not string surgery on the raw text: "myorg/?prod-.*" can match
// "myorgprod-x" and "a/b|c/d" matches owner c, so neither may be owner-bucketed.
// The parser keeps the last rune of a literal separate when a quantifier
// follows it, so a leading literal is genuinely mandatory.
func classifySubject(pattern string) (key string, class subjectClass) {
	re, err := parsePattern(pattern)
	if err != nil {
		return "", subjectAny
	}
	if lit, ok := literalOf(re); ok {
		return lit, subjectExact
	}
	if re.Op != syntax.OpConcat || len(re.Sub) == 0 {
		return "", subjectAny
	}
	if prefix, ok := literalOf(re.Sub[0]); ok {
		if i := strings.IndexByte(prefix, '/'); i >= 0 {
			return prefix[:i], subjectOwner
		}
	}
	return "", subjectAny
}

// ownerOf returns the "owner" segment of subject (everything before the first
// '/'), or subject itself if there is no '/'.
func ownerOf(subject string) string {
	if i := strings.IndexByte(subject, '/'); i >= 0 {
		return subject[:i]
	}
	return subject
}
