package config

import (
	"regexp"
	"strings"
)

// issuerIndex buckets one issuer's effective RoleMappings by subject-pattern
// specificity so AuthorizeRoles/FindSessionPolicy can skip mappings that
// provably cannot match. Every candidatesFor result is still re-verified
// against its own compiledPattern (config.go); soundness of the bucket
// assignment itself is classifySubject's job — see there.
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

		owner, class := classifySubject(m.Subject, m.compiledPattern)
		switch class {
		case subjectExact:
			bucket.exact[m.Subject] = append(bucket.exact[m.Subject], m)
		case subjectOwner:
			bucket.byOwner[owner] = append(bucket.byOwner[owner], m)
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

// classifySubject buckets a subject pattern (auto-anchored regex; compiled is
// RoleMapping.compiledPattern): a literal string goes in exact; a pattern
// whose compiled regexp.LiteralPrefix() provably starts with "owner/" goes in
// byOwner[owner]; anything else is fully generic ("any", always scanned).
//
// byOwner MUST use the compiled LiteralPrefix, not string surgery on the raw
// pattern text before its first '/' — that naive scan is unsound for a
// quantified first slash ("myorg/?prod-.*" can match "myorgprod-x", no
// slash) or top-level alternation ("a/b|c/d"), both of which must fall
// through to "any" instead of missing matches in candidatesFor.
func classifySubject(pattern string, compiled *regexp.Regexp) (owner string, class subjectClass) {
	if isLiteral(pattern) {
		return "", subjectExact
	}

	if compiled != nil {
		if prefix, _ := compiled.LiteralPrefix(); prefix != "" {
			if i := strings.IndexByte(prefix, '/'); i >= 0 {
				return prefix[:i], subjectOwner
			}
		}
	}
	return "", subjectAny
}

// isLiteral reports whether s contains no regex metacharacters, i.e. compiling
// it as a pattern would only ever match s itself.
func isLiteral(s string) bool {
	return regexp.QuoteMeta(s) == s
}

// ownerOf returns the "owner" segment of subject (everything before the first
// '/'), or subject itself if there is no '/'.
func ownerOf(subject string) string {
	if i := strings.IndexByte(subject, '/'); i >= 0 {
		return subject[:i]
	}
	return subject
}

// candidatesFor gathers every mapping that could possibly match subject.
// Always allocates a fresh slice: idx's buckets are shared, concurrently-read
// state, so appending onto one in place would race.
func candidatesFor(idx *issuerIndex, subject string) []*RoleMapping {
	owner := ownerOf(subject)
	exact := idx.exact[subject]
	byOwner := idx.byOwner[owner]

	out := make([]*RoleMapping, 0, len(exact)+len(byOwner)+len(idx.any))
	out = append(out, exact...)
	out = append(out, byOwner...)
	out = append(out, idx.any...)
	return out
}
