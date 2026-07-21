package config

import (
	"regexp"
	"strings"
)

// issuerIndex buckets one issuer's effective RoleMappings by how specific
// their subject pattern is, so AuthorizeRoles/FindSessionPolicy can skip
// scanning mappings that provably cannot match a given subject. Bucketing can
// only affect performance, never correctness: every candidate returned by
// candidatesFor is re-verified against its own compiledPattern before being
// treated as a match (see AuthorizeRoles/FindSessionPolicy in config.go),
// which is what makes the index provably equivalent to a full linear scan.
type issuerIndex struct {
	exact   map[string][]*RoleMapping // subject pattern is a literal, whole string
	byOwner map[string][]*RoleMapping // subject pattern's first "owner/" segment is literal
	any     []*RoleMapping            // fully-generic pattern; always scanned
}

// authzIndex is the per-issuer index built by buildAuthzIndex.
type authzIndex map[string]*issuerIndex

// buildAuthzIndex classifies every mapping's Subject pattern and buckets it
// under its resolved Issuer. Order within each bucket follows mappings'
// original relative order (declaration order is preserved via
// RoleMapping.order for callers that need first-match-wins semantics).
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

// classifySubject inspects a subject pattern (a regex, auto-anchored at
// compile time — compiled is its RoleMapping.compiledPattern) and decides
// which index bucket it belongs in:
//   - a pattern that is a literal string (no regex metacharacters) can only
//     ever match that exact string, so it goes in the exact bucket keyed by
//     itself;
//   - a pattern where EVERY match provably starts with a literal "owner/"
//     segment goes in the byOwner bucket keyed by that owner, since it can only
//     match subjects under that owner;
//   - anything else is fully generic and must always be scanned.
//
// The byOwner decision is made from the compiled program's guaranteed literal
// prefix (regexp.LiteralPrefix), NOT from string surgery on the raw pattern.
// byOwner[owner] is only correct if every subject the pattern can match starts
// with "owner/" — otherwise candidatesFor, which keys on ownerOf(subject),
// would miss matches. LiteralPrefix returns the literal string every match must
// begin with, so bucketing by the text before its first '/' is sound. This
// correctly demotes shapes that a naive "text before the first '/'" scan got
// wrong: a quantified first slash ("myorg/?prod-.*" → prefix "myorg", which can
// match "myorgprod-x" with no slash) and top-level alternation ("a/b|c/d" →
// prefix ""), both of which fall through to the conservative "any" bucket.
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

// candidatesFor gathers every mapping that could possibly match subject:
// exact-literal matches on subject itself, owner-bucketed matches on
// subject's owner segment, and every fully-generic mapping. It always
// allocates a fresh slice — idx.exact/idx.byOwner/idx.any are shared,
// concurrently-read state (behind Config's atomic snapshot), so appending
// onto a slice retrieved from one of those maps in place would risk a data
// race / corrupting other readers' view of that bucket.
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
