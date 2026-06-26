package config

import (
	"strings"

	"github.com/boogy/aws-oidc-warden/pkg/utils"
)

// Authorize reports whether the role's IAM tags authorize the given OIDC claims.
// roleTags is the role's full tag set (any keys); only keys under TagPrefix are
// considered. A role must carry at least a `<prefix>repo` or `<prefix>repo-owner`
// tag (and match it) to be assumable; every other present dimension tag must
// also match (AND). Within a single tag, space-separated values mean OR.
func (t *TagAuth) Authorize(roleTags map[string]string, claims map[string]any) bool {
	if t == nil || !t.Enabled {
		return false
	}
	p := t.TagPrefix
	get := func(suffix string) (string, bool) {
		v, ok := roleTags[p+suffix]
		return v, ok
	}
	claim := func(key string) string {
		s, _ := claims[key].(string)
		return s
	}

	// Identity gate: repo OR repo-owner. At least one must be present and match.
	repoTag, hasRepo := get("repo")
	ownerTag, hasOwner := get("repo-owner")
	if !hasRepo && !hasOwner {
		return false
	}
	identityOK := false
	if hasRepo && valueInList(claim("repository"), repoTag) {
		identityOK = true
	}
	if hasOwner && valueInList(claim("repository_owner"), ownerTag) {
		identityOK = true
	}
	if !identityOK {
		return false
	}

	// branch: match against the full ref or the short branch name.
	if v, ok := get("branch"); ok {
		ref := claim("ref")
		if !valueInList(ref, v) && !valueInList(utils.ExtractBranchFromRef(ref), v) {
			return false
		}
	}

	// Remaining single-claim dimensions (AND).
	dims := []struct{ suffix, claimKey string }{
		{"ref-type", "ref_type"},
		{"event-name", "event_name"},
		{"environment", "runner_environment"},
		{"actor", "actor"},
	}
	for _, d := range dims {
		if v, ok := get(d.suffix); ok {
			if !valueInList(claim(d.claimKey), v) {
				return false
			}
		}
	}
	return true
}

// valueInList reports whether claimVal exactly equals one of the
// space-separated values in tagVal. Empty claimVal never matches.
func valueInList(claimVal, tagVal string) bool {
	if claimVal == "" {
		return false
	}
	for _, want := range strings.Fields(tagVal) {
		if claimVal == want {
			return true
		}
	}
	return false
}
