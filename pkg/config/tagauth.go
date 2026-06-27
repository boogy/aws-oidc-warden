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
//
// The supported dimensions mirror repo_role_mappings constraints (repo,
// repo-owner, branch, ref, ref-type, event-name, workflow-ref, environment,
// actor) so a role can require, e.g., repo==X AND ref==Y. Unlike constraints,
// tag matching is exact (AWS tag values cannot hold regex).
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
	identityOK := (hasRepo && repoMatches(claim("repository"), repoTag, t.DefaultOrg)) ||
		(hasOwner && valueInList(claim("repository_owner"), ownerTag))
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

	// Remaining single-claim dimensions (AND). These mirror the
	// repo_role_mappings constraints, but match exactly (AWS tag charset has no
	// regex); a space-separated tag value means OR.
	dims := []struct{ suffix, claimKey string }{
		{"ref", "ref"},                   // exact full ref, e.g. refs/heads/main
		{"ref-type", "ref_type"},         // "branch" or "tag"
		{"event-name", "event_name"},     // e.g. "push", "pull_request"
		{"workflow-ref", "workflow_ref"}, // e.g. org/repo/.github/workflows/deploy.yml@refs/heads/main
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

// repoMatches reports whether claimRepo matches the aow/repo tag value.
// Each space-separated token that contains no "/" is treated as a bare repo
// name and expanded to "<defaultOrg>/<token>" before comparison; tokens
// already in org/repo form match as-is. When defaultOrg is empty, bare tokens
// never match. Matching is exact (AWS tag charset has no regex).
func repoMatches(claimRepo, tagVal, defaultOrg string) bool {
	if claimRepo == "" {
		return false
	}
	for _, want := range strings.Fields(tagVal) {
		if !strings.Contains(want, "/") {
			if defaultOrg == "" {
				continue
			}
			want = defaultOrg + "/" + want
		}
		if claimRepo == want {
			return true
		}
	}
	return false
}
