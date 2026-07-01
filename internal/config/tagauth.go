package config

import (
	"strings"

	"github.com/boogy/aws-oidc-warden/internal/utils"
)

// Authorize reports whether the role's IAM tags authorize the given OIDC
// claims for a verified (issuer, subject) pair. roleTags is the role's full
// tag set (any keys); only keys under TagPrefix are considered. A role must
// carry at least one identity tag — the canonical `<prefix>subject`, or the
// legacy `<prefix>repo`/`<prefix>repo-owner` aliases (retained through v2 for
// GitHub-shaped subjects) — and match it, to be assumable; every other
// present dimension tag must also match (AND). Within a single tag,
// space-separated values mean OR.
//
// When more than one issuer is configured (t.multiIssuer), a role must also
// carry a matching `<prefix>issuer` tag: without it, tag-auth cannot tell
// which issuer's identity namespace the role trusts, so it fails closed
// (SHARED.md invariant #3: no cross-issuer identity collision). With a
// single issuer, the issuer tag is optional but still checked if present.
//
// The supported dimensions mirror role_mapping conditions (subject, repo,
// repo-owner, branch, ref, ref-type, event-name, workflow-ref, environment,
// actor) so a role can require, e.g., subject==X AND ref==Y. Unlike
// conditions, tag matching is exact (AWS tag values cannot hold regex).
func (t *TagAuth) Authorize(roleTags map[string]string, claims map[string]any, verifiedIssuer, subject string) bool {
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

	// Issuer gate: cross-issuer identity collision guard.
	issuerTag, hasIssuer := get("issuer")
	if hasIssuer {
		if !valueInList(verifiedIssuer, issuerTag) {
			return false
		}
	} else if t.multiIssuer {
		return false
	}

	// Identity gate: subject OR repo OR repo-owner. At least one must be
	// present and match.
	subjectTag, hasSubject := get("subject")
	repoTag, hasRepo := get("repo")
	ownerTag, hasOwner := get("repo-owner")
	if !hasSubject && !hasRepo && !hasOwner {
		return false
	}
	identityOK := (hasSubject && valueInList(subject, subjectTag)) ||
		(hasRepo && repoMatches(claim("repository"), repoTag, t.DefaultOrg)) ||
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
