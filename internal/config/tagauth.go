package config

import (
	"strings"

	"github.com/boogy/aws-oidc-warden/internal/utils"
)

// Authorize reports whether the role's IAM tags authorize claims for a
// verified (issuer, subject) pair. Only keys under TagPrefix are read.
//
// Requires at least one identity tag (`subject`, or legacy `repo`/
// `repo-owner`) that matches; every other present dimension tag must also
// match (AND). Space-separated values within one tag are OR'd.
//
// With >1 issuer configured, a role must also carry a matching `issuer` tag
// or it fails closed (no cross-issuer identity collision).
//
// Named dimension suffixes mirror role_mapping conditions and name GitHub
// claims; `claim.<name>` is the issuer-agnostic form for any other claim
// (e.g. `aow/claim.project_path`), read through claimText so it matches
// regardless of JSON type, and matched case-sensitively (IAM tag keys are
// stored verbatim).
//
// Tag matching is exact — no regex, unlike conditions.
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
	// claimMatchesTag: a list claim matches if any element does; scalars go
	// through claimText so non-string JSON values compare too. Unreadable
	// (object/null/absent) never matches — fail-closed, claim.* only narrows.
	claimMatchesTag := func(key, tagVal string) bool {
		switch v := claims[key].(type) {
		case []any:
			for _, elem := range v {
				if s, ok := claimText(elem); ok && valueInList(s, tagVal) {
					return true
				}
			}
		case []string:
			for _, s := range v {
				if valueInList(s, tagVal) {
					return true
				}
			}
		default:
			if s, ok := claimText(v); ok {
				return valueInList(s, tagVal)
			}
		}
		return false
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

	// Remaining single-claim dimensions (AND), matched exactly.
	dims := []struct{ suffix, claimKey string }{
		{"ref", "ref"},                   // exact full ref, e.g. refs/heads/main
		{"ref-type", "ref_type"},         // "branch" or "tag"
		{"event-name", "event_name"},     // e.g. "push", "pull_request"
		{"workflow-ref", "workflow_ref"}, // e.g. org/repo/.github/workflows/deploy.yml@refs/heads/main
		{"environment", "environment"},
		{"runner-environment", "runner_environment"},
		{"actor", "actor"},
	}
	for _, d := range dims {
		if v, ok := get(d.suffix); ok {
			if !valueInList(claim(d.claimKey), v) {
				return false
			}
		}
	}

	// `<prefix>claim.<name>` constrains raw claim <name> (AND); only
	// dimension available to a non-GitHub issuer beyond subject.
	claimPrefix := p + "claim."
	for key, tagVal := range roleTags {
		name, ok := strings.CutPrefix(key, claimPrefix)
		if !ok {
			continue
		}
		if !claimMatchesTag(name, tagVal) {
			return false
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

// repoMatches reports whether claimRepo matches the aow/repo tag value. A
// bare (no "/") token expands to "<defaultOrg>/<token>"; empty defaultOrg
// means bare tokens never match.
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
