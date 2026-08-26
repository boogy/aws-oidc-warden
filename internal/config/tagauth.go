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
// (no cross-issuer identity collision). With a
// single issuer, the issuer tag is optional but still checked if present.
//
// The named dimensions mirror role_mapping conditions (subject, repo,
// repo-owner, branch, ref, ref-type, event-name, workflow-ref, environment,
// runner-environment, actor) so a role can require, e.g., subject==X AND
// ref==Y. Those suffixes name GitHub Actions claims; every other issuer
// reaches its own claims through the issuer-agnostic `<prefix>claim.<name>`
// form, which matches the raw verified claim <name> — e.g.
// `aow/claim.project_path` for GitLab. Both forms AND together with the rest.
// A `claim.` tag compares against the claim VALUE, not its JSON type: a claim
// minted as a bool or a number is rendered the same way conditions and session
// tags render it, so `aow/claim.email_verified = "true"` matches both `true`
// and `"true"`.
//
// Unlike conditions, tag matching is exact (AWS tag values cannot hold regex),
// and unlike condition keys, a `claim.` suffix is matched case-sensitively:
// IAM tag keys are stored verbatim, so no case is lost on the way in and an
// exact lookup is always what the operator wrote.
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
	// claimMatchesTag reports whether the raw claim satisfies a tag value.
	// A scalar claim matches directly; a list claim (groups, aud, roles)
	// matches when any element does, mirroring how conditions treat list
	// claims. Scalars are read through claimText, the same renderer conditions
	// and session tags use, so a claim minted as a JSON bool or number is
	// comparable here too: `aow/claim.email_verified = "true"` matches whether
	// the issuer sends `true` or `"true"`. Without it the `claim.` form — the
	// ONLY dimension a non-GitHub issuer has beyond subject — silently never
	// matched a non-string claim, so the tag the operator wrote to narrow
	// access instead denied every caller. A value with no reading (object,
	// null, absent) still never matches, which is fail-closed: claim.* tags
	// only ever narrow, so an unreadable claim can only deny.
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

	// Remaining single-claim dimensions (AND). These mirror the
	// role_mappings conditions, but match exactly (AWS tag charset has no
	// regex); a space-separated tag value means OR.
	dims := []struct{ suffix, claimKey string }{
		{"ref", "ref"},                   // exact full ref, e.g. refs/heads/main
		{"ref-type", "ref_type"},         // "branch" or "tag"
		{"event-name", "event_name"},     // e.g. "push", "pull_request"
		{"workflow-ref", "workflow_ref"}, // e.g. org/repo/.github/workflows/deploy.yml@refs/heads/main
		// Every suffix is its claim name with underscores written as dashes.
		// `environment` checked runner_environment until 3.0.0 — the same word
		// meaning two claims depending on where it was written. It now checks
		// the deployment-environment claim; the runner type has its own tag.
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

	// Issuer-agnostic dimensions: `<prefix>claim.<name>` constrains the raw
	// verified claim <name>. This is the only dimension form available to a
	// non-GitHub issuer beyond `subject`, since every suffix above names a
	// GitHub Actions claim. Each one is a further AND; a role carrying only
	// claim.* tags and no identity tag was already rejected by the identity
	// gate, so these can narrow access but never grant it. An empty name
	// (a bare `<prefix>claim.` tag) names no claim and denies.
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
