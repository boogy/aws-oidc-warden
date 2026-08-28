package config

import "strings"

// auditableClaimsFor returns, per issuer, the raw claim names its config
// references: claim_mappings, required_claims, session_tags, and any claim
// named by a condition on a mapping bound to it (so a none_of/any_of
// deciding claim is always recordable, not just claim_mappings targets).
//
// Stored as written plus lower-cased: viper lower-cases config keys but not
// raw claims; callers resolve exact-then-folded (see claimResolver).
func auditableClaimsFor(issuer string, spec *IssuerConfig, mappings []*RoleMapping) map[string]bool {
	out := make(map[string]bool)
	add := func(name string) {
		if name == "" {
			return
		}
		out[name] = true
		out[strings.ToLower(name)] = true
	}

	if spec != nil {
		for _, claimName := range spec.ClaimMappings {
			add(claimName)
		}
		for _, claimName := range spec.RequiredClaims {
			add(claimName)
		}
		for _, claimName := range spec.SessionTags {
			add(claimName)
		}
	}

	for _, m := range mappings {
		if m.Issuer != issuer {
			continue
		}
		collectConditionClaims(m.Conditions, add)
	}
	return out
}

// collectConditionClaims reports every claim name c gates on, including
// inside nested all_of/any_of/none_of. Walks the declared tree, not compiled
// predicates, so it stays correct if a pattern failed to compile.
func collectConditionClaims(c *Condition, add func(string)) {
	if c == nil {
		return
	}
	for name, named := range map[string]Patterns{
		"ref":                c.Ref,
		"ref_type":           c.RefType,
		"event_name":         c.EventName,
		"workflow_ref":       c.WorkflowRef,
		"actor":              c.Actor,
		"runner_environment": c.RunnerEnvironment,
		"environment":        c.Environment,
	} {
		if len(named) > 0 {
			add(name)
		}
	}
	for name := range c.Claims {
		add(name)
	}
	for name := range c.ExplicitClaims {
		add(name)
	}
	for _, group := range [][]*Condition{c.AllOf, c.AnyOf, c.NoneOf} {
		for _, member := range group {
			collectConditionClaims(member, add)
		}
	}
}

// AuditableClaims reports whether claimName is one issuer's config
// references, exact-first then case-folded (see auditableClaimsFor).
//
// An unknown issuer matches nothing (fail-closed).
//
// Two differently-cased claims folding to the same referenced name are BOTH
// recorded, deliberately — neither can be preferred, and this is exactly the
// case the condition engine denies as ambiguous (see claimResolver).
func (c *Config) AuditableClaims(issuer, claimName string) bool {
	set, ok := c.auditable[issuer]
	if !ok {
		return false
	}
	if set[claimName] {
		return true
	}
	return set[strings.ToLower(claimName)]
}
