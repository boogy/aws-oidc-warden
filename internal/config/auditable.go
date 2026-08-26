package config

import "strings"

// auditableClaimsFor returns, per issuer, the set of raw claim names that
// issuer's own configuration explicitly references: its claim_mappings
// targets, its required_claims, its session_tags targets, and every claim
// named by a condition on a role_mapping bound to it.
//
// This is the inclusion set the audit record uses for a non-github provider
// (see handler.auditClaims). Recording only claim_mappings targets was too
// narrow in one specific and damaging way: a claim that DECIDED the request —
// the `groups` a none_of vetoed on, the entitlement an any_of required — was
// absent from the record, so the audit trail could not explain its own
// decision. Every name here is one the operator wrote into the config, so
// widening to them records nothing the operator did not already single out;
// a claim the issuer happens to mint and nothing references (email, name) is
// still never recorded.
//
// Names are stored as written, plus a lower-cased form, because viper
// lower-cases every config KEY it reads: a condition on `isContractor` is
// stored as `iscontractor`, while the raw claim is still `isContractor`.
// Callers resolve exact-first-then-folded, matching how condition evaluation
// resolves the same names (see claimResolver).
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

// collectConditionClaims walks a condition tree and reports every claim name
// it gates on, including inside nested all_of/any_of/none_of groups. It walks
// the declared tree rather than the compiled predicates so it stays correct
// for a node whose patterns failed to compile.
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

// AuditableClaims reports whether the named raw claim is one the issuer's own
// configuration references, and so may be recorded in the audit record for a
// provider that does not record everything. Resolution is exact-first, then
// case-folded, for the viper key-lowering reason in auditableClaimsFor.
//
// An issuer with no computed set (unknown issuer) matches nothing, which
// keeps the record fail-closed rather than fail-open.
//
// The fold does mean that when a token carries two differently-cased claims
// that fold to one referenced name (project_path and PROJECT_PATH), BOTH are
// recorded, including the one the operator did not write. That is deliberate,
// not an oversight. The fold cannot be dropped — it is the entire reason this
// works, since the config name arrived from viper already lower-cased and the
// raw claim did not — and nothing distinguishes which of the two the operator
// meant, so preferring one would be arbitrary. Recording both is bounded (only
// case-variants of a name the operator explicitly wrote), lossless (each keeps
// its own raw name as the record key, so neither overwrites the other), and in
// the one case where it bites the request has already been DENIED as ambiguous
// by the condition engine (see claimResolver) — there the two values are
// precisely what explains the denial to a reader of the record.
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
