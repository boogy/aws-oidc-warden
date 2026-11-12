package config

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/go-viper/mapstructure/v2"
)

// RoleEntry is one item of a roles list: a bare role ARN or @role_set, or an
// object whose non-nil settings replace the entry's value for that role.
type RoleEntry struct {
	Role               string            `mapstructure:"role"                 json:"role"`
	Conditions         *Condition        `mapstructure:"conditions"           json:"conditions,omitempty"`
	SessionPolicy      *string           `mapstructure:"session_policy"       json:"session_policy,omitempty"`
	SessionPolicyFile  *string           `mapstructure:"session_policy_file"  json:"session_policy_file,omitempty"`
	RoleSessionName    *string           `mapstructure:"role_session_name"    json:"role_session_name,omitempty"`
	AllowSessionName   *bool             `mapstructure:"allow_session_name"   json:"allow_session_name,omitempty"`
	IDPToken           *bool             `mapstructure:"idp_token"            json:"idp_token,omitempty"`
	MaxSessionDuration *time.Duration    `mapstructure:"max_session_duration" json:"max_session_duration,omitempty"`
	SessionDuration    *time.Duration    `mapstructure:"session_duration"     json:"session_duration,omitempty"`
	SessionTags        map[string]string `mapstructure:"session_tags"         json:"session_tags"` // nil = inherit; an empty map must survive the clone
}

var (
	roleEntryType      = reflect.TypeFor[RoleEntry]()
	roleEntrySliceType = reflect.SliceOf(roleEntryType)
)

// roleEntryHookFunc splits a scalar `roles: "a,b"`, decodes a bare string into {role: s}, and rejects a present-but-empty key.
func roleEntryHookFunc() mapstructure.DecodeHookFuncType {
	return func(_, to reflect.Type, data any) (any, error) {
		if s, ok := data.(string); ok && to == roleEntrySliceType {
			// StringToSliceHookFunc splits only for []string targets.
			if s == "" {
				return []string{}, nil
			}
			return strings.Split(s, ","), nil
		}
		if to != roleEntryType {
			return data, nil
		}
		switch v := data.(type) {
		case string:
			return map[string]any{"role": v}, nil
		case map[string]any:
			for _, key := range slices.Sorted(maps.Keys(v)) {
				if v[key] == nil {
					return nil, fmt.Errorf("role setting %q is present but empty", key)
				}
			}
		}
		return data, nil
	}
}

type overrideGroup int

const (
	groupConditions overrideGroup = iota
	groupPolicy
	groupName
	groupDuration
	groupSessionDuration
	groupIDPToken
	groupTags
	groupCount
)

var overrideGroupNames = [groupCount]string{
	"conditions",
	"session_policy/session_policy_file",
	"role_session_name/allow_session_name",
	"max_session_duration",
	"session_duration",
	"idp_token",
	"session_tags",
}

func (r RoleEntry) overrides() [groupCount]bool {
	return [groupCount]bool{
		groupConditions:      r.Conditions != nil,
		groupPolicy:          r.SessionPolicy != nil || r.SessionPolicyFile != nil,
		groupName:            r.RoleSessionName != nil || r.AllowSessionName != nil,
		groupDuration:        r.MaxSessionDuration != nil,
		groupSessionDuration: r.SessionDuration != nil,
		groupIDPToken:        r.IDPToken != nil,
		groupTags:            r.SessionTags != nil,
	}
}

func (r RoleEntry) hasOverride() bool {
	for _, set := range r.overrides() {
		if set {
			return true
		}
	}
	return false
}

// validate rejects a present-but-empty override; allow_session_name: false is not empty and clears an inherited name.
func (r RoleEntry) validate() error {
	switch {
	case r.SessionPolicy != nil && *r.SessionPolicy == "":
		return fmt.Errorf("session_policy must not be empty")
	case r.SessionPolicyFile != nil && *r.SessionPolicyFile == "":
		return fmt.Errorf("session_policy_file must not be empty")
	case r.RoleSessionName != nil && *r.RoleSessionName == "":
		return fmt.Errorf("role_session_name must not be empty")
	case r.MaxSessionDuration != nil && *r.MaxSessionDuration == 0:
		return fmt.Errorf("max_session_duration must not be 0")
	case r.SessionDuration != nil && *r.SessionDuration == 0:
		return fmt.Errorf("session_duration must not be 0")
	case r.SessionTags != nil && len(r.SessionTags) == 0:
		return fmt.Errorf("session_tags must not be empty")
	}
	return nil
}

func valueOf[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// overlay returns m with this role's overrides applied; each group is replaced as a unit.
func (r RoleEntry) overlay(m RoleMapping) RoleMapping {
	g := r.overrides()
	if g[groupConditions] {
		m.Conditions = r.Conditions
		m.roleConditions = true
	}
	if g[groupPolicy] {
		m.SessionPolicy, m.SessionPolicyFile = valueOf(r.SessionPolicy), valueOf(r.SessionPolicyFile)
	}
	if g[groupName] {
		m.RoleSessionName, m.AllowSessionName = valueOf(r.RoleSessionName), valueOf(r.AllowSessionName)
	}
	if g[groupDuration] {
		m.MaxSessionDuration = *r.MaxSessionDuration
	}
	if g[groupSessionDuration] {
		m.SessionDuration = *r.SessionDuration
	}
	if g[groupIDPToken] {
		m.IDPToken = *r.IDPToken
	}
	if g[groupTags] {
		m.SessionTags = r.SessionTags
	}
	return m
}

// entrySets reports which override groups the entry itself sets; false values are indistinguishable from unset.
func (m RoleMapping) entrySets() [groupCount]bool {
	return [groupCount]bool{
		groupConditions:      m.Conditions != nil,
		groupPolicy:          m.SessionPolicy != "" || m.SessionPolicyFile != "",
		groupName:            m.RoleSessionName != "" || m.AllowSessionName,
		groupDuration:        m.MaxSessionDuration != 0,
		groupSessionDuration: m.SessionDuration != 0,
		groupIDPToken:        m.IDPToken,
		groupTags:            len(m.SessionTags) > 0,
	}
}

// expandRoles resolves m.Roles into effective mappings: one per role with overrides, one for the rest.
func (c *Config) expandRoles(m RoleMapping, source string, i int) ([]RoleMapping, error) {
	wrap := func(err error) error {
		return fmt.Errorf("%s[%d]: %w", source, i, err)
	}

	resolved := make([][]string, len(m.Roles))
	counts := make(map[string]int)
	for ri, e := range m.Roles {
		if err := e.validate(); err != nil {
			return nil, wrap(fmt.Errorf("roles[%d]: %w", ri, err))
		}
		arns, err := c.resolveRoleSet([]string{e.Role})
		if err != nil {
			return nil, wrap(fmt.Errorf("roles[%d]: %w", ri, err))
		}
		resolved[ri] = arns
		keys := make([]string, len(arns))
		for ai, arn := range arns {
			keys[ai] = mappedRoleKey(arn)
		}
		for _, key := range slices.Compact(slices.Sorted(slices.Values(keys))) {
			counts[key]++
		}
	}

	var plain []string
	var overridden []int
	inherits := [groupCount]bool{}
	for ri, e := range m.Roles {
		if e.hasOverride() {
			overridden = append(overridden, ri)
			for _, arn := range resolved[ri] {
				if counts[mappedRoleKey(arn)] > 1 {
					return nil, wrap(fmt.Errorf("role %q has its own settings and appears more than once in this entry", arn))
				}
			}
		} else {
			plain = append(plain, resolved[ri]...)
		}
		for g, set := range e.overrides() {
			if !set {
				inherits[g] = true
			}
		}
	}

	for g, set := range m.entrySets() {
		if set && !inherits[g] {
			return nil, wrap(fmt.Errorf("entry-level %s is overridden on every role, so no role inherits it", overrideGroupNames[g]))
		}
	}

	var pieces []RoleMapping
	if len(plain) > 0 {
		base := m
		base.Roles, base.grantedRoles = nil, plain
		pieces = append(pieces, base)
	}
	for _, ri := range overridden {
		e := m.Roles[ri]
		piece := e.overlay(m)
		piece.Roles, piece.grantedRoles, piece.roleLabel = nil, resolved[ri], e.Role
		if e.IDPToken != nil && !*e.IDPToken && piece.MaxSessionDuration > IdPDefaultMaxSessionDuration {
			return nil, wrap(fmt.Errorf("role %q sets idp_token: false but max_session_duration over 1h requires the IdP", e.Role))
		}
		if e.IDPToken != nil && !*e.IDPToken && c.IdP != nil && c.IdP.Only {
			return nil, wrap(fmt.Errorf("role %q sets idp_token: false but idp.only routes every role through the IdP", e.Role))
		}
		pieces = append(pieces, piece)
	}

	if m.Conditions == nil && slices.ContainsFunc(m.Roles, func(e RoleEntry) bool { return e.Conditions != nil }) {
		for ri, e := range m.Roles {
			if e.Conditions != nil {
				continue
			}
			for _, arn := range resolved[ri] {
				logevent.Warn(context.Background(), nil, logevent.ConfigWarning,
					"role has no conditions while other roles in the same entry do; any matching subject can assume it",
					slog.String("warning", "unconditional_role_beside_conditioned"),
					slog.String("source", fmt.Sprintf("%s[%d]", source, i)),
					slog.String("roleArn", arn))
			}
		}
	}
	return pieces, nil
}
