package config

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// Patterns is a list of regex patterns for ONE claim, OR'd together: the claim
// satisfies the entry when any pattern matches (see satisfiesConditions).
//
// It decodes from either shape, so the common single-pattern case stays a
// plain scalar:
//
//	conditions:
//	  repository: "octo-org/api"                  # string
//	  actor: ["release-bot", "release-manager"]   # list, OR'd
//
// A nil Patterns means the key was absent (no predicate). An explicitly empty
// list is rejected by compileConditionAt — it would gate nothing.
type Patterns []string

// patternsType is the decode target the mapstructure hook below keys on.
var patternsType = reflect.TypeOf(Patterns(nil))

// conditionPtrType is the decode target nilConditionHookFunc keys on.
var conditionPtrType = reflect.TypeOf((*Condition)(nil))

// UnmarshalJSON accepts the same string-or-list shapes as the mapstructure
// hook. Both are needed: config files decode through viper/mapstructure, while
// the provider's snapshot clone (cloneConfig) round-trips through encoding/json.
func (p *Patterns) UnmarshalJSON(data []byte) error {
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		*p = list
		return nil
	}
	var one string
	if err := json.Unmarshal(data, &one); err != nil {
		return fmt.Errorf("condition pattern must be a string or a list of strings: %w", err)
	}
	*p = Patterns{one}
	return nil
}

// stringToPatternsHookFunc lets a scalar decode into Patterns.
//
// It runs FIRST in the chain, ahead of viper's StringToSliceHookFunc(","),
// which splits a string bound for a slice on commas and would tear a regex like
// `v[0-9]{1,3}` in half. That hook happens not to fire here today — it requires
// the target to be exactly `[]string`, and Patterns is a named type — but the
// gate must not depend on that detail, and once this hook has produced a slice
// the comma hook cannot apply to the value at all.
// See TestPatternsDecodeKeepsCommasInRegexes.
func stringToPatternsHookFunc() mapstructure.DecodeHookFuncType {
	return func(from, to reflect.Type, data any) (any, error) {
		if to != patternsType {
			return data, nil
		}
		// A key written with nothing after it (`ref:`) reaches this hook only
		// because decoderOptions sets DecodeNil; otherwise mapstructure skips
		// the field and `ref:` decodes to exactly what omitting `ref` does —
		// the operator wrote a gate and the compiled condition has none. An
		// empty (non-nil) Patterns instead reaches the compiler, which
		// rejects any claim key carrying no pattern.
		if v := reflect.ValueOf(data); !v.IsValid() || ((v.Kind() == reflect.Slice || v.Kind() == reflect.Map) && v.IsNil()) {
			return Patterns{}, nil
		}
		if from.Kind() != reflect.String {
			return data, nil
		}
		return Patterns{reflect.ValueOf(data).String()}, nil
	}
}

// nilConditionHookFunc turns a `conditions:` key written with nothing after it
// into an empty (non-nil) Condition — the hole stringToPatternsHookFunc closes,
// one level up. A nil value leaves the *Condition field nil, indistinguishable
// from a mapping that declares no conditions, so the gate disappears and the
// mapping authorizes every request matching its subject. An empty Condition
// reaches compileConditionAt, which rejects a node that gates nothing.
func nilConditionHookFunc() mapstructure.DecodeHookFuncType {
	return func(from, to reflect.Type, data any) (any, error) {
		if to != conditionPtrType {
			return data, nil
		}
		if v := reflect.ValueOf(data); !v.IsValid() || ((v.Kind() == reflect.Slice || v.Kind() == reflect.Map || v.Kind() == reflect.Pointer) && v.IsNil()) {
			return &Condition{}, nil
		}
		return data, nil
	}
}

// decoderOptions returns the mapstructure options EVERY config unmarshal must
// pass (LoadConfig, MergeBytes, parseFragment). Passing viper.DecodeHook
// REPLACES viper's default hook chain rather than extending it, so the two
// defaults are re-composed here after ours — dropping them would silently
// break `jwt_leeway: 30s` and every comma-separated `[]string` value.
func decoderOptions() []viper.DecoderConfigOption {
	return []viper.DecoderConfigOption{
		viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
			stringToPatternsHookFunc(),
			nilConditionHookFunc(),
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		)),
		// Run the hook chain for null values too. Hooks ignore types they do
		// not claim and mapstructure still zeroes the field afterwards, so
		// this changes the meaning of exactly two keys: the ones
		// stringToPatternsHookFunc and nilConditionHookFunc claim.
		func(c *mapstructure.DecoderConfig) { c.DecodeNil = true },
	}
}
