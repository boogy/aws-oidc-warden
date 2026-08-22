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
		if to != patternsType || from.Kind() != reflect.String {
			return data, nil
		}
		return Patterns{reflect.ValueOf(data).String()}, nil
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
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		)),
	}
}
