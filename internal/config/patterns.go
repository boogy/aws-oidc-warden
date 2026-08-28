package config

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// Patterns is a list of regex patterns for ONE claim, OR'd together; decodes
// from a scalar or a list. Nil means the key was absent (no predicate); an
// explicit empty list is rejected by compileConditionAt as gating nothing.
type Patterns []string

// patternsType is the decode target the mapstructure hook below keys on.
var patternsType = reflect.TypeOf(Patterns(nil))

// conditionPtrType is the decode target nilConditionHookFunc keys on.
var conditionPtrType = reflect.TypeOf((*Condition)(nil))

// UnmarshalJSON mirrors the mapstructure hook's string-or-list decode; needed
// separately because cloneConfig round-trips through encoding/json.
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
// Must run before viper's StringToSliceHookFunc(","), which would split a
// regex like `v[0-9]{1,3}` on its comma. See TestPatternsDecodeKeepsCommasInRegexes.
func stringToPatternsHookFunc() mapstructure.DecodeHookFuncType {
	return func(from, to reflect.Type, data any) (any, error) {
		if to != patternsType {
			return data, nil
		}
		// Empty key (`ref:`) -> empty Patterns, which the compiler rejects as
		// gating nothing; reached only because decoderOptions sets DecodeNil.
		if v := reflect.ValueOf(data); !v.IsValid() || ((v.Kind() == reflect.Slice || v.Kind() == reflect.Map) && v.IsNil()) {
			return Patterns{}, nil
		}
		if from.Kind() != reflect.String {
			return data, nil
		}
		return Patterns{reflect.ValueOf(data).String()}, nil
	}
}

// nilConditionHookFunc turns an empty `conditions:` key into an empty
// (non-nil) Condition, so it reaches compileConditionAt's gates-nothing
// check instead of leaving *Condition nil and authorizing unconditionally.
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
// pass (LoadConfig, MergeBytes, parseFragment). viper.DecodeHook REPLACES
// viper's default chain, so its defaults are re-composed here after ours.
func decoderOptions() []viper.DecoderConfigOption {
	return []viper.DecoderConfigOption{
		viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
			stringToPatternsHookFunc(),
			nilConditionHookFunc(),
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		)),
		// DecodeNil: affects only the two keys the hooks above claim.
		func(c *mapstructure.DecoderConfig) { c.DecodeNil = true },
	}
}
