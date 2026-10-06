package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"

	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// Patterns is a list of regex patterns OR'd together — one claim's patterns in
// a condition, or a role_mapping's subjects; decodes from a scalar or a list.
// Nil means the key was absent; an explicit empty list is rejected as gating
// nothing (compileConditionAt for conditions, appendEffective for subjects).
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
		return fmt.Errorf("pattern must be a string or a list of strings: %w", err)
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
		// Empty key (`ref:`, `subject:`) -> empty Patterns, which the compiler
		// rejects as gating nothing; reached only because DecodeNil is set.
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
//
// md, when non-nil, receives the decode metadata; see rejectUnusedKeys.
func decoderOptions(md *mapstructure.Metadata) []viper.DecoderConfigOption {
	return []viper.DecoderConfigOption{
		viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
			stringToPatternsHookFunc(),
			nilConditionHookFunc(),
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		)),
		// DecodeNil: affects only the two keys the hooks above claim.
		func(c *mapstructure.DecoderConfig) { c.DecodeNil = true; c.Metadata = md },
	}
}

// rejectUnusedKeys fails on a nested key no struct field claimed
// (role_mappings[0].condtions, tag_auth.enabeld): such a typo silently drops
// the setting it was meant to carry. An unused top-level key only warns, so
// holder keys such as YAML anchors (x-anchors) keep loading.
func rejectUnusedKeys(unused []string, source string) error {
	unused = slices.Sorted(slices.Values(unused))
	for _, key := range unused {
		if strings.ContainsAny(key, ".[") {
			return fmt.Errorf("%s: unknown key %q is not a config field (check the spelling)", source, key)
		}
	}
	for _, key := range unused {
		logevent.Warn(context.Background(), nil, logevent.ConfigWarning, "unknown top-level config key is ignored",
			slog.String("warning", "unknown_config_key"),
			slog.String("key", key),
			slog.String("source", source))
	}
	return nil
}
