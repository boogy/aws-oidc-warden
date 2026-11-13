package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/boogy/aws-oidc-warden/internal/logevent"
	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// Patterns is a list of regex patterns OR'd together; decodes from a scalar or a list. Nil means the key was absent.
type Patterns []string

// patternsType is the decode target the mapstructure hook below keys on.
var patternsType = reflect.TypeFor[Patterns]()

// conditionPtrType is the decode target nilConditionHookFunc keys on.
var conditionPtrType = reflect.TypeFor[*Condition]()

// UnmarshalJSON mirrors the mapstructure hook's string-or-list decode: cloneConfig round-trips through encoding/json.
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

// stringToPatternsHookFunc decodes a scalar into Patterns; must precede StringToSliceHookFunc(",") so regex commas survive.
func stringToPatternsHookFunc() mapstructure.DecodeHookFuncType {
	return func(from, to reflect.Type, data any) (any, error) {
		if to != patternsType {
			return data, nil
		}
		// Empty key (`ref:`, `subject:`): empty Patterns, rejected later as gating nothing; needs DecodeNil.
		if v := reflect.ValueOf(data); !v.IsValid() || ((v.Kind() == reflect.Slice || v.Kind() == reflect.Map) && v.IsNil()) {
			return Patterns{}, nil
		}
		if from.Kind() != reflect.String {
			return data, nil
		}
		return Patterns{reflect.ValueOf(data).String()}, nil
	}
}

// nilConditionHookFunc turns an empty `conditions:` key into a non-nil empty Condition, which fails load instead of passing.
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

// decoderOptions returns the mapstructure options every config unmarshal must pass, re-composing viper's default hooks; md may be nil.
func decoderOptions(md *mapstructure.Metadata) []viper.DecoderConfigOption {
	return []viper.DecoderConfigOption{
		viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
			roleEntryHookFunc(),
			stringToPatternsHookFunc(),
			nilConditionHookFunc(),
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		)),
		// DecodeNil: affects only the keys the hooks above claim.
		func(c *mapstructure.DecoderConfig) { c.DecodeNil = true; c.Metadata = md },
	}
}

// fileOnly re-reads v's config file without env overrides.
func fileOnly(v *viper.Viper) (*viper.Viper, error) {
	f := viper.New()
	f.SetConfigFile(v.ConfigFileUsed())
	if err := f.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("problem re-reading config file: %w", err)
	}
	return f, nil
}

const removedTransitiveKey = "tag_auth.transitive_session_tags"

// rejectUnusedKeys fails on an unclaimed nested key; unused top-level keys only warn. v is read only for removedTransitiveKey and must not apply env overrides.
func rejectUnusedKeys(v *viper.Viper, unused []string, source string) error {
	unused = slices.Sorted(slices.Values(unused))
	for _, key := range unused {
		if key == removedTransitiveKey {
			if b, err := strconv.ParseBool(fmt.Sprint(v.Get(key))); err == nil && !b {
				continue
			}
			return fmt.Errorf("%s: %s was removed: use session_tags_transitive", source, key)
		}
		if strings.ContainsAny(key, ".[") {
			return fmt.Errorf("%s: unknown key %q is not a config field (check the spelling)", source, key)
		}
	}
	for _, key := range unused {
		if key == removedTransitiveKey {
			logevent.Warn(context.Background(), nil, logevent.ConfigWarning, "removed config key is ignored: use session_tags_transitive",
				slog.String("warning", "removed_config_key"),
				slog.String("key", key),
				slog.String("source", source))
			continue
		}
		logevent.Warn(context.Background(), nil, logevent.ConfigWarning, "unknown top-level config key is ignored",
			slog.String("warning", "unknown_config_key"),
			slog.String("key", key),
			slog.String("source", source))
	}
	return nil
}
