package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/boogy/aws-oidc-warden/internal/utils"
	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// fragmentAllowedKeys is the config_fragments merge allowlist. Everything
// else (issuers, hardening knobs, tag_auth, ...) is base-only and rejected by
// rejectDisallowedFragmentKeys, checked against every key viper discovers
// (not just FragmentConfig's own fields), regardless of nesting depth.
var fragmentAllowedKeys = map[string]bool{
	"default_issuer": true,
	"role_sets":      true,
	"role_mappings":  true,
	"role_groups":    true,
}

// FragmentConfig is the schema for one config_fragments entry: a strict
// subset of Config — only the fields a fragment is allowed to contribute.
type FragmentConfig struct {
	DefaultIssuer string              `mapstructure:"default_issuer"`
	RoleSets      map[string][]string `mapstructure:"role_sets"`
	RoleMappings  []RoleMapping       `mapstructure:"role_mappings"`
	RoleGroups    []RoleGroup         `mapstructure:"role_groups"`
}

// parseFragment parses one fragment's raw bytes, rejecting any top-level or
// nested key outside fragmentAllowedKeys before unmarshalling. format is the
// viper config type, normally derived from the fragment's URI via FormatFromPath.
func parseFragment(data []byte, format, source string) (*FragmentConfig, error) {
	if format == "" {
		format = "json"
	}

	v := viper.New()
	v.SetConfigType(format)
	if err := v.ReadConfig(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("config fragment %q: failed to parse %s: %w", source, format, err)
	}

	if err := rejectDisallowedFragmentKeys(v.AllKeys()); err != nil {
		return nil, fmt.Errorf("config fragment %q: %w", source, err)
	}

	var frag FragmentConfig
	var md mapstructure.Metadata
	if err := v.Unmarshal(&frag, decoderOptions(&md)...); err != nil {
		return nil, fmt.Errorf("config fragment %q: failed to unmarshal: %w", source, err)
	}
	if err := rejectUnusedKeys(md.Unused, fmt.Sprintf("config fragment %q", source)); err != nil {
		return nil, err
	}
	return &frag, nil
}

// rejectDisallowedFragmentKeys errors on the first key (viper's dotted,
// fully-flattened set, e.g. "tag_auth.enabled") whose top-level segment is
// not in fragmentAllowedKeys.
func rejectDisallowedFragmentKeys(keys []string) error {
	for _, key := range keys {
		top := key
		if i := strings.IndexByte(key, '.'); i >= 0 {
			top = key[:i]
		}
		if !fragmentAllowedKeys[top] {
			return fmt.Errorf(
				"key %q is not allowed in a config fragment (only role_mappings, role_groups, "+
					"role_sets, default_issuer may be set here; issuers/hardening knobs/tag_auth/"+
					"allow_insecure_issuers are base-only)", top)
		}
	}
	return nil
}

// mergeFragment applies frag's allowed fields onto cfg; Validate() resolves and indexes them afterwards.
func mergeFragment(cfg *Config, frag *FragmentConfig, source string, baseIssuers map[string]bool) error {
	if frag.DefaultIssuer != "" {
		if !baseIssuers[frag.DefaultIssuer] {
			return fmt.Errorf("config fragment %q: default_issuer %q is not a base-defined issuer", source, frag.DefaultIssuer)
		}
		if cfg.DefaultIssuer != "" && cfg.DefaultIssuer != frag.DefaultIssuer {
			return fmt.Errorf("config fragment %q: default_issuer %q conflicts with already-set %q", source, frag.DefaultIssuer, cfg.DefaultIssuer)
		}
	}

	if len(frag.RoleSets) > 0 {
		// Sorted for a deterministic error on multiple collisions.
		names := make([]string, 0, len(frag.RoleSets))
		for name := range frag.RoleSets {
			names = append(names, name)
		}
		sort.Strings(names)

		if cfg.RoleSets == nil {
			cfg.RoleSets = make(map[string][]string, len(frag.RoleSets))
		}
		for _, name := range names {
			if _, exists := cfg.RoleSets[name]; exists {
				return fmt.Errorf("config fragment %q: role_sets %q collides with an already-defined role_set", source, name)
			}
			cfg.RoleSets[name] = frag.RoleSets[name]
		}
	}

	// The fragment's default binds only its own entries; cfg.DefaultIssuer is
	// never touched, so it cannot re-home another source's issuer-less entries.
	// The appended elements are copies, so the cached parse stays unmodified.
	nm, ng := len(cfg.RoleMappings), len(cfg.RoleGroups)
	cfg.RoleMappings = append(cfg.RoleMappings, frag.RoleMappings...)
	cfg.RoleGroups = append(cfg.RoleGroups, frag.RoleGroups...)
	if frag.DefaultIssuer != "" {
		for i := nm; i < len(cfg.RoleMappings); i++ {
			if cfg.RoleMappings[i].Issuer == "" {
				cfg.RoleMappings[i].Issuer = frag.DefaultIssuer
			}
		}
		for i := ng; i < len(cfg.RoleGroups); i++ {
			if cfg.RoleGroups[i].Issuer == "" {
				cfg.RoleGroups[i].Issuer = frag.DefaultIssuer
			}
		}
	}
	return nil
}

// isRemoteFragment reports whether uri names a remote source (delegated to
// the injected FragmentFetchFunc, e.g. "s3://...") vs. a local path.
func isRemoteFragment(uri string) bool {
	return strings.Contains(uri, "://")
}

// ContentDigest is the fragment etag: "sha256:" plus the hex digest of data.
func ContentDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// readLocalFragment reads a fragment bounded at limit bytes, with ContentDigest as its etag.
func readLocalFragment(path string, limit int) ([]byte, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open config fragment %q: %w", path, err)
	}
	defer func() {
		_ = f.Close()
	}()

	data, err := utils.ReadAllCapped(f, int64(limit), "config fragment")
	if err != nil {
		return nil, "", fmt.Errorf("failed to read config fragment %q: %w", path, err)
	}
	return data, ContentDigest(data), nil
}
