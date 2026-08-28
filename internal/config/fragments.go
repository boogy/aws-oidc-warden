package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/viper"
)

// maxFragmentBytes mirrors the 1 MiB cap applied elsewhere to remote/S3-sourced
// documents (internal/handler's maxRemoteConfigSize, S3 session policy reads).
const maxFragmentBytes = 1024 * 1024

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
	if err := v.Unmarshal(&frag, decoderOptions()...); err != nil {
		return nil, fmt.Errorf("config fragment %q: failed to unmarshal: %w", source, err)
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

// mergeFragment applies frag's allowed fields onto cfg:
//   - default_issuer must be base-defined; a conflicting value from an
//     earlier fragment/base is rejected (result must not depend on fetch order).
//   - role_sets are merged by name; a name colliding with an existing
//     role_set is rejected, so a fragment can't silently repoint "@prod".
//   - role_mappings/role_groups are appended; resolution/compilation/indexing
//     happen later in Validate() (config.go), not here.
func mergeFragment(cfg *Config, frag *FragmentConfig, source string, baseIssuers map[string]bool) error {
	if frag.DefaultIssuer != "" {
		if !baseIssuers[frag.DefaultIssuer] {
			return fmt.Errorf("config fragment %q: default_issuer %q is not a base-defined issuer", source, frag.DefaultIssuer)
		}
		if cfg.DefaultIssuer != "" && cfg.DefaultIssuer != frag.DefaultIssuer {
			return fmt.Errorf("config fragment %q: default_issuer %q conflicts with already-set %q", source, frag.DefaultIssuer, cfg.DefaultIssuer)
		}
		cfg.DefaultIssuer = frag.DefaultIssuer
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

	cfg.RoleMappings = append(cfg.RoleMappings, frag.RoleMappings...)
	cfg.RoleGroups = append(cfg.RoleGroups, frag.RoleGroups...)
	return nil
}

// isRemoteFragment reports whether uri names a remote source (delegated to
// the injected FragmentFetchFunc, e.g. "s3://...") vs. a local path.
func isRemoteFragment(uri string) bool {
	return strings.Contains(uri, "://")
}

// readLocalFragment reads a fragment from the local filesystem, bounded at
// maxFragmentBytes, with a sha256 content hash as its etag (local files have
// no native ETag; lets Provider.applyFragments skip re-parsing when unchanged).
func readLocalFragment(path string) ([]byte, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open config fragment %q: %w", path, err)
	}
	defer func() {
		_ = f.Close()
	}()

	data, err := io.ReadAll(io.LimitReader(f, maxFragmentBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("failed to read config fragment %q: %w", path, err)
	}
	if len(data) > maxFragmentBytes {
		return nil, "", fmt.Errorf("config fragment %q exceeds %d byte cap", path, maxFragmentBytes)
	}

	sum := sha256.Sum256(data)
	return data, "sha256:" + hex.EncodeToString(sum[:]), nil
}
