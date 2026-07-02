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

// maxFragmentBytes bounds the size of a single fetched/read fragment,
// mirroring the 1 MiB cap applied elsewhere to remote/S3-sourced documents
// (internal/handler's maxRemoteConfigSize for the primary config, and S3
// session policy reads).
const maxFragmentBytes = 1024 * 1024

// fragmentAllowedKeys is the config_fragments merge allowlist (SHARED.md
// invariant #9): a fragment may only ever contribute to the provider-neutral
// authorization surface. Everything else — issuers, hardening knobs,
// allow_insecure_issuers, tag_auth, config_fragments itself, etc. — is
// base-only and rejected by rejectDisallowedFragmentKeys regardless of how
// deeply it's nested (checked against every key viper discovers, not just
// FragmentConfig's own fields).
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

// parseFragment parses one fragment's raw bytes, rejecting any top-level (or
// nested) key outside fragmentAllowedKeys before unmarshalling — so a
// fragment can never smuggle in `issuers`, `tag_auth`,
// `allow_insecure_issuers`, or any other base-only setting (invariant #9).
// format is the viper config type, normally derived from the fragment's URI
// via FormatFromPath.
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
	if err := v.Unmarshal(&frag); err != nil {
		return nil, fmt.Errorf("config fragment %q: failed to unmarshal: %w", source, err)
	}
	return &frag, nil
}

// rejectDisallowedFragmentKeys errors on the first key (from viper's dotted,
// fully-flattened key set — e.g. "tag_auth.enabled") whose top-level segment
// is not in fragmentAllowedKeys.
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
//   - default_issuer must reference a base-defined issuer (S5) and, if
//     already set (by the base config or an earlier-merged fragment) to a
//     different value, is rejected as an ambiguous/conflicting override —
//     the resolved default must never depend on fragment fetch order.
//   - role_sets are merged by name; a name colliding with an existing
//     base/earlier-fragment role_set is rejected — a fragment silently
//     redefining e.g. "@prod" would repoint every mapping that already
//     references it, a security-relevant change fragments must not make
//     unilaterally.
//   - role_mappings/role_groups are appended in fragment (then declaration)
//     order; issuer resolution, role_set expansion, pattern compilation and
//     indexing all happen later in the single, shared Validate() pass
//     (config.go) — mergeFragment itself does no resolving/compiling.
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
		// Sorted iteration keeps a multi-collision error message deterministic;
		// the collision check itself is order-independent.
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
// the injected FragmentFetchFunc, e.g. "s3://...") rather than a local
// filesystem path.
func isRemoteFragment(uri string) bool {
	return strings.Contains(uri, "://")
}

// readLocalFragment reads a fragment from the local filesystem (a
// config_fragments entry with no "scheme://" prefix — e.g. a bind-mounted
// file in local/dev use), bounding the read at maxFragmentBytes and
// computing a sha256 content hash as its etag (local files have no native
// ETag; this also lets an unchanged local fragment be recognized and skip
// re-parsing, same as a remote one — see Provider.applyFragments).
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
