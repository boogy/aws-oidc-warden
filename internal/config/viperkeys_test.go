package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/require"
)

// The config loader case-folds every map KEY it reads and splits it on ".".
// Operator-supplied strings that must survive verbatim therefore cannot be
// written as config keys. These tests pin the two places that got it wrong,
// through the YAML path — the struct-literal tests that already covered both
// features could not see the problem, because they never went through the
// loader at all.

// TestFragmentChecksumPinsDottedPath is the regression that motivated moving
// config_fragment_checksums from a map to a list: as a map keyed by URI, the
// loader split "/…/team.yaml" at the dot into a nested map and failed to
// decode. Since every fragment path ends in .yaml or .yml, the integrity pin
// could not be applied to any fragment that actually existed.
func TestFragmentChecksumPinsDottedPath(t *testing.T) {
	dir := t.TempDir()
	frag := filepath.Join(dir, "team-platform.yaml")
	require.NoError(t, os.WriteFile(frag, []byte("role_mappings: []\n"), 0o600))

	cfg := baseConfig(t)
	src := `
config_fragments:
  - "` + frag + `"
config_fragment_checksums:
  - uri: "` + frag + `"
    checksum: "sha256:a1b2c3"
`
	require.NoError(t, cfg.MergeBytes([]byte(src), "yaml"))
	require.Len(t, cfg.ConfigFragmentChecksums, 1)
	// The URI is a value now, so it arrives byte-for-byte as written:
	// full path, dot intact, case intact.
	require.Equal(t, frag, cfg.ConfigFragmentChecksums[0].URI)
	require.Equal(t, "sha256:a1b2c3", cfg.ConfigFragmentChecksums[0].Checksum)
}

// TestFragmentChecksumRejectsInertPin: a pin naming a URI no config_fragments
// entry lists is never consulted, so the fragment is unpinned while the config
// reads as though it were pinned. That is the one state the pin exists to
// prevent, so it must not boot.
func TestFragmentChecksumRejectsInertPin(t *testing.T) {
	cfg := baseConfig(t)
	src := `
config_fragment_checksums:
  - uri: "/etc/aws-oidc-warden/fragments/never-listed.yaml"
    checksum: "sha256:a1b2c3"
`
	err := cfg.MergeBytes([]byte(src), "yaml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not listed in config_fragments")
}

// TestRoleSetReferenceIsCaseInsensitive: a role_set NAME is a config key and
// is folded on load; the "@name" reference is a config value and is not. A
// mixed-case name therefore could not be referenced from the same file that
// defined it.
func TestRoleSetReferenceIsCaseInsensitive(t *testing.T) {
	cfg := baseConfig(t)
	src := `
role_sets:
  ProdDeployers:
    - "arn:aws:iam::123456789012:role/Deploy"
role_mappings:
  - subject: "octo-org/api"
    roles: ["@ProdDeployers"]
`
	require.NoError(t, cfg.MergeBytes([]byte(src), "yaml"))
	ok, roles := cfg.AuthorizeRoles(
		"https://token.actions.githubusercontent.com",
		"octo-org/api",
		map[string]any{},
	)
	require.True(t, ok)
	require.Equal(t, []string{"arn:aws:iam::123456789012:role/Deploy"}, roles)
}

// baseConfig is the surrounding config a documentation fragment is read
// against: the issuers the guides refer to, plus the globals a bare
// role_mappings block needs to validate. A block that declares its own
// issuers replaces these (MergeBytes clears c.Issuers when the payload
// declares the key).
//
// The role_sets are the ones the guides define once near the top of a page
// and then reference by name in later snippets: a fenced block is extracted
// on its own, so it legitimately depends on context earlier in its document.
// Seeding them here keeps the test measuring "is this example correct" rather
// than "is this example self-contained", which is not a property the docs
// claim or should have to.
func baseConfig(t *testing.T) *config.Config {
	t.Helper()
	const base = `
issuers:
  - issuer: "https://token.actions.githubusercontent.com"
    provider: "github"
    audiences: ["sts.amazonaws.com"]
  - issuer: "https://gitlab.com"
    provider: "generic"
    audiences: ["https://gitlab.com"]
    claim_mappings:
      subject: "project_path"
default_issuer: "https://token.actions.githubusercontent.com"
role_session_name: "aws-oidc-warden"
role_sets:
  readonly: ["arn:aws:iam::123456789012:role/DocReadonly"]
  deployers: ["arn:aws:iam::123456789012:role/DocDeployers"]
`
	cfg := &config.Config{}
	require.NoError(t, cfg.MergeBytes([]byte(base), "yaml"), "the test's own base fixture must be valid")
	return cfg
}
