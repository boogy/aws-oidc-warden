package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFragment_AllowedKeysOK(t *testing.T) {
	data := []byte(`
default_issuer: "https://issuer.example.com"
role_sets:
  prod: ["arn:aws:iam::111111111111:role/prod"]
role_mappings:
  - subject: "owner/repo"
    roles: ["arn:aws:iam::111111111111:role/ci"]
role_groups:
  - subjects: ["owner/a", "owner/b"]
    defaults:
      roles: ["arn:aws:iam::111111111111:role/ci"]
`)
	frag, err := parseFragment(data, "yaml", "frag1")
	require.NoError(t, err)
	assert.Equal(t, "https://issuer.example.com", frag.DefaultIssuer)
	assert.Equal(t, []string{"arn:aws:iam::111111111111:role/prod"}, frag.RoleSets["prod"])
	require.Len(t, frag.RoleMappings, 1)
	require.Len(t, frag.RoleGroups, 1)
}

func TestParseFragment_RejectsIssuers(t *testing.T) {
	data := []byte(`
issuers:
  - issuer: "https://evil.example.com"
    audiences: ["sts.amazonaws.com"]
`)
	_, err := parseFragment(data, "yaml", "frag1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"issuers"`)
}

func TestParseFragment_RejectsTagAuth(t *testing.T) {
	data := []byte(`
tag_auth:
  enabled: true
`)
	_, err := parseFragment(data, "yaml", "frag1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"tag_auth"`)
}

func TestParseFragment_RejectsAllowInsecureIssuers(t *testing.T) {
	data := []byte(`allow_insecure_issuers: true`)
	_, err := parseFragment(data, "yaml", "frag1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"allow_insecure_issuers"`)
}

func TestParseFragment_RejectsHardeningKnob(t *testing.T) {
	data := []byte(`jwt_leeway: 200s`)
	_, err := parseFragment(data, "yaml", "frag1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"jwt_leeway"`)
}

func TestParseFragment_RejectsConfigFragmentsItself(t *testing.T) {
	// A fragment must not be able to chain-load further fragments.
	data := []byte(`config_fragments: ["s3://bucket/other.yaml"]`)
	_, err := parseFragment(data, "yaml", "frag1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"config_fragments"`)
}

func TestMergeFragment_DefaultIssuerMustReferenceBaseIssuer(t *testing.T) {
	cfg := &Config{Issuers: singleIssuer("https://issuer-a.example.com", "sts.amazonaws.com")}
	frag := &FragmentConfig{DefaultIssuer: "https://unknown.example.com"}

	err := mergeFragment(cfg, frag, "frag1", map[string]bool{"https://issuer-a.example.com": true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a base-defined issuer")
}

func TestMergeFragment_DefaultIssuerConflict(t *testing.T) {
	baseIssuers := map[string]bool{"https://a.example.com": true, "https://b.example.com": true}
	cfg := &Config{DefaultIssuer: "https://a.example.com"}
	frag := &FragmentConfig{DefaultIssuer: "https://b.example.com"}

	err := mergeFragment(cfg, frag, "frag1", baseIssuers)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflicts with already-set")
}

func TestMergeFragment_DefaultIssuerIdempotentSameValue(t *testing.T) {
	baseIssuers := map[string]bool{"https://a.example.com": true}
	cfg := &Config{DefaultIssuer: "https://a.example.com"}
	frag := &FragmentConfig{DefaultIssuer: "https://a.example.com"}

	require.NoError(t, mergeFragment(cfg, frag, "frag1", baseIssuers))
	assert.Equal(t, "https://a.example.com", cfg.DefaultIssuer)
}

func TestMergeFragment_RoleSetCollision(t *testing.T) {
	cfg := &Config{RoleSets: map[string][]string{"prod": {"arn:aws:iam::111111111111:role/prod"}}}
	frag := &FragmentConfig{RoleSets: map[string][]string{"prod": {"arn:aws:iam::222222222222:role/evil"}}}

	err := mergeFragment(cfg, frag, "frag1", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"prod" collides`)
}

func TestMergeFragment_AppendsRoleMappingsAndGroupsInOrder(t *testing.T) {
	cfg := &Config{
		RoleMappings: []RoleMapping{{Subject: "base/repo", Roles: []string{"arn:aws:iam::111111111111:role/base"}}},
	}
	frag := &FragmentConfig{
		RoleMappings: []RoleMapping{{Subject: "frag/repo", Roles: []string{"arn:aws:iam::111111111111:role/frag"}}},
		RoleGroups:   []RoleGroup{{Subjects: []string{"frag/a"}}},
	}

	require.NoError(t, mergeFragment(cfg, frag, "frag1", nil))
	require.Len(t, cfg.RoleMappings, 2)
	assert.Equal(t, "base/repo", cfg.RoleMappings[0].Subject)
	assert.Equal(t, "frag/repo", cfg.RoleMappings[1].Subject)
	require.Len(t, cfg.RoleGroups, 1)
}

func TestIsRemoteFragment(t *testing.T) {
	assert.True(t, isRemoteFragment("s3://bucket/key.yaml"))
	assert.True(t, isRemoteFragment("https://example.com/frag.yaml"))
	assert.False(t, isRemoteFragment("/etc/aow/fragment.yaml"))
	assert.False(t, isRemoteFragment("relative/fragment.yaml"))
}

func TestReadLocalFragment_ReadsAndHashes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "frag.yaml")
	require.NoError(t, os.WriteFile(path, []byte("role_mappings: []\n"), 0o600))

	data, etag, err := readLocalFragment(path)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
	assert.Contains(t, etag, "sha256:")

	// Same content -> same etag (used for change detection).
	_, etag2, err := readLocalFragment(path)
	require.NoError(t, err)
	assert.Equal(t, etag, etag2)
}

func TestReadLocalFragment_BoundedRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.yaml")
	big := make([]byte, maxFragmentBytes+10)
	require.NoError(t, os.WriteFile(path, big, 0o600))

	_, _, err := readLocalFragment(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestReadLocalFragment_MissingFile(t *testing.T) {
	_, _, err := readLocalFragment(filepath.Join(t.TempDir(), "missing.yaml"))
	require.Error(t, err)
}
