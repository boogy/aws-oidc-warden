package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/config"
	"github.com/stretchr/testify/require"
)

// TestDocumentedYAMLLoadsAndValidates runs every configuration example in the
// prose documentation through the real loader.
//
// example-config.yaml has TestExampleConfigLoadsAndValidates, but the YAML in
// README.md and docs/*.md — which is what a reader actually copies while
// following a guide — was checked by nothing. A key renamed in the engine, a
// pattern that Validate() now rejects, or an example carried forward from v2
// would sit there indefinitely: the suite would stay green and the docs would
// be wrong. Documentation accuracy is only durable if it is enforced.
//
// Blocks that are not warden configuration (GitHub Actions workflows, the
// deliberately-obsolete v1 example in MIGRATION_V2.md) are skipped by looking
// at their top-level keys, and the known-key set is derived by reflection from
// config.Config itself so it cannot drift from the struct.
func TestDocumentedYAMLLoadsAndValidates(t *testing.T) {
	known := topLevelConfigKeys()
	require.NotEmpty(t, known)

	files := docFiles(t)
	require.NotEmpty(t, files, "no documentation found to check")

	checked := 0
	for _, f := range files {
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		for _, b := range yamlBlocks(string(src)) {
			body, kind := classifyBlock(b.body, known)
			if kind == blockSkip {
				continue
			}
			checked++
			name := fmt.Sprintf("%s:%d", filepath.Base(f), b.line)
			t.Run(name, func(t *testing.T) {
				if kind == blockUnknownKey {
					t.Fatalf("documented example at %s:%d has top-level key(s) %s "+
						"that config.Config does not define; the loader ignores "+
						"unknown keys silently, so this example would appear to "+
						"work and configure nothing", f, b.line, body)
				}
				cfg := baseConfig(t)
				require.NoError(t, cfg.MergeBytes([]byte(body), "yaml"),
					"documented example at %s:%d does not load", f, b.line)
			})
		}
	}
	// A refactor that broke extraction would silently check nothing and pass.
	require.GreaterOrEqual(t, checked, 15, "expected the doc set to yield config examples; extraction is probably broken")
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

type blockKind int

const (
	blockSkip blockKind = iota
	blockConfig
	blockUnknownKey
)

// nonConfigMarkers name top-level keys that positively identify a block as
// something other than warden configuration: GitHub Actions workflow YAML, and
// the deliberately-obsolete v1 shape quoted in MIGRATION_V2.md.
//
// Skipping is driven off THIS list rather than off "any key I do not
// recognize". The old rule made a single unknown key hide the whole block, so
// an example carrying one stale or misspelled key — precisely what this test
// exists to catch — was silently skipped and reported as a pass. The loader
// cannot backstop it either: an unknown top-level key is ignored, not
// rejected, so `repo_role_mappings` parses to zero mappings without error.
var nonConfigMarkers = map[string]bool{
	"name": true, "on": true, "jobs": true, "steps": true,
	"runs-on": true, "permissions": true, "uses": true, "with": true,
	"repo_role_mappings": true, "repo_role_groups": true, "constraints": true,
}

// classifyBlock decides whether a fenced yaml block is warden configuration,
// and normalizes a bare `conditions:` fragment into the role_mappings entry it
// is written to live inside.
func classifyBlock(body string, known map[string]bool) (string, blockKind) {
	top := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		k, _, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		top[strings.TrimSpace(k)] = true
	}
	if len(top) == 0 {
		return "", blockSkip
	}
	if len(top) == 1 && top["conditions"] {
		var b strings.Builder
		b.WriteString("role_mappings:\n  - subject: \"org/repo\"\n    roles: [\"arn:aws:iam::123456789012:role/DocExample\"]\n")
		for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
			if line == "" {
				b.WriteString("\n")
				continue
			}
			b.WriteString("    " + line + "\n")
		}
		return b.String(), blockConfig
	}
	for k := range top {
		if nonConfigMarkers[k] {
			return "", blockSkip
		}
	}
	var knownCount int
	var unknown []string
	for k := range top {
		if known[k] {
			knownCount++
		} else {
			unknown = append(unknown, k)
		}
	}
	if knownCount == 0 {
		return "", blockSkip
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return strings.Join(unknown, ", "), blockUnknownKey
	}
	return body, blockConfig
}

// topLevelConfigKeys reads the mapstructure tags off config.Config, so the
// skip heuristic tracks the struct instead of a hand-maintained list.
func topLevelConfigKeys() map[string]bool {
	out := map[string]bool{}
	ty := reflect.TypeOf(config.Config{})
	for i := range ty.NumField() {
		tag, _, _ := strings.Cut(ty.Field(i).Tag.Get("mapstructure"), ",")
		if tag != "" && tag != "-" {
			out[tag] = true
		}
	}
	return out
}

type yamlBlock struct {
	body string
	line int
}

var yamlFence = regexp.MustCompile("(?s)```yaml\n(.*?)```")

func yamlBlocks(src string) []yamlBlock {
	var out []yamlBlock
	for _, m := range yamlFence.FindAllStringSubmatchIndex(src, -1) {
		out = append(out, yamlBlock{
			body: src[m[2]:m[3]],
			line: strings.Count(src[:m[0]], "\n") + 1,
		})
	}
	return out
}

func docFiles(t *testing.T) []string {
	t.Helper()
	files := []string{"../../README.md"}
	// docs/*.md is the bulk of the prose, but a reader following the
	// cross-account example copies YAML out of docs/examples/ too, and that
	// tree was outside the sweep. Glob both levels rather than naming files,
	// so a new guide is covered the day it is added.
	for _, pat := range []string{"../../docs/*.md", "../../docs/examples/*/*.md"} {
		entries, err := filepath.Glob(pat)
		require.NoError(t, err)
		files = append(files, entries...)
	}
	return files
}

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

// exampleConfigPath is the file shipped at the repo root and pointed at by the
// README, `make run`, and every deployment guide.
const exampleConfigPath = "../../example-config.yaml"

// TestExampleConfigLoadsAndValidates guards the one config an operator is most
// likely to copy. Nothing else in the suite reads it, so a key renamed in the
// engine could leave the shipped example rejecting at boot — or, worse,
// loading with a different meaning — and every test would still pass.
func TestExampleConfigLoadsAndValidates(t *testing.T) {
	data, err := os.ReadFile(exampleConfigPath)
	require.NoError(t, err)

	cfg := &config.Config{}
	require.NoError(t, cfg.MergeBytes(data, "yaml"), "example-config.yaml must load and validate")

	require.NotEmpty(t, cfg.Issuers)
	require.NotEmpty(t, cfg.RoleMappings)

	// Spot-check the mappings whose conditions carry the v3 semantics, through
	// the real authorization path. Each pair is the same subject with and
	// without the claim the example gates on, so a mapping that silently
	// stopped gating (or started denying) shows up here.
	const gh = "https://token.actions.githubusercontent.com"
	cases := []struct {
		name    string
		subject string
		claims  map[string]any
		want    bool
	}{
		{
			name:    "deployment environment gates prod",
			subject: "org/prod-repo",
			claims: map[string]any{
				"ref": "refs/tags/v1.2.3", "ref_type": "tag",
				"environment": "production", "runner_environment": "github-hosted",
				"actor": "release-bot", "sha": "0123456789abcdef0123456789abcdef01234567",
			},
			want: true,
		},
		{
			name:    "runner type is not the deployment environment",
			subject: "org/prod-repo",
			claims: map[string]any{
				"ref": "refs/tags/v1.2.3", "ref_type": "tag",
				"environment": "github-hosted", "runner_environment": "github-hosted",
				"actor": "release-bot", "sha": "0123456789abcdef0123456789abcdef01234567",
			},
			want: false,
		},
		{
			name:    "pull-request gate needs every claim",
			subject: "org/pr-checks",
			claims: map[string]any{
				"event_name": "pull_request", "base_ref": "main",
				"repository_visibility": "public", "ref_protected": "true",
			},
			want: true,
		},
		{
			name:    "pull-request gate denies an unprotected ref",
			subject: "org/pr-checks",
			claims: map[string]any{
				"event_name": "pull_request", "base_ref": "main",
				"repository_visibility": "public", "ref_protected": "false",
			},
			want: false,
		},
		{
			name:    "none_of members veto independently",
			subject: "org/guarded-repo",
			claims:  map[string]any{"ref": "refs/heads/main"},
			want:    true,
		},
		{
			name:    "a self-hosted runner alone is vetoed",
			subject: "org/guarded-repo",
			claims:  map[string]any{"ref": "refs/heads/main", "runner_environment": "self-hosted"},
			want:    false,
		},
		{
			name:    "a dispatched run alone is vetoed",
			subject: "org/guarded-repo",
			claims:  map[string]any{"ref": "refs/heads/main", "event_name": "workflow_dispatch"},
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, roles := cfg.AuthorizeRoles(gh, tc.subject, tc.claims)
			require.Equal(t, tc.want, ok)
			if tc.want {
				require.NotEmpty(t, roles)
			}
		})
	}
}

// TestExampleConfigGenericIssuer exercises the GitLab (`provider: generic`)
// half of the shipped example through the same authorization path.
//
// TestExampleConfigLoadsAndValidates only drives the GitHub issuer, so every
// generic-issuer line in the example — the claim-native condition keys that
// name GitLab's own claims, the list-valued `groups` claim, and the issuer
// binding that keeps the two issuers' subject namespaces apart — was shipped
// unexercised. That is the half of the config a non-GitHub operator copies.
func TestExampleConfigGenericIssuer(t *testing.T) {
	data, err := os.ReadFile(exampleConfigPath)
	require.NoError(t, err)

	cfg := &config.Config{}
	require.NoError(t, cfg.MergeBytes(data, "yaml"))

	const (
		gitlab = "https://gitlab.com"
		gh     = "https://token.actions.githubusercontent.com"
		subj   = "mygroup/myproject"
	)

	// The canonical subject for this issuer comes from claim_mappings.subject,
	// so the example must map it — a generic issuer without it is a Validate()
	// error, and the mapping below could never be reached.
	var gitlabSpec *config.IssuerConfig
	for i := range cfg.Issuers {
		if cfg.Issuers[i].Issuer == gitlab {
			gitlabSpec = &cfg.Issuers[i]
		}
	}
	require.NotNil(t, gitlabSpec, "the example must keep a generic issuer")
	require.Equal(t, "generic", gitlabSpec.Provider)
	require.NotEmpty(t, gitlabSpec.ClaimMappings["subject"])

	base := func() map[string]any {
		return map[string]any{
			"ref":          "main",
			"project_path": subj,
			"groups":       []any{"platform-team", "docs"},
		}
	}

	cases := []struct {
		name    string
		issuer  string
		subject string
		mutate  func(map[string]any)
		want    bool
	}{
		{name: "every claim-native condition satisfied", issuer: gitlab, subject: subj, want: true},
		{
			name: "list claim matches on any element", issuer: gitlab, subject: subj,
			mutate: func(c map[string]any) { c["groups"] = []any{"unrelated", "sre"} },
			want:   true,
		},
		{
			name: "no group matches", issuer: gitlab, subject: subj,
			mutate: func(c map[string]any) { c["groups"] = []any{"contractors"} },
			want:   false,
		},
		{
			name: "the groups claim is absent", issuer: gitlab, subject: subj,
			mutate: func(c map[string]any) { delete(c, "groups") },
			want:   false,
		},
		{
			name: "a GitLab-named claim still gates", issuer: gitlab, subject: subj,
			mutate: func(c map[string]any) { c["project_path"] = "other/project" },
			want:   false,
		},
		{
			name: "the ref condition still gates", issuer: gitlab, subject: subj,
			mutate: func(c map[string]any) { c["ref"] = "feature/x" },
			want:   false,
		},
		// Issuer binding: the same subject string presented by the other
		// configured issuer must not reach this mapping.
		{name: "same subject, wrong issuer", issuer: gh, subject: subj, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := base()
			if tc.mutate != nil {
				tc.mutate(claims)
			}
			ok, roles := cfg.AuthorizeRoles(tc.issuer, tc.subject, claims)
			require.Equal(t, tc.want, ok)
			if tc.want {
				require.NotEmpty(t, roles)
			}
		})
	}
}
