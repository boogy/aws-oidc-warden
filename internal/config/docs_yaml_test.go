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
