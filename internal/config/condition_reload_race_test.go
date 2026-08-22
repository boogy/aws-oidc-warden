package config

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestHotReloadNestedConditionRace is the nested-tree counterpart of
// TestHotReloadConditionRace. A config_fragment's *Condition is reused across
// snapshots (applyFragments keeps the parsed fragment between reloads), and
// compileConditionAt mutates each node in place. cloneCondition must therefore
// deep-copy every nested group member: a SHALLOW clone leaves the inner nodes
// shared, so a reader can observe a nested node's compiled list transiently
// empty — and an empty node is TRUE, which makes the whole gate pass.
//
// A shallow clone still passes TestHotReloadConditionRace, because that test's
// condition is flat. This one is what pins the recursion.
//
// Run under -race: there must be no data race, and the loop must never
// authorize the privileged role under claims its condition rejects.
func TestHotReloadNestedConditionRace(t *testing.T) {
	const iss = "https://token.actions.githubusercontent.com"
	const prod = "arn:aws:iam::111111111111:role/prod"

	dir := t.TempDir()
	fragPath := filepath.Join(dir, "frag.yaml")
	if err := os.WriteFile(fragPath, []byte(`
role_mappings:
  - subject: "acme/app"
    roles: ["`+prod+`"]
    conditions:
      any_of:
        - all_of:
            - event_name: "push"
            - ref: "refs/heads/main"
        - all_of:
            - event_name: "workflow_dispatch"
            - actor_matches: ["release-bot"]
      none_of:
        - environment: "sandbox"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	base := &Config{
		Issuers:              []IssuerConfig{{Issuer: iss, Provider: "github", Audiences: []string{"sts.amazonaws.com"}}},
		DefaultIssuer:        iss,
		RoleSessionName:      "test",
		ConfigFragments:      []string{fragPath},
		ConfigReloadInterval: time.Nanosecond, // every MaybeRefresh is "due"
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}

	p := NewProvider(base, time.Nanosecond, "", nil)
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	var stop atomic.Bool
	var wg sync.WaitGroup

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				p.MaybeRefresh(ctx)
			}
		}()
	}

	// Two shapes that MUST be denied: one that no any_of member accepts, and
	// one that an any_of member accepts but the none_of vetoes.
	badClaims := []map[string]any{
		{"event_name": "push", "ref": "refs/heads/attacker"},
		{"event_name": "push", "ref": "refs/heads/main", "runner_environment": "sandbox"},
	}

	var bypasses atomic.Int64
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			claims := badClaims[i%len(badClaims)]
			for !stop.Load() {
				cfg := p.Get()
				if ok, roles := cfg.AuthorizeRoles(iss, "acme/app", claims); ok {
					for _, r := range roles {
						if r == prod {
							bypasses.Add(1)
						}
					}
				}
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	stop.Store(true)
	wg.Wait()

	if n := bypasses.Load(); n > 0 {
		t.Fatalf("%d authorization bypasses: prod role granted under rejected claims "+
			"while a nested condition was transiently blank during reload (regression: "+
			"cloneCondition must deep-copy every group member)", n)
	}

	// Sanity: both legitimate shapes still authorize after all the reloading.
	if ok, _ := p.Get().AuthorizeRoles(iss, "acme/app", map[string]any{"event_name": "push", "ref": "refs/heads/main"}); !ok {
		t.Fatal("prod role should still be authorized for a push to main")
	}
	if ok, _ := p.Get().AuthorizeRoles(iss, "acme/app", map[string]any{"event_name": "workflow_dispatch", "actor": "release-bot"}); !ok {
		t.Fatal("prod role should still be authorized for a release-bot dispatch")
	}
}
