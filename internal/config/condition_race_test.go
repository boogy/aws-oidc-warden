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

// hotReloadRace hot-reloads a fragment-backed config from two goroutines while
// four readers authorize with claims the fragment's conditions must reject.
//
// A config_fragment's *Condition is reused across snapshots (applyFragments
// keeps the parsed fragment between reloads) and compileConditionAt mutates
// each node in place (cond.compiled = cond.compiled[:0]). Readers take the
// served snapshot through Get() with no lock, so a shared condition can be
// observed transiently blank — and a blank node is TRUE, which passes the gate.
// cloneCondition, which copies into effective-private memory before compiling,
// is what prevents it.
//
// Run under -race: no data race, and no grant of prod under denied claims.
func hotReloadRace(t *testing.T, conditions string, denied []map[string]any, allowed ...map[string]any) {
	t.Helper()

	const iss = "https://token.actions.githubusercontent.com"
	const prod = "arn:aws:iam::111111111111:role/prod"

	fragPath := filepath.Join(t.TempDir(), "frag.yaml")
	if err := os.WriteFile(fragPath, []byte(`
role_mappings:
  - subject: "acme/app"
    roles: ["`+prod+`"]
    conditions:
`+conditions), 0o600); err != nil {
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
	ctx := context.Background()
	if err := p.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	var stop atomic.Bool
	var bypasses atomic.Int64
	var wg sync.WaitGroup

	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				p.MaybeRefresh(ctx)
			}
		}()
	}
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			claims := denied[i%len(denied)]
			for !stop.Load() {
				ok, roles := p.Get().AuthorizeRoles(iss, "acme/app", claims)
				if !ok {
					continue
				}
				for _, r := range roles {
					if r == prod {
						bypasses.Add(1)
					}
				}
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	stop.Store(true)
	wg.Wait()

	if n := bypasses.Load(); n > 0 {
		t.Fatalf("%d authorization bypasses: prod granted under claims its conditions reject, "+
			"while a condition was transiently blank during reload", n)
	}

	// Sanity: all the reloading did not break the grants that should hold.
	for _, claims := range allowed {
		if ok, _ := p.Get().AuthorizeRoles(iss, "acme/app", claims); !ok {
			t.Fatalf("prod should still be authorized for %v", claims)
		}
	}
}

func TestHotReloadConditionRace(t *testing.T) {
	hotReloadRace(t,
		`      ref: "refs/heads/main"`+"\n",
		[]map[string]any{{"ref": "refs/heads/attacker"}},
		map[string]any{"ref": "refs/heads/main"},
	)
}

// TestHotReloadNestedConditionRace is what pins the recursion in
// cloneCondition. A SHALLOW clone leaves the nested nodes shared and still
// passes the flat test above, because that condition has no children.
func TestHotReloadNestedConditionRace(t *testing.T) {
	hotReloadRace(t, `      any_of:
        - all_of:
            - event_name: "push"
            - ref: "refs/heads/main"
        - all_of:
            - event_name: "workflow_dispatch"
            - actor: ["release-bot"]
      none_of:
        - runner_environment: "sandbox"
`,
		// One shape no any_of member accepts, and one a member accepts but the
		// none_of vetoes.
		[]map[string]any{
			{"event_name": "push", "ref": "refs/heads/attacker"},
			{"event_name": "push", "ref": "refs/heads/main", "runner_environment": "sandbox"},
		},
		map[string]any{"event_name": "push", "ref": "refs/heads/main"},
		map[string]any{"event_name": "workflow_dispatch", "actor": "release-bot"},
	)
}
