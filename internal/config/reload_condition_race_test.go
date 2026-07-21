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

// TestHotReloadConditionRace is the regression test for the hot-reload
// condition race. A config_fragment's *Condition used to be shared across every
// config snapshot (mergeFragment copies RoleMapping by value but shared the
// Conditions pointer, and applyFragments reuses the parsed fragment across
// reloads). Each reload's Validate()->compileCondition mutated that shared
// struct in place (cond.compiled = cond.compiled[:0]) while concurrent requests
// read the currently-served snapshot through Get() with no lock — so a reader
// could observe compiled transiently empty and satisfiesConditions would return
// true, silently passing all conditions (an authorization bypass).
//
// The fix clones each condition into effective-private memory before compiling
// (see cloneCondition / appendEffective), so compileCondition never mutates a
// struct another snapshot is reading.
//
// Run under -race: with the fix there must be no data race, and the loop must
// never authorize the privileged role on a branch its condition rejects.
func TestHotReloadConditionRace(t *testing.T) {
	const iss = "https://token.actions.githubusercontent.com"
	const prod = "arn:aws:iam::111111111111:role/prod"

	dir := t.TempDir()
	fragPath := filepath.Join(dir, "frag.yaml")
	if err := os.WriteFile(fragPath, []byte(`
role_mappings:
  - subject: "acme/app"
    roles: ["`+prod+`"]
    conditions:
      ref: "refs/heads/main"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	base := &Config{
		Issuers:              []IssuerConfig{{Issuer: iss, Provider: "github", Audiences: []string{"sts.amazonaws.com"}}},
		DefaultIssuer:        iss,
		RoleSessionName:      "s",
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

	// Reloaders: keep hot-reloading; each reload recompiles the fragment's
	// conditions.
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				p.MaybeRefresh(ctx)
			}
		}()
	}

	// Readers: authorize on a branch that MUST be rejected. Any grant is a
	// condition bypass.
	var bypasses atomic.Int64
	badClaims := map[string]any{"ref": "refs/heads/attacker"}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				cfg := p.Get()
				if ok, roles := cfg.AuthorizeRoles(iss, "acme/app", badClaims); ok {
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
		t.Fatalf("%d authorization bypasses: prod role granted on refs/heads/attacker "+
			"while conditions were transiently blank during reload (regression)", n)
	}

	// Sanity: the legitimate branch is still authorized after all the reloading.
	if ok, _ := p.Get().AuthorizeRoles(iss, "acme/app", map[string]any{"ref": "refs/heads/main"}); !ok {
		t.Fatal("prod role should still be authorized on refs/heads/main")
	}
}
