package config

import (
	"testing"

	"github.com/boogy/aws-oidc-warden/internal/types"
)

func TestClaimTextAcceptsOpaqueClaim(t *testing.T) {
	cases := []struct {
		name string
		v    types.OpaqueClaim
		want string
	}{
		{"array rendering", types.OpaqueClaim("[break-glass]"), "[break-glass]"},
		{"object rendering", types.OpaqueClaim("map[break-glass:true]"), "map[break-glass:true]"},
		{"empty", types.OpaqueClaim(""), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := claimText(tc.v)
			if !ok {
				t.Fatalf("claimText(%q) reported unreadable, want readable", tc.v)
			}
			if got != tc.want {
				t.Fatalf("claimText(%q) = %q, want %q", tc.v, got, tc.want)
			}
		})
	}
}

func TestValueIsUndecidableTreatsOpaqueClaimAsUnreadable(t *testing.T) {
	cases := []types.OpaqueClaim{
		"[break-glass]",
		"map[break-glass:true]",
		"anything-at-all",
		"",
	}
	for _, v := range cases {
		if !valueIsUndecidable(v) {
			t.Fatalf("valueIsUndecidable(%q) = false, want true (OpaqueClaim must always be undecidable)", v)
		}
		if _, ok := claimText(v); !ok {
			t.Fatalf("claimText(%q) reported unreadable — the premise of the OpaqueClaim asymmetry test no longer holds", v)
		}
	}
}

func TestOpaqueClaimPositiveAndNoneOfAreNotComplements(t *testing.T) {
	claims := map[string]any{"groups": types.OpaqueClaim("[break-glass]")}

	// Pattern has no brackets: it does not literally match "[break-glass]",
	// isolating valueIsUndecidable's veto from an ordinary literal match.
	positive := condCfg(t, &Condition{Claims: map[string]Patterns{"groups": {"break-glass"}}})
	noneOf := condCfg(t, &Condition{NoneOf: []*Condition{
		{Claims: map[string]Patterns{"groups": {"break-glass"}}},
	}})

	if authorizes(positive, claims) {
		t.Fatal("bare predicate must deny: pattern does not match the opaque claim's literal text")
	}
	if authorizes(noneOf, claims) {
		t.Fatal("none_of must also deny: valueIsUndecidable must fire the veto")
	}
}
