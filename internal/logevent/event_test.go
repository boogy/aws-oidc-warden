package logevent

import (
	"sort"
	"testing"
)

func TestEvent_Category(t *testing.T) {
	for _, tc := range []struct {
		name string
		e    Event
		want string
	}{
		{"sts event", STSAssumeRoleFailure, "sts"},
		{"cache event", CacheHit, "cache"},
		{"app event", AppStart, "app"},
		{"multi-segment type", Event{typ: "authz.tag_auth.lookup_failure"}, "authz"},
		{"no dot falls back to whole type", Event{typ: "nodot"}, "nodot"},
		{"empty type", Event{typ: ""}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.e.Category(); got != tc.want {
				t.Errorf("Category() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEvent_String(t *testing.T) {
	if got := STSAssumeRoleFailure.String(); got != "sts.assume_role.failure" {
		t.Errorf("String() = %q, want sts.assume_role.failure", got)
	}
}

func TestDeriveOutcome(t *testing.T) {
	for _, tc := range []struct {
		eventType string
		want      string
	}{
		{"sts.assume_role.success", "success"},
		{"sts.assume_role.failure", "failure"},
		{"cache.hit", ""},
		{"authz.decision", ""},
		{"a.successful", ""},
		{"a.failured", ""},
		{"nodot", ""},
		{"", ""},
	} {
		t.Run(tc.eventType, func(t *testing.T) {
			if got := deriveOutcome(tc.eventType); got != tc.want {
				t.Errorf("deriveOutcome(%q) = %q, want %q", tc.eventType, got, tc.want)
			}
		})
	}
}

func TestNewEvent_DerivesOutcomeAndRegisters(t *testing.T) {
	if STSAssumeRoleSuccess.outcome != "success" {
		t.Errorf("STSAssumeRoleSuccess.outcome = %q, want success", STSAssumeRoleSuccess.outcome)
	}
	if STSAssumeRoleFailure.outcome != "failure" {
		t.Errorf("STSAssumeRoleFailure.outcome = %q, want failure", STSAssumeRoleFailure.outcome)
	}
	if CacheHit.outcome != "" {
		t.Errorf("CacheHit.outcome = %q, want empty (no derivable suffix)", CacheHit.outcome)
	}
	if AuthzDecision.outcome != "" {
		t.Errorf("AuthzDecision.outcome = %q, want empty until WithOutcome is applied", AuthzDecision.outcome)
	}

	found := false
	for _, e := range All() {
		if e == CacheHit {
			found = true
			break
		}
	}
	if !found {
		t.Error("All() does not contain CacheHit, want every category var registered")
	}
}

func TestEvent_WithOutcome(t *testing.T) {
	allow := AuthzDecision.WithOutcome("allow")
	if allow.outcome != "allow" {
		t.Errorf("WithOutcome(%q).outcome = %q, want allow", "allow", allow.outcome)
	}
	if allow.typ != AuthzDecision.typ {
		t.Errorf("WithOutcome must preserve type, got %q want %q", allow.typ, AuthzDecision.typ)
	}
	if AuthzDecision.outcome != "" {
		t.Errorf("WithOutcome must not mutate the original event, AuthzDecision.outcome = %q", AuthzDecision.outcome)
	}

	deny := AuthzDecision.WithOutcome("deny")
	if deny.outcome != "deny" || allow.outcome != "allow" {
		t.Error("WithOutcome results must be independent copies")
	}
}

func TestAll_ReturnedSliceIsACopy(t *testing.T) {
	got := All()
	if len(got) == 0 {
		t.Fatal("All() returned no events, want the full catalog")
	}
	before := registry[0]
	got[0].typ = "mutated"
	if registry[0] != before {
		t.Error("mutating All()'s result must not affect the package registry")
	}
}

func TestAll_IsSortedByType(t *testing.T) {
	got := All()
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i].typ < got[j].typ }) {
		t.Error("All() must return events sorted by type")
	}
}
