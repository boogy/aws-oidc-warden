package logevent

import (
	"regexp"
	"testing"
)

// eventTypePattern widens the plan's ^[a-z]+(\.[a-z_]+)+$ to allow digits in non-leading segments, since the catalog itself requires it for "s3" (aws.s3.get.failure, aws.s3.object.oversize).
var eventTypePattern = regexp.MustCompile(`^[a-z]+(\.[a-z0-9_]+)+$`)

func TestCatalog_EveryEventMatchesTheNamingPattern(t *testing.T) {
	for _, e := range All() {
		if !eventTypePattern.MatchString(e.String()) {
			t.Errorf("event type %q does not match %s", e.String(), eventTypePattern)
		}
	}
}

func TestCatalog_EveryEventTypeIsUnique(t *testing.T) {
	seen := make(map[string]int, len(All()))
	for _, e := range All() {
		seen[e.String()]++
	}
	for eventType, count := range seen {
		if count > 1 {
			t.Errorf("event type %q registered %d times, want exactly once", eventType, count)
		}
	}
}

func TestCatalog_NonEmpty(t *testing.T) {
	if len(All()) == 0 {
		t.Fatal("catalog is empty, want the category files to have registered events")
	}
}
