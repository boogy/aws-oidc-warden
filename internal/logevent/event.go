package logevent

import (
	"sort"
	"strings"
)

// Event is a catalog log event: a dot-separated type plus an optional outcome.
type Event struct {
	typ     string
	outcome string
}

var registry []Event

// newEvent registers a catalog event, deriving outcome from a .success/.failure suffix.
func newEvent(eventType string) Event {
	e := Event{typ: eventType, outcome: deriveOutcome(eventType)}
	registry = append(registry, e)
	return e
}

func deriveOutcome(eventType string) string {
	last := eventType[strings.LastIndex(eventType, ".")+1:]
	if last == "success" || last == "failure" {
		return last
	}
	return ""
}

// String returns e's dot-separated type, e.g. "sts.assume_role.failure".
func (e Event) String() string {
	return e.typ
}

// Category returns e's first dot-separated segment.
func (e Event) Category() string {
	if i := strings.IndexByte(e.typ, '.'); i >= 0 {
		return e.typ[:i]
	}
	return e.typ
}

// WithOutcome returns a copy of e with outcome overridden.
func (e Event) WithOutcome(outcome string) Event {
	e.outcome = outcome
	return e
}

// All returns every registered catalog event, sorted by type.
func All() []Event {
	out := make([]Event, len(registry))
	copy(out, registry)
	sort.Slice(out, func(i, j int) bool { return out[i].typ < out[j].typ })
	return out
}
