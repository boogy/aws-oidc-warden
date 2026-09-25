package logevent

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestCatalog_EveryEventDocumentedInLoggingMD(t *testing.T) {
	doc, err := os.ReadFile("../../docs/LOGGING.md")
	if err != nil {
		t.Fatalf("reading docs/LOGGING.md: %v", err)
	}
	contents := "\n" + string(doc)

	for _, e := range All() {
		want := fmt.Sprintf("\n| `%s` |", e.String())
		if !strings.Contains(contents, want) {
			t.Errorf("event %q has no catalog row in docs/LOGGING.md", e.String())
		}
	}
}
