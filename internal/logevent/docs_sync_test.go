package logevent

import (
	"os"
	"regexp"
	"testing"
)

func TestCatalog_EveryEventDocumentedInLoggingMD(t *testing.T) {
	doc, err := os.ReadFile("../../docs/LOGGING.md")
	if err != nil {
		t.Fatalf("reading docs/LOGGING.md: %v", err)
	}
	contents := string(doc)

	for _, e := range All() {
		row := regexp.MustCompile("(?m)^\\|[ ]*`" + regexp.QuoteMeta(e.String()) + "`[ ]*\\|")
		if !row.MatchString(contents) {
			t.Errorf("event %q has no catalog row in docs/LOGGING.md", e.String())
		}
	}
}
