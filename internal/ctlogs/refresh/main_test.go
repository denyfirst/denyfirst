package main

import (
	"strings"
	"testing"
)

// -check exits 1 when the logs changed and 0 when they did not, and says what
// changed.
//
// The weekly workflow opens an issue on 1 and nothing on 0. A check that
// answered 0 for a changed list would leave the carried list going stale with
// nobody told, which is the one thing the job exists to prevent.
func TestCheckExitsOneWhenTheLogsChanged(t *testing.T) {
	if code, lines := checkOutcome("91.4", "91.5", nil, nil); code != 0 || !strings.Contains(strings.Join(lines, "\n"), "match") {
		t.Errorf("an unchanged list gave %d %v", code, lines)
	}

	code, lines := checkOutcome("91.4", "91.5", []string{"aa retired"}, []string{"aa usable"})
	if code != 1 {
		t.Errorf("a changed list exited %d, want 1", code)
	}
	text := strings.Join(lines, "\n")
	for _, want := range []string{"91.4", "91.5", "+ aa retired", "- aa usable"} {
		if !strings.Contains(text, want) {
			t.Errorf("the report of a change does not carry %q:\n%s", want, text)
		}
	}
}
