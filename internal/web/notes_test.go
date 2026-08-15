package web

import (
	"strings"
	"testing"
)

// The limits of a scan open by default in one case and only one.
//
// A report that graded nothing has nothing else on the page: no findings, no
// cipher table, no certificate. There the limits are not a footnote, they are
// the finding, and folding them would leave a reader looking at an empty
// report with no explanation of why it is empty.
//
// Every other verdict has a page full of content, and the limits sit beside it
// as the caveat they are. That includes an insecure verdict, which was once
// treated as a second exception on no stated grounds — the comment in the
// script justified the ungraded case and was silent about the other. A default
// that opens on bad news trains a reader to close the block without reading
// it, which produces the same silence the block exists to prevent, by a longer
// route.
//
// The count is in the summary line either way, so nothing is hidden by
// folding. This is a shape check, because the page is assembled in the
// browser.
func TestLimitsOpenOnlyWhenTheyAreTheWholeReport(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}
	source := string(script)

	if !strings.Contains(source, `const alwaysOpen = verdict === "ungraded";`) {
		t.Error("the limits block does not open for an ungraded report, where they are the whole story")
	}

	if strings.Contains(source, `verdict === "ungraded" || verdict === "insecure"`) {
		t.Error("the limits block still opens for an insecure verdict, which has a page of findings beside it")
	}

	// The count has to stay visible whether the block is open or shut, or
	// folding the detail becomes hiding it.
	for _, required := range []string{`"1 limit"`, `" limits"`} {
		if !strings.Contains(source, required) {
			t.Errorf("the summary line does not carry the count %s", required)
		}
	}
}
