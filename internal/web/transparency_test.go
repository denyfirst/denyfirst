package web

import (
	"strings"
	"testing"
)

// The count is measured and it has to reach the page.
//
// The handshake count was collected for months and read by nobody, which is
// how it came to sit in the JSON reporting zero for certificates that carry
// three receipts. Counting the embedded ones fixes the number; showing it is
// what makes the fix visible to somebody who is not reading JSON.
//
// A shape check, because the page is assembled in the browser.
func TestTransparencyReachesThePage(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}
	source := string(script)

	for _, required := range []string{
		"transparencyText",
		"embeddedCount",
		"logIds",
		"sctLogIds",
		"sctCount",
		`pair("Transparency"`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("the script does not contain %q, so the count is measured and not shown", required)
		}
	}

	// The caveat is not on this line, and that is deliberate.
	//
	// The count is something this service measured and measured accurately.
	// That the receipts were not checked against the issuing log's key is
	// something it did not do, and it belongs with the other things it did
	// not do — in the note, which says so at length. On the line it read as
	// though the count itself were uncertain.
	if strings.Contains(source, `+ ", not verified"`) {
		t.Error("the transparency line still hedges a count that was measured exactly")
	}

	// Singular and plural both handled. "1 logs" is where a reader stops
	// trusting the rest of the page.
	for _, required := range []string{`"1 timestamp"`, `"1 log"`} {
		if !strings.Contains(source, required) {
			t.Errorf("the script has no singular form %s", required)
		}
	}
}
