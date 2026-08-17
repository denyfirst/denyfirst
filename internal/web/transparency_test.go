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
		"logCount",
		"sctCount",
		`pair("Transparency"`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("the script does not contain %q, so the count is measured and not shown", required)
		}
	}

	// Both numbers, and the caveat. A page that prints a count of receipts
	// without saying they went unverified has told the reader the certificate
	// is provably logged, which counting bytes in an extension does not
	// establish.
	if !strings.Contains(source, "not verified") {
		t.Error("the transparency line does not say the receipts went unverified")
	}

	// Singular and plural both handled. "1 logs" is where a reader stops
	// trusting the rest of the page.
	for _, required := range []string{`"1 timestamp"`, `"1 log"`} {
		if !strings.Contains(source, required) {
			t.Errorf("the script has no singular form %s", required)
		}
	}
}
