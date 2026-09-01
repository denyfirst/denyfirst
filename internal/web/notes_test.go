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

// A reader can keep the report they are looking at.
//
// It happens entirely in the browser: the JSON already arrived, so nothing is
// asked of the service again and nothing is kept anywhere. A server endpoint
// returning the same bytes would have to store the result or scan a second
// time, and this project does neither.
func TestTheReportCanBeSaved(t *testing.T) {
	source := script(t)

	for _, required := range []struct{ text, why string }{
		{`el("a", "download"`, "the control has to be on the page"},
		{"JSON.stringify(data", "it has to save the report the reader is looking at, not fetch another"},
		{"application/json", "the type has to say what the bytes are"},
		{"anchor.download =", "without the attribute a browser navigates to the blob instead of saving it"},
		{"URL.revokeObjectURL", "an object URL keeps its blob alive for as long as the document does"},
	} {
		if !strings.Contains(source, required.text) {
			t.Errorf("app.js does not contain %q — %s", required.text, required.why)
		}
	}

	// The name is built from a value somebody typed, and shortened.
	for _, required := range []string{`replace(/[^a-z0-9.-]+/g`, "slice(0, 60)"} {
		if !strings.Contains(source, required) {
			t.Errorf("the filename is not bounded or not sanitised: %q is missing", required)
		}
	}
}

// One format, and the reason is the strings a report carries.
//
// Every subject, name and issuer in a report is chosen by the server that was
// scanned. Each format below hands those strings to something that executes
// them: a spreadsheet reads a leading =, + or @ as a formula; a terminal reads
// an escape sequence as an instruction, which is a defect this project found
// in its own command line output; a browser reads HTML as markup. JSON escapes
// a control byte and carries no executable meaning anywhere.
func TestTheReportIsOfferedInOneFormatOnly(t *testing.T) {
	source := script(t)

	for _, forbidden := range []struct{ text, why string }{
		{"text/csv", "a spreadsheet would read a name beginning with = as a formula"},
		{"text/html", "a browser would read a name as markup"},
		{"text/plain", "a terminal would read an escape sequence in a name as an instruction"},
		{"application/vnd.ms-excel", "the same as text/csv, under another name"},
	} {
		if strings.Contains(source, forbidden.text) {
			t.Errorf("the report is offered as %s — %s", forbidden.text, forbidden.why)
		}
	}
}
