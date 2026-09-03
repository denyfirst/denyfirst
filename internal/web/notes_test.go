package web

import (
	"html"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/policy"
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

	// Read inside the renderer rather than across the file. The summary now
	// tests the verdict too, to decide whether to print what a weak or
	// insecure one means, and a check over the whole source read that as this
	// block opening for insecure again.
	body := source
	if i := strings.Index(body, "function notes(list, verdict)"); i >= 0 {
		body = body[i:]
	} else {
		t.Fatal("the script has no notes renderer")
	}

	if !strings.Contains(body, `verdict === "ungraded"`) {
		t.Error("the limits block does not open for an ungraded report, where they are the whole story")
	}

	if strings.Contains(body, `verdict === "insecure"`) {
		t.Error("the limits block still opens for an insecure verdict, which has a page of findings beside it")
	}

	// The count has to stay visible whether the block is open or shut, or
	// folding the detail becomes hiding it.
	for _, required := range []string{`"1 limit"`, `" limits"`} {
		if !strings.Contains(source, required) {
			t.Errorf("the summary line does not carry the count %s", required)
		}
	}

	// Both fold, and what makes that safe is what is in them.
	//
	// Observed opened by default at first, on the reasoning that a reader who
	// never opens it never sees a post-quantum exchange that passed. Read on
	// the live site, the block ran to five paragraphs and stood between the
	// verdict and the evidence — and every fact in it was already on the face
	// of the report: the key exchange line, the revocation row, the issuance
	// row, the certificate's names and timestamps. What folds is the
	// reasoning, which is the same on every report.
	//
	// What holds, above the tables, is what now carries the affirmative
	// voice, and it is six phrases rather than five paragraphs.
	//
	// The counts stay in the summaries either way, so folding is not hiding.
	opens := map[string]bool{"observed": false, "unsettled": false}
	for kind, want := range opens {
		i := strings.Index(source, `kind: "`+kind+`"`)
		if i < 0 {
			t.Errorf("the script has no %q section", kind)
			continue
		}
		section := source[i:]
		if end := strings.Index(section, "},"); end >= 0 {
			section = section[:end]
		}
		if got := strings.Contains(section, "open: true"); got != want {
			t.Errorf("the %q section opens by default = %v, want %v", kind, got, want)
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

		// The clipboard reads as the same offer and is not. It is shared with
		// every process on the machine, Windows keeps a history of it, and a
		// cloud clipboard sends it off the machine. What is sensitive in a
		// report is not its contents, which are public, but that somebody
		// asked about that host — and this service undertakes to keep no
		// record of exactly that.
		{"clipboard.writeText", "the clipboard is readable by every process on the machine and is sometimes synced off it"},
		{"execCommand(\"copy\")", "the same, by the older name"},
	} {
		if strings.Contains(source, forbidden.text) {
			t.Errorf("the report is offered as %s — %s", forbidden.text, forbidden.why)
		}
	}
}

// The standing limits left the report and are pointed at instead.
//
// Moving them is only defensible if the report still says they exist, how
// many there are, and where to read them. A section quietly dropped would be
// hiding, which is the thing this project objects to in other tools.
func TestTheStandingLimitsAreNamedAndLinked(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}
	source := string(script)

	if strings.Contains(source, `kind: "standing"`) {
		t.Error("the script still renders the standing limits as a section of every report")
	}
	for _, required := range []string{
		`const METHOD_PAGE = "/tls/method"`,
		"limits of this method apply to every scan",
		"standing.length",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("the report does not say where the standing limits went: missing %q", required)
		}
	}

	// And the page it points at has to exist and list every one of them.
	page, ok := rendered["/tls/method"]
	if !ok {
		t.Fatal("the report links /tls/method and the site does not serve it")
	}
	// Compared against the escaped form. The page is a template and
	// html/template escapes what it interpolates, so "Go's" arrives as
	// "Go&#39;s" — which is the escaping working, not the sentence missing.
	// Two of the four carry an apostrophe and this test failed on exactly
	// those two before it was told.
	for _, limit := range policy.StandingLimits() {
		if !strings.Contains(string(page), html.EscapeString(limit.Text)) {
			t.Errorf("/method does not carry the limit %q", limit.Title)
		}
		if !strings.Contains(string(page), `id="`+limit.ID+`"`) {
			t.Errorf("/method has no anchor for %q, so a report cannot point at it", limit.ID)
		}
	}
}

// One sentence about how grading works, in the same words on both faces.
//
// A weak or insecure verdict needs it: kapitalbank.az is graded insecure with
// a trusted chain, a verified staple, transparency, CAA and an accepted
// post-quantum group beside the stamp, and nothing else on the page says why
// one option outweighs the rest.
//
// Written twice, in Go for the terminal and in the script for the page, and
// compared here — the same arrangement as the section titles. A sentence
// explaining a verdict that itself differs between two renderings of one
// report would be worse than not saying it.
func TestBothFacesSayWhatAVerdictMeansInTheSameWords(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}

	// The page builds it from two concatenated string literals, as the file
	// wraps at eighty columns; compare on the words rather than the source.
	source := strings.Join(strings.Fields(string(script)), " ")
	want := strings.Join(strings.Fields(policy.WorstCase), " ")

	// Rebuild the concatenation the way the script writes it.
	joined := strings.ReplaceAll(source, `" + "`, "")
	if !strings.Contains(joined, want) {
		t.Errorf("the page does not carry policy.WorstCase:\n  %s", policy.WorstCase)
	}
}
