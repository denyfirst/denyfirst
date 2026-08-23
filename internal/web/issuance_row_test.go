package web

import (
	"strings"
	"testing"
)

// The line has to be on the page rather than in the notes.
//
// The notes fold shut under every verdict but ungraded, which was the right
// decision and makes this one necessary. For a name with no CAA the sentence
// is often the most useful one in the report: a single DNS record, nothing to
// break by adding it, and a hundred authorities that stop being able to issue.
// A sentence nobody opens is a sentence nobody reads.
func TestIssuanceIsOnTheFaceOfTheReport(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}
	source := string(script)

	if !strings.Contains(source, `pair("Issuance"`) {
		t.Error("no Issuance row; the answer would only reach a reader who opened the notes")
	}
	if !strings.Contains(source, "issuance.line") {
		t.Error("the row does not read the line the policy wrote")
	}
	// Matched on the argument rather than on the whole call. Pinning the exact
	// signature made this fail the moment the section was given one more
	// thing to show — a test asserting a spelling rather than the property it
	// was written to protect, which is the trap the privacy page fell into
	// and the revocation wording fell into after it.
	if !strings.Contains(source, "certificate(data.certificate") || !strings.Contains(source, "data.issuance") {
		t.Error("the certificate section is not given the issuance answer, so the row is always empty")
	}
}

// Issuance above transparency, because they are halves of one question in the
// order the halves happen: a restriction is checked when a certificate is
// issued, and the logs record the result either way.
func TestIssuanceSitsAboveTransparency(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}
	source := string(script)

	issuance := strings.Index(source, `pair("Issuance"`)
	transparency := strings.Index(source, `pair("Transparency"`)

	if issuance < 0 || transparency < 0 {
		t.Fatal("one of the two rows is missing")
	}
	if issuance > transparency {
		t.Error("transparency is rendered before issuance; prevention comes before detection")
	}
}
