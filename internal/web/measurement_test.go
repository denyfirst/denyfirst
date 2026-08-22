package web

import (
	"strings"
	"testing"
)

func script(t *testing.T) string {
	t.Helper()
	body, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}
	return string(body)
}

// The page said "refused" for every version it could not measure.
//
// Only one kind of failure is a refusal: the server answered and declined.
// Our own client not offering the version, a name that did not resolve, a
// timeout, a reset, a destination the service will not dial — all of them
// leave `supported` false as well, and all of them were printed as "refused".
//
// The direction is what makes it a defect rather than a wording choice. A row
// reading "TLS 1.0 refused" is a row in the server's favour, and the page was
// awarding it on the strength of a handshake that never took place. The API
// carries both halves and the page read neither.
func TestAVersionThatCouldNotBeMeasuredIsNotCalledRefused(t *testing.T) {
	source := script(t)

	if strings.Contains(source, `v.supported ? "accepted" : "refused"`) {
		t.Error("the version row still derives \"refused\" from the absence of success")
	}
	for _, required := range []string{"v.refused", "not measured", "v.error"} {
		if !strings.Contains(source, required) {
			t.Errorf("app.js does not read %q, so a failed probe cannot be told from a refusal", required)
		}
	}
}

// A list that stopped early is marked where the list is, not only in the
// notes at the foot.
//
// The note is counted in the summary line, but the block holding it is shut
// under every verdict except ungraded — so under a weak or insecure verdict
// the reader is looking at a table headed "Cipher suites accepted" with
// nothing on it to say the weak end was never reached.
func TestATruncatedCipherListIsMarkedOnTheTable(t *testing.T) {
	source := script(t)

	if !strings.Contains(source, "cipherListComplete") {
		t.Fatal("app.js never reads cipherListComplete, so a truncated list is drawn as a complete one")
	}

	// Negated rather than compared against false. A response that omits the
	// field must get the cautious reading, which is the polarity the Go field
	// was given for the same reason.
	if strings.Contains(source, "cipherListComplete === false") {
		t.Error("an absent cipherListComplete would be read as a complete list")
	}
	if !strings.Contains(source, "!v.cipherListComplete") {
		t.Error("the incomplete-list marker is not driven by the field")
	}
}

// "3 timestamps from 0 logs" is not a fact about a certificate. It is this
// scanner saying it could not read what it was sent, in a sentence shaped
// like a measurement.
func TestUnreadableTimestampsDoNotBecomeAMeasurement(t *testing.T) {
	source := script(t)

	transparency := section(t, source, "function transparencyText(")
	if !strings.Contains(transparency, "logs === 0") {
		t.Error("transparencyText has no branch for timestamps whose log could not be read")
	}
}

// Every class the script can put on a node has a rule behind it. A class with
// no rule is a distinction the reader cannot see, which is the same as not
// having made it.
func TestTheClassesTheScriptAddsAreStyled(t *testing.T) {
	css, err := assets.ReadFile("assets/style.css")
	if err != nil {
		t.Fatalf("reading the stylesheet: %v", err)
	}
	source := script(t)

	for _, class := range []string{"row-note", "group-note"} {
		if !strings.Contains(source, `"`+class+`"`) {
			t.Errorf("app.js no longer uses %q", class)
		}
		if !strings.Contains(string(css), "."+class) {
			t.Errorf("app.js writes class %q and the stylesheet has no rule for it", class)
		}
	}
}

// section returns the text of one function, so a test can assert about the
// part of the script it means rather than about the whole file.
func section(t *testing.T, source, opening string) string {
	t.Helper()

	start := strings.Index(source, opening)
	if start < 0 {
		t.Fatalf("app.js no longer contains %q", opening)
	}
	rest := source[start:]
	if end := strings.Index(rest, "\n}\n"); end >= 0 {
		return rest[:end]
	}
	return rest
}
