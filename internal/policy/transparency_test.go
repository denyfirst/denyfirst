package policy

import (
	"strings"
	"testing"
)

// Every branch says something, and no two branches say the same thing.
//
// The four situations below look alike from a distance — a number and whether
// it is zero — and they are not alike at all. One certificate is logged. One is
// outside the public authorities and owes nobody a receipt. One may be logged
// through a channel nobody read. One is a certificate a browser will refuse.
// Collapsing any pair of them loses the only information a reader wanted.
func TestDescribeTransparencySeparatesTheFourSituations(t *testing.T) {
	logged := strings.Join(DescribeTransparency(TransparencyFacts{
		Embedded: 3, FromLogs: 3, Trusted: true,
	}), " ")

	private := strings.Join(DescribeTransparency(TransparencyFacts{
		Trusted: false,
	}), " ")

	maybeStapled := strings.Join(DescribeTransparency(TransparencyFacts{
		Trusted: true, Stapled: true,
	}), " ")

	absent := strings.Join(DescribeTransparency(TransparencyFacts{
		Trusted: true,
	}), " ")

	all := map[string]string{
		"logged": logged, "private": private, "maybe stapled": maybeStapled, "absent": absent,
	}
	for name, note := range all {
		if note == "" {
			t.Errorf("the %s case says nothing; silence about transparency reads as a clean result", name)
		}
	}
	for a, na := range all {
		for b, nb := range all {
			if a < b && na == nb {
				t.Errorf("the %s and %s cases produce the same sentence", a, b)
			}
		}
	}

	if !strings.Contains(private, "no obligation") {
		t.Errorf("a certificate outside the public authorities is described as if it were at fault: %s", private)
	}
	if !strings.Contains(maybeStapled, "does not read") {
		t.Errorf("a report holding an unread stapled response claims more than it looked at: %s", maybeStapled)
	}
	if !strings.Contains(absent, "browsers refuse") {
		t.Errorf("the consequence of a genuinely unlogged public certificate is not stated: %s", absent)
	}
}

// A count that was never checked must not be reported as if it were.
//
// Verifying a receipt needs the issuing log's public key, and the set of
// qualified logs is a list browsers ship and revise. Nothing here carries a
// copy. A report that prints "3 transparency timestamps" and stops has told a
// reader the certificate is verifiably logged, which is a step further than
// counting bytes in an extension gets anybody.
func TestLoggedNoteDoesNotClaimTheReceiptsWereVerified(t *testing.T) {
	note := strings.Join(DescribeTransparency(TransparencyFacts{
		Embedded: 2, FromLogs: 2, Trusted: true,
	}), " ")

	if !strings.Contains(note, "not verified") {
		t.Errorf("the note does not say the receipts went unverified: %s", note)
	}
}

// Both numbers reach the reader, because one of them cannot answer the
// question on its own. Browsers ask for receipts from distinct logs so that a
// single misbehaving log cannot satisfy the requirement alone.
func TestBothCountsAreReported(t *testing.T) {
	note := strings.Join(DescribeTransparency(TransparencyFacts{
		Embedded: 3, FromLogs: 1, Trusted: true,
	}), " ")

	if !strings.Contains(note, "3 transparency timestamps") {
		t.Errorf("the number of timestamps is missing: %s", note)
	}
	if !strings.Contains(note, "1 log") {
		t.Errorf("the number of logs is missing, so three receipts from one log reads as three from three: %s", note)
	}
}

// Timestamps arriving by both routes at once is unusual and worth naming, so a
// reader comparing this against another tool is not left wondering which
// number they are looking at.
func TestBothDeliveryRoutesAreNamedWhenBothCarried(t *testing.T) {
	note := strings.Join(DescribeTransparency(TransparencyFacts{
		Embedded: 2, FromLogs: 2, InHandshake: 1, Trusted: true,
	}), " ")

	if !strings.Contains(note, "3 transparency timestamps") {
		t.Errorf("the two routes are not added together: %s", note)
	}
	if !strings.Contains(note, "embedded in the certificate and 1 in the handshake") {
		t.Errorf("the split between the routes is not stated: %s", note)
	}
}

// A report that says "1 logs" is a report somebody stopped reading.
func TestSingularCountsReadAsEnglish(t *testing.T) {
	note := strings.Join(DescribeTransparency(TransparencyFacts{
		Embedded: 1, FromLogs: 1, Trusted: true,
	}), " ")

	for _, wrong := range []string{"1 logs", "1 transparency timestamps"} {
		if strings.Contains(note, wrong) {
			t.Errorf("the note contains %q: %s", wrong, note)
		}
	}
}
