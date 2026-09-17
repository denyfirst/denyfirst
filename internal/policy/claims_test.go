package policy

import (
	"strings"
	"testing"
)

// A verified receipt is a promise verified, and says that much (audit A20).
//
// A signature proves a log promised to include the certificate. That it did is
// an inclusion proof, which nothing here asks for, so the sentence may not say
// the log recorded it.
func TestAVerifiedReceiptIsAPromiseAndNotAnInclusion(t *testing.T) {
	text := strings.Join(Texts(DescribeTransparency(checked())), " ")
	for _, claim := range []string{"did record", "recorded this certificate", "is in the log"} {
		if strings.Contains(text, claim) {
			t.Errorf("a verified receipt is said to prove inclusion (%q): %s", claim, text)
		}
	}
	for _, want := range []string{"promise", "inclusion proof"} {
		if !strings.Contains(text, want) {
			t.Errorf("the note does not say %q: %s", want, text)
		}
	}
}

// Complete enumeration is complete over what this client offers, not over what
// the server accepts (audit A20).
func TestCoverageClaimsOnlyTheSuitesThisClientOffers(t *testing.T) {
	line := Coverage(full())
	if strings.Contains(line, "server accepts") {
		t.Errorf("the coverage line claims the server's whole list: %s", line)
	}
	if !strings.Contains(line, "this client can offer") {
		t.Errorf("the coverage line does not bound the enumeration: %s", line)
	}
}
