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
// The sentence itself moved to internal/policy on 2026-08-31, with the tests
// that describe it — singular and plural, the union rather than the sum, and
// receipts that arrived and could not be read. What is left here is the half
// this file can answer: that the page shows the line, and does not build a
// second one of its own.
func TestTransparencyReachesThePage(t *testing.T) {
	source := script(t)

	if !strings.Contains(source, `pair("Transparency"`) {
		t.Error("the certificate section has no Transparency row, so the count is measured and not shown")
	}
	if !strings.Contains(source, "transparencyLine") {
		t.Error("the row does not read the line the report carries")
	}

	for _, gone := range []string{
		"function transparencyText",
		"transparency.embeddedCount",
		"tls.sctCount",
		"sctLogIds",
	} {
		if strings.Contains(source, gone) {
			t.Errorf("the script still composes the transparency sentence from %q; "+
				"the sentence belongs in internal/policy so that both faces read one string", gone)
		}
	}
}

// The key exchange is a property of the transport, so it sits with the suites
// rather than with the chain — and, like the two sentences above it, it is
// built in internal/policy and printed here unchanged.
//
// It is the one measurement in this report that costs the scanned server an
// extra handshake, which is a reason to be sure it reaches a reader.
func TestTheKeyExchangeLineReachesThePage(t *testing.T) {
	source := script(t)

	if !strings.Contains(source, "keyExchangeLine") {
		t.Error("the page never reads the key exchange line, so the extra handshake buys nothing")
	}
	if !strings.Contains(source, "ciphers(data.tls, data)") {
		t.Error("the cipher section is not given the report, so the line is always empty")
	}
	if strings.Contains(source, "postQuantum.offered") {
		t.Error("the page composes the sentence from the facts again; it belongs in internal/policy")
	}
}
