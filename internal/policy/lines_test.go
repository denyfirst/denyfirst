package policy

import (
	"strings"
	"testing"
)

// The six revocation states have to stay distinguishable.
//
// A report that prints "not stapled" both for a server that could have
// stapled and for a certificate with nothing to staple has collapsed the only
// distinction that matters, and the first reading — that something is wrong —
// is the wrong one for most certificates issued now.
//
// There were four states and there are six: reading the response splits
// "stapled" into verified and unverifiable, in both the ordinary and the
// must-staple case. Matched on the shortest fragment that identifies a state
// and nothing about how it is phrased. The earlier version of this test lived
// in internal/web and pinned an exact sentence, which failed for a change
// that was correct — a test asserting a spelling rather than the property it
// was written to protect.
func TestEveryRevocationStateHasItsOwnSentence(t *testing.T) {
	cases := []struct {
		name  string
		facts StapleFacts
		says  string
	}{
		{"must-staple and nothing arrived",
			StapleFacts{MustStaple: true}, "requires a stapled response and none was sent"},
		{"must-staple and what arrived did not verify",
			StapleFacts{MustStaple: true, Stapled: true}, "the one sent could not be verified"},
		{"must-staple, stapled and verified",
			StapleFacts{MustStaple: true, Stapled: true, Validated: true, Status: "good"}, "the certificate requires it"},
		{"stapled and verified",
			StapleFacts{Stapled: true, Validated: true, Status: "good"}, "a status response was stapled"},
		{"stapled and unverifiable",
			StapleFacts{Stapled: true}, "establishes nothing"},
		{"not stapled, a responder exists",
			StapleFacts{HasResponder: true}, "names a responder a client would have to ask"},
		{"not stapled, nowhere to ask",
			StapleFacts{}, "names no responder"},
	}

	seen := map[string]string{}
	for _, c := range cases {
		got := RevocationLine(c.facts)
		if !strings.Contains(got, c.says) {
			t.Errorf("%s: the line does not identify its state\n  want to contain: %s\n  got: %s",
				c.name, c.says, got)
		}
		if other, clash := seen[got]; clash {
			t.Errorf("%s and %s produce the same sentence, so a reader cannot tell them apart:\n  %s",
				c.name, other, got)
		}
		seen[got] = c.name
	}
}

// An absent verification result reads as unverified.
//
// This line said "a status response was stapled" for a whole policy version
// after that stopped being the whole story: internal/ocsp parses the
// response, matches it to the certificate, checks it has not expired and
// verifies the authority's signature, and the one line a reader looks at for
// exactly this went on reporting that some bytes arrived.
//
// The polarity is the point. Validated is read as false when unset, so a
// producer that forgets the field gets the cautious sentence rather than the
// confident one.
func TestTheRevocationLineSaysWhetherTheResponseWasVerified(t *testing.T) {
	got := RevocationLine(StapleFacts{Stapled: true})
	if strings.Contains(got, "verified against the issuing authority") {
		t.Errorf("a response nobody verified is described as verified: %s", got)
	}

	verified := RevocationLine(StapleFacts{Stapled: true, Validated: true, Status: "good"})
	if !strings.Contains(verified, "verified against the issuing authority") {
		t.Errorf("a verified response does not say so: %s", verified)
	}
}

// What the authority said, when it is worth saying.
//
// "good" is the ordinary answer and repeating it adds nothing; anything else
// is the reason for having asked at all, and it belongs on the line rather
// than in a note that folds shut.
func TestAnUnusualStatusReachesTheLine(t *testing.T) {
	for _, status := range []string{"revoked", "unknown"} {
		for _, mustStaple := range []bool{false, true} {
			got := RevocationLine(StapleFacts{
				Stapled: true, Validated: true, Status: status, MustStaple: mustStaple,
			})
			if !strings.Contains(got, "the authority says the status is "+status) {
				t.Errorf("status %q, must-staple %v: not on the line: %s", status, mustStaple, got)
			}
		}
	}

	good := RevocationLine(StapleFacts{Stapled: true, Validated: true, Status: "good"})
	if strings.Contains(good, "the authority says") {
		t.Errorf("the ordinary answer is repeated back: %s", good)
	}
}

// "3 timestamps from 0 logs" is not a fact about a certificate. It is this
// scanner saying it could not read what it was sent, in a sentence shaped
// like a measurement.
func TestUnreadableTimestampsDoNotBecomeAMeasurement(t *testing.T) {
	got := TransparencyLine(TransparencyFacts{Embedded: 3, FromLogs: 0})
	if strings.Contains(got, "from 0 logs") {
		t.Errorf("unreadable receipts are reported as a count of logs: %s", got)
	}
	if !strings.Contains(got, "none of which could be read") {
		t.Errorf("nothing says the receipts could not be read: %s", got)
	}
}

// Singular and plural both handled. "1 logs" is where a reader stops trusting
// the rest of the page.
func TestTheTransparencyLineCountsInEnglish(t *testing.T) {
	one := TransparencyLine(TransparencyFacts{Embedded: 1, FromLogs: 1})
	if !strings.Contains(one, "1 timestamp from 1 log") {
		t.Errorf("the singular forms are wrong: %s", one)
	}
	if strings.Contains(one, "timestamps") || strings.Contains(one, "logs") {
		t.Errorf("a plural leaked into the singular case: %s", one)
	}

	many := TransparencyLine(TransparencyFacts{Embedded: 3, FromLogs: 2})
	if !strings.Contains(many, "3 timestamps from 2 logs") {
		t.Errorf("the plural forms are wrong: %s", many)
	}
}

// Where they arrived from, only when both routes were used.
//
// The union, not the sum: a certificate can carry receipts and the handshake
// can carry more, and the usual arrangement is that both name the same logs.
// FromLogs is that union, computed once by the caller.
func TestTheTransparencyLineSaysWhichRouteWhenBothWereUsed(t *testing.T) {
	both := TransparencyLine(TransparencyFacts{Embedded: 2, InHandshake: 1, FromLogs: 2})
	if !strings.Contains(both, "(2 embedded, 1 in the handshake)") {
		t.Errorf("both routes were used and the line does not say so: %s", both)
	}

	oneRoute := TransparencyLine(TransparencyFacts{Embedded: 2, FromLogs: 2})
	if strings.Contains(oneRoute, "embedded,") {
		t.Errorf("only one route was used and the line breaks it down anyway: %s", oneRoute)
	}
}

// The caveat about verification is not on this line, and that is deliberate.
//
// The count is something this service measured and measured accurately. That
// the receipts were not checked against the issuing log's key is something it
// did not do, and it belongs with the other things it did not do — in the
// note, which says so at length. On the line it read as though the count
// itself were uncertain.
func TestTheTransparencyLineDoesNotHedgeACountItMeasured(t *testing.T) {
	got := TransparencyLine(TransparencyFacts{Embedded: 3, FromLogs: 2})
	if strings.Contains(got, "not verified") {
		t.Errorf("the line hedges a count that was measured exactly: %s", got)
	}
}

func TestNoReceiptsAtAll(t *testing.T) {
	got := TransparencyLine(TransparencyFacts{})
	if got != "no timestamps in the certificate or the handshake" {
		t.Errorf("unexpected sentence for a certificate with no receipts: %s", got)
	}
}
