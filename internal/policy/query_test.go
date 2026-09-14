package policy

import (
	"strings"
	"testing"
	"time"
)

var queryNow = time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

func revokedFindings(f StapleFacts) int {
	n := 0
	for _, finding := range GradeStapling(f).Findings {
		if finding.RuleID == "cert.revoked" {
			n++
		}
	}
	return n
}

// A responder asked directly that says revoked raises cert.revoked, and the
// line says who answered and when.
func TestAResponderAskedDirectlyThatSaysRevokedIsGraded(t *testing.T) {
	f := StapleFacts{HasResponder: true, QueryStatus: "revoked", QueryRevokedAt: queryNow.Add(-48 * time.Hour)}

	got := GradeStapling(f)
	if got.Verdict != Insecure || revokedFindings(f) != 1 {
		t.Errorf("verdict %s with %d cert.revoked findings; a verified answer saying revoked is insecure", got.Verdict, revokedFindings(f))
	}
	line := RevocationLine(f)
	if !strings.Contains(line, "asked directly") || !strings.Contains(line, "revoked on 2026-09-12") {
		t.Errorf("the line is %q", line)
	}
}

// One withdrawal is one finding, however many sources say it.
func TestARevocationSaidThreeWaysIsOneFinding(t *testing.T) {
	for name, f := range map[string]StapleFacts{
		"stapled and asked": {Stapled: true, Validated: true, Status: "revoked", QueryStatus: "revoked"},
		"listed and asked":  {ListStatus: "revoked", QueryStatus: "revoked"},
	} {
		if n := revokedFindings(f); n != 1 {
			t.Errorf("%s: cert.revoked raised %d times", name, n)
		}
	}
}

// An unknown answer is not reassurance, and a good one is dated.
func TestAResponderAnswerOfUnknownOrGoodIsSaidAsItIs(t *testing.T) {
	unknown := StapleFacts{HasResponder: true, QueryStatus: "unknown"}
	found := false
	for _, finding := range GradeStapling(unknown).Findings {
		found = found || finding.RuleID == "cert.revocation-unknown"
	}
	if !found {
		t.Error("a verified unknown from the responder raised no cert.revocation-unknown")
	}

	good := StapleFacts{HasResponder: true, QueryStatus: "good", QueryAsOf: queryNow}
	if got := GradeStapling(good); len(got.Findings) != 0 {
		t.Errorf("a verified good answer was graded %v", got.Findings)
	}
	if line := RevocationLine(good); !strings.Contains(line, "not revoked as of 2026-09-14") {
		t.Errorf("the line is %q", line)
	}
}

// Asked and established nothing: said, and graded for nothing. And a scan that
// did not ask reads exactly as before.
func TestAQueryThatEstablishedNothingIsSaidAndAScanThatDidNotAskIsUnchanged(t *testing.T) {
	failed := StapleFacts{HasResponder: true, QueryReason: "the responder could not be reached"}
	if got := GradeStapling(failed); len(got.Findings) != 0 {
		t.Errorf("a question nobody answered was graded %v", got.Findings)
	}
	if line := RevocationLine(failed); !strings.Contains(line, "asked directly and the responder could not be reached") {
		t.Errorf("the line is %q", line)
	}

	if line := RevocationLine(StapleFacts{HasResponder: true}); line != "not stapled; the certificate names a responder a client would have to ask" {
		t.Errorf("a scan that did not ask carries %q", line)
	}
}
