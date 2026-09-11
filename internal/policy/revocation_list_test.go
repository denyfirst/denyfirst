package policy

import (
	"strings"
	"testing"
	"time"
)

// What a revocation list establishes has to reach the reader, and reach them as
// one finding rather than two.

var listNow = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

// A list that names the certificate is the finding, and says so in the line.
func TestAListThatNamesTheCertificateIsReported(t *testing.T) {
	f := StapleFacts{
		HasCRL:        true,
		ListStatus:    "revoked",
		ListRevokedAt: listNow.Add(-48 * time.Hour),
		ListAsOf:      listNow.Add(-6 * time.Hour),
	}

	got := GradeStapling(f)
	if got.Verdict != Insecure {
		t.Errorf("verdict is %q, want insecure: the authority has withdrawn this certificate", got.Verdict)
	}

	var found bool
	for _, finding := range got.Findings {
		if finding.RuleID == "cert.revoked" {
			found = true
		}
	}
	if !found {
		t.Error("no cert.revoked finding, so a withdrawn certificate is graded on everything " +
			"except the thing that matters most about it")
	}

	line := RevocationLine(f)
	if !strings.Contains(line, "revoked") {
		t.Errorf("the revocation line does not say it was revoked: %q", line)
	}
	if !strings.Contains(line, "2026-09-09") {
		t.Errorf("the revocation line does not say when: %q", line)
	}
}

// A list that does not name it says so, with the date it was published.
//
// The date is the part that matters. A list is a snapshot an authority
// publishes on a schedule, so "not revoked" is true as of then rather than as
// of now, and a reader acting on it has to be able to tell the difference. A
// stapled response carries its own freshness; this does not.
func TestAListThatDoesNotNameTheCertificateSaysAsOfWhen(t *testing.T) {
	f := StapleFacts{
		HasCRL:     true,
		ListStatus: "good",
		ListAsOf:   listNow.Add(-30 * time.Hour),
	}

	if got := GradeStapling(f); got.Verdict != Strong {
		t.Errorf("verdict is %q, want strong", got.Verdict)
	}

	line := RevocationLine(f)
	if !strings.Contains(line, "does not name this certificate") {
		t.Errorf("the revocation line does not say the list was read: %q", line)
	}
	if !strings.Contains(line, "2026-09-10") {
		t.Errorf("the revocation line does not say when the list was published, so a reader "+
			"takes a snapshot for this moment: %q", line)
	}
}

// A list that could not be read says which of the four checks failed.
//
// Not silence. A report that stops at "not stapled" for a certificate whose
// authority publishes no responder has told the reader nothing about revocation
// while appearing to have covered it (R4).
func TestAListThatCouldNotBeReadSaysWhy(t *testing.T) {
	f := StapleFacts{
		HasCRL:     true,
		ListReason: "the revocation list was not signed by the issuing authority",
	}

	line := RevocationLine(f)
	if !strings.Contains(line, "not established") {
		t.Errorf("the revocation line does not say the check did not happen: %q", line)
	}
	if !strings.Contains(line, "not signed by the issuing authority") {
		t.Errorf("the revocation line does not carry the reason: %q", line)
	}
}

// One withdrawal is one finding.
//
// A server can staple a response saying revoked and name a list that agrees.
// Two findings for one fact is the double-charging R6 is written about, and it
// would also double a reader's estimate of how much is wrong.
func TestOneWithdrawalIsOneFinding(t *testing.T) {
	f := StapleFacts{
		Stapled:       true,
		Validated:     true,
		Status:        "revoked",
		RevokedAt:     listNow.Add(-48 * time.Hour),
		HasCRL:        true,
		ListStatus:    "revoked",
		ListRevokedAt: listNow.Add(-48 * time.Hour),
	}

	n := 0
	for _, finding := range GradeStapling(f).Findings {
		if finding.RuleID == "cert.revoked" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("cert.revoked was raised %d times for one withdrawal", n)
	}
}

// A deployment that reads no list reads exactly as it did before.
//
// The demonstration does not fetch, so its reports must not acquire a sentence
// about a check it does not run — and must not lose the one they had.
func TestADeploymentThatReadsNoListIsUnchanged(t *testing.T) {
	f := StapleFacts{HasCRL: true}

	line := RevocationLine(f)
	if line != "not stapled; the certificate names no responder, so there is none to send" {
		t.Errorf("the revocation line for a deployment that fetches nothing is %q", line)
	}
}
