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

// What the public logs hold has to reach the reader, and reach them as
// information rather than as a verdict.

// A deployment that searched nothing says nothing.
func TestADeploymentThatSearchedNoLogsSaysNothing(t *testing.T) {
	if line := LoggedLine(LogFacts{}); line != "" {
		t.Errorf("a scan that queried no log carries %q; a sentence about the logs from a "+
			"scan that never asked them is a claim about somebody else's records", line)
	}
	if notes := DescribeLogged(LogFacts{}); len(notes) != 0 {
		t.Errorf("a scan that queried no log carries %d notes about them", len(notes))
	}
}

// A search that failed says so, and never reads as an empty estate.
func TestAFailedSearchIsNotAnEmptyEstate(t *testing.T) {
	f := LogFacts{Searched: true, Reason: "the monitor could not be reached"}

	line := LoggedLine(f)
	if !strings.Contains(line, "not established") {
		t.Errorf("a failed search reads as %q", line)
	}

	var said bool
	for _, n := range DescribeLogged(f) {
		if n.Kind != KindUnsettled {
			t.Errorf("the note is %q, want unsettled: nothing was established", n.Kind)
		}
		if strings.Contains(n.Text, "could not be reached") {
			said = true
		}
	}
	if !said {
		t.Error("the notes do not carry the reason the search failed")
	}
}

// One certificate, and it is the one in use.
func TestOneCertificateInUseReadsAsSettled(t *testing.T) {
	line := LoggedLine(LogFacts{Searched: true, Distinct: 1})

	if !strings.Contains(line, "the one this server presented") {
		t.Errorf("line is %q", line)
	}
	if strings.Contains(line, "not the one") {
		t.Errorf("a certificate in use reads as unaccounted for: %q", line)
	}
}

// A certificate valid today that was not presented is the finding this exists
// for, and the count reaches the sentence.
func TestACertificateNotPresentedIsSaidPlainly(t *testing.T) {
	for _, tc := range []struct {
		distinct, unseen int
		want             string
	}{
		{1, 1, "it is not the one this server presented"},
		{3, 1, "one of which is valid today and was not the one presented here"},
		{5, 2, "2 of which are valid today and were not the one presented here"},
	} {
		f := LogFacts{Searched: true, Distinct: tc.distinct, Unseen: tc.unseen}

		line := LoggedLine(f)
		if !strings.Contains(line, tc.want) {
			t.Errorf("with %d distinct and %d unseen the line is %q, want it to contain %q",
				tc.distinct, tc.unseen, line, tc.want)
		}

		var explained bool
		for _, n := range DescribeLogged(f) {
			if strings.Contains(n.Text, "was not the one this server presented") {
				explained = true
				if n.Kind != KindObserved {
					t.Errorf("the note is %q; a certificate in a log is a fact, and which ones "+
						"were ordered is a question no scan can answer (R21)", n.Kind)
				}
			}
		}
		if !explained {
			t.Errorf("with %d unseen nothing explains what the number means", tc.unseen)
		}
	}
}

// Nothing here is graded.
//
// A certificate in a log is a fact; whether it should exist is a question about
// somebody's purchasing. An early renewal, a content delivery network issuing on
// the customer's behalf, and a certificate obtained by somebody who should not
// have one are identical from here, so a verdict would be a threshold this
// project invented (R21, R17).
func TestWhatTheLogsHoldIsNeverGraded(t *testing.T) {
	for _, n := range DescribeLogged(LogFacts{Searched: true, Distinct: 9, Unseen: 4}) {
		if n.Kind != KindObserved && n.Kind != KindUnsettled {
			t.Errorf("a note about the logs is of kind %q", n.Kind)
		}
	}
}

// A report says the search was by exact name.
//
// A certificate obtained for a subdomain is a real way to be attacked and is not
// covered. Silence there would let a clean answer read as a clean estate (R4).
func TestTheReportSaysSubdomainsWereNotSearched(t *testing.T) {
	var said bool
	for _, n := range DescribeLogged(LogFacts{Searched: true, Distinct: 1}) {
		if strings.Contains(n.Text, "subdomain") {
			said = true
		}
	}
	if !said {
		t.Error("nothing says that only the exact name was searched, so a reader takes a clean " +
			"answer for a clean estate")
	}
}

// A cut list says it is cut, and the count stays whole.
func TestATruncatedListSaysSoAndKeepsItsCount(t *testing.T) {
	f := LogFacts{Searched: true, Distinct: 400, Truncated: true}

	if !strings.Contains(LoggedLine(f), "400") {
		t.Errorf("the count was cut with the list: %q", LoggedLine(f))
	}

	var said bool
	for _, n := range DescribeLogged(f) {
		if strings.Contains(n.Text, "More certificates exist") {
			said = true
		}
	}
	if !said {
		t.Error("a cut list does not say so, so a reader takes a partial list for the whole history")
	}
}
