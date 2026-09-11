package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/mailscan"
	"github.com/denyfirst/denyfirst/internal/policy"
)

// mailSample is a domain with a policy worth printing.
func mailSample() mailResult {
	facts := policy.MailFacts{
		SPFRecords:   1,
		SPFAll:       "-",
		SPFLookups:   4,
		SPFIncludes:  []string{"spf.provider.example"},
		DMARCRecords: 1,
		DMARCPolicy:  "reject",
		DMARCPercent: 100,
	}
	graded := policy.GradeMail(facts)

	return mailResult{
		Domain: "example.test",
		Result: &mailscan.Result{
			Domain:   "example.test",
			Policy:   policy.MailVersion,
			Verdict:  graded.Verdict,
			Findings: graded.Findings,
			Notes:    graded.Notes,
			Observed: &facts,
		},
	}
}

func mailReport(t *testing.T, r mailResult) string {
	t.Helper()
	var b bytes.Buffer
	printMail(&b, r)
	return b.String()
}

func TestTheMailReportShowsWhatTheZoneSays(t *testing.T) {
	text := mailReport(t, mailSample())
	for _, want := range []string{
		"Sender policy", "ends in -all", "4 of the ten lookups allowed",
		"Authentication policy", "DMARC", "p=reject at 100%", "TLS-RPT",
		policy.MailVersion,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not carry %q:\n%s", want, text)
		}
	}
}

func TestTheMailReportNamesTheMailRuleSet(t *testing.T) {
	// Three rule sets in one binary now, and a report carrying the wrong name
	// sends a reader to a changelog that never mentions the rule that graded
	// them.
	text := mailReport(t, mailSample())
	for _, wrong := range []string{policy.TLSVersion, policy.WebVersion} {
		if strings.Contains(text, wrong) {
			t.Errorf("the mail report names %q:\n%s", wrong, text)
		}
	}
}

// The footer of a check with no page of its own prints its limits rather than
// pointing at somebody else's.
//
// The defect this was written for shipped and was caught by hand: the mail
// report ended with "denyfirst-scan -limits, or https://denyfirst.dev/tls/method",
// which is a page about cipher suites and certificates under a report that
// looked at neither. A URL for a page nobody has written is worse than no URL,
// because a reader follows it.
func TestTheMailReportPointsAtNoPageItDoesNotHave(t *testing.T) {
	text := mailReport(t, mailSample())

	for _, wrong := range []string{tlsMethodPage, webMethodPage} {
		if strings.Contains(text, wrong) {
			t.Errorf("the mail report sends its reader to %s, which describes a different "+
				"check:\n%s", wrong, text)
		}
	}
	if strings.Contains(text, "denyfirst-scan -limits, or") {
		t.Errorf("the report offers a page after \"or\" and there is none:\n%s", text)
	}

	// And having printed no pointer, it prints the limit itself. Silence here
	// would be the worst of the three: a report that read only DNS, said so
	// nowhere, and mentioned no page where it might have been explained.
	if !strings.Contains(text, "Limits of this method") {
		t.Errorf("the report has no limits section at all:\n%s", text)
	}
	for _, l := range policy.MailStandingLimits() {
		if !strings.Contains(text, strings.Fields(l.Text)[0]) {
			t.Errorf("the limit %q is neither printed nor pointed at:\n%s", l.ID, text)
		}
	}
}

// -limits under -check mail prints the mail limits and offers no page.
func TestTheMailLimitsStandAlone(t *testing.T) {
	limits, page := limitsFor(checkMail)
	if page != "" {
		t.Fatalf("the mail check names the page %q, and no such page exists", page)
	}
	if len(limits) == 0 {
		t.Fatal("the mail check declares no limits")
	}

	var buf bytes.Buffer
	printLimits(&buf, limits, page)
	text := buf.String()

	if strings.Contains(text, "Read alongside") {
		t.Errorf("-check mail -limits offers a page to read alongside:\n%s", text)
	}
	for _, l := range limits {
		if !strings.Contains(text, l.Title) {
			t.Errorf("-check mail -limits omits %q", l.ID)
		}
	}

	// The other two still name theirs, so this is the empty page being
	// handled rather than the line being deleted.
	for _, check := range []string{checkTLS, checkWeb} {
		var other bytes.Buffer
		l, p := limitsFor(check)
		printLimits(&other, l, p)
		if !strings.Contains(other.String(), "Read alongside") {
			t.Errorf("-check %s -limits no longer points at %s", check, p)
		}
	}
}

// A mail limit is not a TLS limit and not a web limit.
func TestTheThreeChecksDeclareDifferentLimits(t *testing.T) {
	sets := map[string][]policy.StandingLimit{
		checkTLS:  policy.StandingLimits(),
		checkWeb:  policy.WebStandingLimits(),
		checkMail: policy.MailStandingLimits(),
	}
	seen := map[string]string{}
	for check, limits := range sets {
		for _, l := range limits {
			if other, ok := seen[l.ID]; ok {
				t.Errorf("%s appears under both -check %s and -check %s", l.ID, other, check)
			}
			seen[l.ID] = check
		}
	}
}

// A domain that could not be scanned exits non-zero, and one that was scanned
// and graded exits by its verdict — the same two numbers the other checks use.
func TestTheMailExitStatusMatchesTheOtherChecks(t *testing.T) {
	failed := mailResult{Domain: "example.test", Error: "refused"}
	if got := exitCode(mailOutcomes([]mailResult{failed})); got == 0 {
		t.Error("a domain that could not be scanned exited zero")
	}

	good := mailSample()
	if got := exitCode(mailOutcomes([]mailResult{good})); got != 0 {
		t.Errorf("a correctly configured domain exited %d", got)
	}

	broken := mailSample()
	broken.Verdict = policy.Insecure
	if got := exitCode(mailOutcomes([]mailResult{broken})); got == 0 {
		t.Error("an insecure domain exited zero")
	}
}

// A record with no all mechanism is described, never printed as "ends in all".
func TestAPolicyWithNoAllIsNotPrintedAsHavingOne(t *testing.T) {
	if got := allOrNone(""); got != "no " {
		t.Errorf("allOrNone(\"\") = %q, want %q", got, "no ")
	}
	for _, q := range []string{"-", "~", "?", "+"} {
		if got := allOrNone(q); got != q {
			t.Errorf("allOrNone(%q) = %q", q, got)
		}
	}
}
