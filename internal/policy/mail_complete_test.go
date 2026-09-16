package policy

import (
	"strings"
	"testing"
)

// A domain whose principal records could not be read is not strong.
//
// Every rule reads something, and a rule about a record that was not read stays
// silent. Strong claims that nothing fell short, which a scan that read nothing
// cannot claim (audit A11: three failed lookups came back strong).
func TestUnreadPrincipalRecordsAreNotStrong(t *testing.T) {
	for name, f := range map[string]MailFacts{
		"all three unread": {SPFReason: "unavailable", DMARCReason: "unavailable", MXReason: "unavailable"},
		"sender policy":    {SPFReason: "unavailable", DMARCRecords: 1, DMARCPolicy: "reject", DMARCPercent: 100, MXRead: true},
		"DMARC":            {SPFRecords: 1, SPFAll: "-", DMARCReason: "unavailable", MXRead: true},
		"exchangers":       {SPFRecords: 1, SPFAll: "-", DMARCRecords: 1, DMARCPolicy: "reject", DMARCPercent: 100, MXReason: "unavailable"},
	} {
		if got := GradeMail(f).Verdict; got != Ungraded {
			t.Errorf("%s: verdict %q, want ungraded", name, got)
		}
	}
}

// Everything read, nothing wrong: strong, as before. And a finding raised from
// what was read survives a record that was not.
func TestReadRecordsStillGradeAsTheyDid(t *testing.T) {
	read := MailFacts{SPFRecords: 1, SPFAll: "-", DMARCRecords: 1, DMARCPolicy: "reject", DMARCPercent: 100, MXRead: true}
	if got := GradeMail(read).Verdict; got != Strong {
		t.Errorf("a domain read in full with nothing wrong is %q, want strong", got)
	}

	broken := MailFacts{SPFRecords: 2, DMARCReason: "unavailable", MXRead: true}
	if got := GradeMail(broken).Verdict; got != Insecure {
		t.Errorf("two SPF records beside an unread DMARC record graded %q, want insecure", got)
	}
}

// A lookup count that is a lower bound is said as one, and a policy pulled in
// that nobody could read keeps the report from being strong.
func TestAnSPFCountThatIsALowerBoundIsSaidAsOne(t *testing.T) {
	over := MailFacts{SPFRecords: 1, SPFAll: "-", SPFLookups: 30, SPFLookupLimit: true, SPFLookupsAtLeast: true,
		DMARCRecords: 1, DMARCPolicy: "reject", DMARCPercent: 100, MXRead: true}
	got := GradeMail(over)
	found := false
	for _, f := range got.Findings {
		if f.RuleID == "mail.spf-lookup-limit" {
			found = true
			if !strings.Contains(f.Rationale, "takes at least 30") {
				t.Errorf("the finding does not say the count is a lower bound: %s", f.Rationale)
			}
		}
	}
	if !found || got.Verdict != Insecure {
		t.Errorf("thirty lookups graded %q with findings %v", got.Verdict, got.Findings)
	}

	unread := MailFacts{SPFRecords: 1, SPFAll: "-", SPFLookups: 3, SPFLookupsAtLeast: true, SPFUnreadIncludes: 2,
		DMARCRecords: 1, DMARCPolicy: "reject", DMARCPercent: 100, MXRead: true}
	got = GradeMail(unread)
	if got.Verdict != Ungraded {
		t.Errorf("a policy with two includes nobody could read is %q, want ungraded", got.Verdict)
	}
	var observed, unsettled string
	for _, n := range got.Notes {
		switch n.Kind {
		case KindObserved:
			observed += n.Text
		case KindUnsettled:
			unsettled += n.Text
		}
	}
	if !strings.Contains(observed, "takes at least 3 of the ten") {
		t.Errorf("the count is not said to be a lower bound: %s", observed)
	}
	if !strings.Contains(unsettled, "2 policies this one pulls in could not be read") {
		t.Errorf("the unread includes are not named: %s", unsettled)
	}
}
