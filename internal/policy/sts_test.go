package policy

import (
	"strings"
	"testing"
)

// stsFacts is a domain doing everything right, with a policy read.
//
// Built once and copied, so that every test below differs from a passing domain
// in exactly the one field it is about. The alternative is a fixture per test
// and a finding that turns out to have come from a field nobody was looking at.
func stsFacts() MailFacts {
	return MailFacts{
		SPFRecords: 1, SPFAll: "-",
		DMARCRecords: 1, DMARCPolicy: "reject", DMARCReporting: true,
		MXRead: true, MXHosts: []string{"mx1.example.net"},
		MTASTSRecords: 1, MTASTSPolicyRead: true, MTASTSMode: "enforce",
		MTASTSMaxAge: 604800, MTASTSPolicyMX: []string{"mx1.example.net"},
		DANEAsked: 1,
	}
}

// A policy covering its own mail is not a finding.
func TestAnEnforcingPolicyThatCoversItsMailIsStrong(t *testing.T) {
	got := GradeMail(stsFacts())

	if len(got.Findings) != 0 {
		t.Errorf("graded %v for a domain enforcing a policy that names its own exchanger",
			mailRuleIDs(got))
	}
	if got.Verdict != Strong {
		t.Errorf("verdict = %q, want strong", got.Verdict)
	}
	if text := mailNoteText(got.Notes); !strings.Contains(text, "enforce mode") {
		t.Errorf("the report does not say the policy enforces:\n%s", text)
	}
}

// An enforcing policy that excludes the domain's own exchanger is graded.
//
// RFC 8461 §5: a sending server applying an enforcing policy must not deliver to
// a host the policy does not match. So every sender that honours MTA-STS — which
// includes the largest of them — queues this domain's mail and then returns it,
// and from DNS alone the configuration looks identical to a correct one.
func TestAnEnforcingPolicyThatExcludesItsOwnExchangerIsGraded(t *testing.T) {
	f := stsFacts()
	f.MXHosts = []string{"mx1.example.net", "mx2.example.net"}
	f.MTASTSUncovered = []string{"mx2.example.net"}

	got := GradeMail(f)
	if !mailHas(got, "mail.mta-sts-uncovered-exchanger") {
		t.Fatalf("findings are %v; an enforcing policy that stops the domain's own mail is not "+
			"among them", mailRuleIDs(got))
	}

	// The host is named. A count alone says there is a problem and not where.
	for _, finding := range got.Findings {
		if finding.RuleID != "mail.mta-sts-uncovered-exchanger" {
			continue
		}
		if !strings.Contains(finding.Rationale, "mx2.example.net") {
			t.Errorf("the finding does not name the exchanger the policy leaves out: %q",
				finding.Rationale)
		}
		if len(finding.References) == 0 {
			t.Error("the finding cites no document, so a reader cannot check it")
		}
	}
}

// The same exclusion under a testing policy is described and not graded.
//
// In testing mode a sending server delivers anyway, so nothing is failing yet —
// and that is exactly why the sentence matters: the operator is being led towards
// enforce, and enforcing this policy as it stands would stop their mail. A
// verdict here would penalise the staging position (R6); silence would let them
// walk into it.
func TestAnUncoveredExchangerUnderTestingIsSaidAndNotGraded(t *testing.T) {
	f := stsFacts()
	f.MTASTSMode = "testing"
	f.MXHosts = []string{"mx1.example.net", "mx2.example.net"}
	f.MTASTSUncovered = []string{"mx2.example.net"}

	got := GradeMail(f)
	if len(got.Findings) != 0 {
		t.Errorf("graded %v for a policy in the mode MTA-STS is rolled out through",
			mailRuleIDs(got))
	}

	text := mailNoteText(got.Notes)
	if !strings.Contains(text, "mx2.example.net") {
		t.Fatalf("nothing names the exchanger the policy leaves out, so moving to enforce is a "+
			"surprise:\n%s", text)
	}
	if !strings.Contains(text, "moving this policy to enforce") {
		t.Errorf("the report names the gap without saying what happens when the mode changes, "+
			"which is the only reason the gap matters yet:\n%s", text)
	}
}

// A policy that names no mode is a policy no sending server can apply.
//
// RFC 8461 requires the field. Graded the way a DMARC record with no p= is, and
// for the same reason: the domain has the record, the file, and no protection.
func TestAPolicyThatNamesNoModeIsGraded(t *testing.T) {
	f := stsFacts()
	f.MTASTSMode = ""

	got := GradeMail(f)
	if !mailHas(got, "mail.mta-sts-policy-invalid") {
		t.Fatalf("findings are %v; a policy carrying no mode is not among them", mailRuleIDs(got))
	}

	// And nothing describes a mode that was never there.
	if text := mailNoteText(got.Notes); strings.Contains(text, "is in  mode") {
		t.Errorf("the report renders an empty mode as a mode:\n%s", text)
	}
}

// An enforcing or testing policy naming no exchanger permits nothing.
//
// RFC 8461 requires at least one mx in either mode. Graded separately from the
// coverage rule because it needs no MX lookup to establish: a policy with no
// patterns matches nothing whatever the domain publishes.
func TestAPolicyNamingNoExchangerIsGraded(t *testing.T) {
	for _, mode := range []string{"enforce", "testing"} {
		f := stsFacts()
		f.MTASTSMode = mode
		f.MTASTSPolicyMX = nil

		got := GradeMail(f)
		if !mailHas(got, "mail.mta-sts-policy-invalid") {
			t.Errorf("mode %s naming no exchanger gave %v, and a policy matching no host at all "+
				"is not among them", mode, mailRuleIDs(got))
		}
	}

	// And a policy in none mode is not: withdrawing a policy is what none is
	// for, and no mx is expected with it.
	f := stsFacts()
	f.MTASTSMode = "none"
	f.MTASTSPolicyMX = nil
	if got := GradeMail(f); len(got.Findings) != 0 {
		t.Errorf("graded %v for a policy being deliberately withdrawn", mailRuleIDs(got))
	}
}

// A policy nobody read is not graded, and the report says why not.
//
// Every rule above rests on MTASTSPolicyRead, because without it a deployment
// that does not fetch the policy — the default, and every deployment requiring no
// proof of control — would be grading an empty mode on every domain that
// announces a policy at all.
func TestAPolicyNobodyReadIsNotGraded(t *testing.T) {
	f := MailFacts{
		SPFRecords: 1, SPFAll: "-",
		DMARCRecords: 1, DMARCPolicy: "reject", DMARCReporting: true,
		MXRead: true, MXHosts: []string{"mx1.example.net"},
		MTASTSRecords: 1, DANEAsked: 1,
		MTASTSPolicyReason: "this deployment reads the record and not the policy file",
	}

	got := GradeMail(f)
	if len(got.Findings) != 0 {
		t.Errorf("graded %v against a policy that was never fetched", mailRuleIDs(got))
	}

	text := mailNoteText(got.Notes)
	if !strings.Contains(text, "was not read") {
		t.Errorf("the report does not say the policy was not read:\n%s", text)
	}
	if !strings.Contains(text, f.MTASTSPolicyReason) {
		t.Errorf("the report does not carry the reason the policy was not read, so a reader "+
			"cannot tell a deployment's limit from a domain's fault:\n%s", text)
	}

	// The sentence is Unsettled rather than Observed: a reader who takes "a
	// policy is announced" for "the mail path is protected" has completed it in
	// the stronger direction, and this is the kind that refuses that.
	for _, n := range got.Notes {
		if strings.Contains(n.Text, "policy is announced") && n.Kind != KindUnsettled {
			t.Errorf("the sentence about an unread policy is %q, want %q", n.Kind, KindUnsettled)
		}
	}
}

// The cache lifetime is reported and never compared to anything.
//
// RFC 8461 sets no floor a scanner could hold a domain to, so a number this
// project called too short would be a threshold it invented (R21). What a reader
// gets is the value, in words they do not have to do arithmetic on.
func TestTheCacheLifetimeIsReportedAndNotGraded(t *testing.T) {
	for seconds, want := range map[int]string{
		604800:  "7 days",
		86400:   "one day",
		3600:    "one hour",
		7200:    "2 hours",
		90:      "90 seconds",
		1209600: "14 days",
	} {
		f := stsFacts()
		f.MTASTSMaxAge = seconds

		got := GradeMail(f)
		if len(got.Findings) != 0 {
			t.Errorf("max_age %d was graded %v, and no document sets a floor this project could "+
				"hold a domain to", seconds, mailRuleIDs(got))
		}
		if text := mailNoteText(got.Notes); !strings.Contains(text, want) {
			t.Errorf("max_age %d is not reported as %q:\n%s", seconds, want, text)
		}
	}
}

// Mode none is a withdrawal, which is a decision rather than an absence.
func TestModeNoneIsReadAsAWithdrawal(t *testing.T) {
	f := stsFacts()
	f.MTASTSMode = "none"
	f.MTASTSPolicyMX = nil

	got := GradeMail(f)
	text := mailNoteText(got.Notes)
	if !strings.Contains(text, "none mode") {
		t.Fatalf("the report does not say the policy is in none mode:\n%s", text)
	}
	if !strings.Contains(text, "withdrawing") {
		t.Errorf("the report names the mode without saying what it does:\n%s", text)
	}
}

// Every MTA-STS finding names the mail rule set and cites RFC 8461.
//
// R22: one rule set grades one check. A finding carrying the TLS version would
// make two incomparable things look comparable, and a finding citing nothing is
// one a reader has to take on trust.
func TestTheSTSFindingsCiteTheirDocument(t *testing.T) {
	f := stsFacts()
	f.MXHosts = []string{"mx1.example.net", "mx2.example.net"}
	f.MTASTSUncovered = []string{"mx2.example.net"}

	for _, finding := range GradeMail(f).Findings {
		if !strings.HasPrefix(finding.RuleID, "mail.mta-sts") {
			continue
		}
		if finding.Policy != MailVersion {
			t.Errorf("%s carries policy %q, want %q", finding.RuleID, finding.Policy, MailVersion)
		}
		var cited bool
		for _, ref := range finding.References {
			if strings.Contains(ref.Label, "RFC 8461") {
				cited = true
			}
		}
		if !cited {
			t.Errorf("%s cites %v, and none of them is the document the rule rests on",
				finding.RuleID, finding.References)
		}
	}
}
