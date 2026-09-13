package policy

import (
	"strings"
	"testing"
)

// good is an exchanger that offers STARTTLS with a certificate that verifies.
func good(host string) ExchangerTLS {
	return ExchangerTLS{
		Host: host, Connected: true, Measured: true, Offered: true, Upgraded: true,
		Version: "TLS 1.3", Suite: "TLS_AES_128_GCM_SHA256", Trusted: true, NameMatches: true,
	}
}

// exchangerFacts is a domain doing everything right in DNS, whose exchangers
// answered as given. No MTA-STS policy, so nothing here is graded by one.
func exchangerFacts(exchangers ...ExchangerTLS) MailFacts {
	f := MailFacts{
		SPFRecords: 1, SPFAll: "-",
		DMARCRecords: 1, DMARCPolicy: "reject", DMARCReporting: true,
		MXRead: true, DANEAsked: len(exchangers),
		ExchangersContacted: true, Exchangers: exchangers,
	}
	for _, x := range exchangers {
		f.MXHosts = append(f.MXHosts, x.Host)
	}
	return f
}

// An exchanger offering STARTTLS with a certificate that verifies is said to.
func TestAnExchangerThatVerifiesIsSaidToVerify(t *testing.T) {
	got := GradeMail(exchangerFacts(good("mx1.example.net")))
	if len(got.Findings) != 0 {
		t.Errorf("graded %v", mailRuleIDs(got))
	}
	if text := mailNoteText(got.Notes); !strings.Contains(text, "STARTTLS is offered by mx1.example.net") {
		t.Errorf("the report does not say the exchanger is fine:\n%s", text)
	}
}

// No STARTTLS, and no MTA-STS: described and not graded.
//
// RFC 3207 makes STARTTLS optional. Grading its absence would invent a rule no
// document sets (R21) — but saying nothing would leave a reader believing their
// mail is encrypted in transit when it is not.
func TestAnExchangerWithoutSTARTTLSIsDescribedAndNotGraded(t *testing.T) {
	x := good("mx1.example.net")
	x.Offered, x.Upgraded, x.Version, x.Suite = false, false, "", ""

	got := GradeMail(exchangerFacts(x))
	if len(got.Findings) != 0 {
		t.Errorf("graded %v for an exchanger RFC 3207 does not require to offer STARTTLS", mailRuleIDs(got))
	}
	text := mailNoteText(got.Notes)
	if !strings.Contains(text, "mx1.example.net does not offer STARTTLS") || !strings.Contains(text, "unencrypted") {
		t.Errorf("the report does not say mail to it crosses the network unencrypted:\n%s", text)
	}
}

// A certificate that does not verify, and no MTA-STS: described and not graded.
func TestAnExchangerCertificateThatFailsIsDescribedAndNotGraded(t *testing.T) {
	untrusted := good("mx1.example.net")
	untrusted.Trusted, untrusted.CertificateReason = false, "it does not chain to a root this deployment trusts"
	misnamed := good("mx2.example.net")
	misnamed.NameMatches = false

	got := GradeMail(exchangerFacts(untrusted, misnamed))
	if len(got.Findings) != 0 {
		t.Errorf("graded %v; a sender delivering opportunistically does not check the certificate", mailRuleIDs(got))
	}
	text := mailNoteText(got.Notes)
	for _, want := range []string{"does not verify", "mx1.example.net (it does not chain", "mx2.example.net (it does not name"} {
		if !strings.Contains(text, want) {
			t.Errorf("the report does not carry %q:\n%s", want, text)
		}
	}
}

// Under an enforcing MTA-STS policy, an exchanger that cannot satisfy it is
// graded — in each of the three ways it can fail.
//
// RFC 8461: a sending server applying an enforcing policy must not deliver to
// an exchanger that does not offer STARTTLS with a certificate valid for its
// name. So the domain's own mail is refused, and from DNS the configuration
// looks correct.
func TestAnEnforcingPolicyGradesAnExchangerThatCannotSatisfyIt(t *testing.T) {
	for name, broken := range map[string]func(*ExchangerTLS){
		"no STARTTLS":      func(x *ExchangerTLS) { x.Offered, x.Upgraded = false, false },
		"untrusted":        func(x *ExchangerTLS) { x.Trusted, x.CertificateReason = false, "it is outside its validity period" },
		"for another name": func(x *ExchangerTLS) { x.NameMatches = false },
	} {
		x := good("mx1.example.net")
		broken(&x)

		f := stsFacts()
		f.ExchangersContacted, f.Exchangers = true, []ExchangerTLS{x}

		got := GradeMail(f)
		if !mailHas(got, "mail.mta-sts-exchanger-fails-policy") {
			t.Errorf("%s: findings are %v", name, mailRuleIDs(got))
			continue
		}
		for _, finding := range got.Findings {
			if finding.RuleID == "mail.mta-sts-exchanger-fails-policy" && !strings.Contains(finding.Rationale, "mx1.example.net") {
				t.Errorf("%s: the finding does not name the exchanger: %q", name, finding.Rationale)
			}
		}
	}
}

// An exchanger that satisfies the enforcing policy is not a finding.
func TestAnExchangerSatisfyingTheEnforcingPolicyIsNotAFinding(t *testing.T) {
	f := stsFacts()
	f.ExchangersContacted, f.Exchangers = true, []ExchangerTLS{good("mx1.example.net")}

	if got := GradeMail(f); len(got.Findings) != 0 {
		t.Errorf("graded %v for an exchanger that keeps the policy's promise", mailRuleIDs(got))
	}
}

// Testing mode delivers anyway, so an exchanger failing it is not graded.
func TestATestingPolicyDoesNotGradeTheExchanger(t *testing.T) {
	x := good("mx1.example.net")
	x.Offered, x.Upgraded = false, false

	f := stsFacts()
	f.MTASTSMode = "testing"
	f.ExchangersContacted, f.Exchangers = true, []ExchangerTLS{x}

	if got := GradeMail(f); mailHas(got, "mail.mta-sts-exchanger-fails-policy") {
		t.Errorf("graded %v under a policy whose senders deliver anyway", mailRuleIDs(got))
	}
}

// STARTTLS offered and not negotiated with this client is not graded.
//
// A server whose TLS shares nothing with Go's stack looks exactly like this, and
// that is a limit of this client before it is a fault of the exchanger (R4).
func TestAnExchangerThisClientCouldNotNegotiateWithIsNotGraded(t *testing.T) {
	x := good("mx1.example.net")
	x.Upgraded, x.Version, x.Suite, x.Trusted, x.NameMatches = false, "", "", false, false
	x.Reason = "STARTTLS was accepted and no encrypted connection could be negotiated with this client"

	f := stsFacts()
	f.ExchangersContacted, f.Exchangers = true, []ExchangerTLS{x}

	got := GradeMail(f)
	if mailHas(got, "mail.mta-sts-exchanger-fails-policy") {
		t.Errorf("graded %v for a negotiation this client could not complete", mailRuleIDs(got))
	}
	if text := mailNoteText(NotesOfKind(got.Notes, KindUnsettled)); !strings.Contains(text, "mx1.example.net") {
		t.Errorf("nothing says this exchanger was not established:\n%s", text)
	}
}

// An exchanger that was never measured is not graded, even under an enforcing
// policy.
//
// Unmeasured leaves Offered false, which is exactly what an exchanger offering no
// STARTTLS looks like to a rule that does not check. So a blocked port 25 on the
// machine running the scan would become "does not offer STARTTLS" against every
// exchanger a correctly configured domain has (R4, R3d). A sabotage removing the
// check escaped every test on 2026-09-13.
func TestAnUnmeasuredExchangerIsNotGradedUnderAnEnforcingPolicy(t *testing.T) {
	f := stsFacts()
	f.ExchangersContacted = true
	f.Exchangers = []ExchangerTLS{{
		Host: "mx1.example.net", ConnectTimedOut: true,
		Reason: "no connection to port 25 opened before the time ran out",
	}}

	if got := GradeMail(f); mailHas(got, "mail.mta-sts-exchanger-fails-policy") {
		t.Errorf("findings are %v; an exchanger nobody reached was graded as offering no STARTTLS",
			mailRuleIDs(got))
	}
}

// An exchanger the policy does not cover is the uncovered finding, not both.
func TestAnUncoveredExchangerIsNotGradedTwice(t *testing.T) {
	x := good("mx2.example.net")
	x.Offered, x.Upgraded = false, false

	f := stsFacts()
	f.MXHosts = []string{"mx1.example.net", "mx2.example.net"}
	f.MTASTSUncovered = []string{"mx2.example.net"}
	f.ExchangersContacted, f.Exchangers = true, []ExchangerTLS{good("mx1.example.net"), x}

	got := GradeMail(f)
	if !mailHas(got, "mail.mta-sts-uncovered-exchanger") {
		t.Fatalf("findings are %v; the uncovered exchanger is not among them", mailRuleIDs(got))
	}
	if mailHas(got, "mail.mta-sts-exchanger-fails-policy") {
		t.Errorf("findings are %v; one exchanger raised two findings for one break", mailRuleIDs(got))
	}
}

// Every exchanger timing out on connect says port 25 is likely blocked here.
//
// R3d: a limit of this scanner's network is not a fault of the server. Most
// residential connections and many hosting providers block outbound port 25,
// and a report blaming every exchanger a domain has would send an operator to
// fix servers that are fine.
func TestEveryExchangerTimingOutSaysPort25MayBeBlockedHere(t *testing.T) {
	blocked := func(host string) ExchangerTLS {
		return ExchangerTLS{Host: host, ConnectTimedOut: true,
			Reason: "no connection to port 25 opened before the time ran out"}
	}

	got := GradeMail(exchangerFacts(blocked("mx1.example.net"), blocked("mx2.example.net")))
	if len(got.Findings) != 0 {
		t.Errorf("graded %v for exchangers that were never reached", mailRuleIDs(got))
	}
	text := mailNoteText(NotesOfKind(got.Notes, KindUnsettled))
	if !strings.Contains(text, "port 25") || !strings.Contains(text, "where this scan ran") {
		t.Errorf("the report does not say port 25 is likely blocked where the scan ran:\n%s", text)
	}
}

// Exchangers not contacted are said to have not been, with the reason.
func TestExchangersNotContactedAreSaidNotToHaveBeen(t *testing.T) {
	f := exchangerFacts()
	f.MXHosts = []string{"mx1.example.net"}
	f.ExchangersContacted = false
	f.ExchangersReason = "this deployment does not contact mail servers"

	got := GradeMail(f)
	if len(got.Findings) != 0 {
		t.Errorf("graded %v for exchangers nobody asked", mailRuleIDs(got))
	}
	text := mailNoteText(NotesOfKind(got.Notes, KindUnsettled))
	if !strings.Contains(text, f.ExchangersReason) {
		t.Errorf("the reason is not in the report:\n%s", text)
	}
}

// The standing limit claims nothing a contacted exchanger makes false.
//
// It said "No mail server was contacted" until the exchangers could be asked,
// and a limit still saying so beside a row reading "STARTTLS mx1: TLS 1.3" would
// be one report contradicting itself.
func TestTheMailLimitIsTrueWhenExchangersWereContacted(t *testing.T) {
	text := LimitMailSendsNothing.Text
	if strings.Contains(text, "No mail server was contacted") || strings.Contains(text, "was not measured") {
		t.Errorf("the limit claims something a contacted exchanger falsifies: %q", text)
	}
	if !strings.Contains(text, "no sender, recipient or message") {
		t.Errorf("the limit does not say what a conversation with an exchanger never contains: %q", text)
	}
}
