package policy

import (
	"strings"
	"testing"
)

// daneFacts is a domain whose one exchanger negotiated TLS and whose DANE
// records made what is given of its certificate.
func daneFacts(b DANEBinding) MailFacts {
	f := exchangerFacts(good(b.Host))
	f.DANEHosts = []string{b.Host}
	f.DANEBindings = []DANEBinding{b}
	return f
}

const daneRule = "mail.dane-exchanger-fails-binding"

// A binding that does not hold, in records the resolver reported validated, is
// graded: RFC 7672 has a sender hold the mail. Both ways it fails.
func TestAValidatedBindingThatDoesNotHoldIsGraded(t *testing.T) {
	for _, outcome := range []string{DANEMismatched, DANENoSTARTTLS} {
		got := GradeMail(daneFacts(DANEBinding{Host: "mx1.example.net", Validated: true, Usable: 1,
			Outcome: outcome, Reason: "no usable DANE record matches the certificate it presented"}))
		if !mailHas(got, daneRule) || got.Verdict != Weak {
			t.Errorf("%s: verdict %s, findings %v", outcome, got.Verdict, mailRuleIDs(got))
			continue
		}
		for _, finding := range got.Findings {
			if finding.RuleID == daneRule && (!strings.Contains(finding.Rationale, "mx1.example.net") ||
				!strings.Contains(finding.Rationale, "reported validated by the resolver")) {
				t.Errorf("%s: the finding does not name the exchanger and whose word the validation is: %q", outcome, finding.Rationale)
			}
		}
	}
}

// Records the resolver did not report validated are ones a sender applying RFC
// 7672 ignores, so a failure in them is said and not graded.
func TestABindingNotReportedValidatedIsNamedAndNotGraded(t *testing.T) {
	got := GradeMail(daneFacts(DANEBinding{Host: "mx1.example.net", Usable: 1, Outcome: DANEMismatched, Reason: "a reason"}))
	if mailHas(got, daneRule) {
		t.Errorf("graded %v for records no sender acts on", mailRuleIDs(got))
	}
	if text := mailNoteText(got.Notes); !strings.Contains(text, "do not hold for mx1.example.net (a reason)") ||
		!strings.Contains(text, "named rather than graded") {
		t.Errorf("the report does not say the binding fails, and why it is not graded:\n%s", text)
	}
}

// Nothing a sender does not use, and nothing this scan could not establish, is
// graded — even where the resolver reported the records validated.
func TestWhatNoSenderUsesAndWhatWasNotEstablishedAreNotGraded(t *testing.T) {
	for _, b := range []DANEBinding{
		{Host: "mx1.example.net", Validated: true, Usable: 0, Outcome: DANENoUsableRecords},
		{Host: "mx1.example.net", Validated: true, Usable: 0, Outcome: DANEMismatched, Reason: "a reason"},
		{Host: "mx1.example.net", Validated: true, Usable: 1, Outcome: DANEUndetermined, Reason: "a reason"},
		{Host: "mx1.example.net", Validated: true, Usable: 1, Outcome: DANENotChecked, Reason: "a reason"},
	} {
		got := GradeMail(daneFacts(b))
		if mailHas(got, daneRule) {
			t.Errorf("%+v: graded %v", b, mailRuleIDs(got))
		}
	}

	text := mailNoteText(GradeMail(daneFacts(DANEBinding{Host: "mx1.example.net", Validated: true, Outcome: DANENoUsableRecords})).Notes)
	if !strings.Contains(text, "authenticates nothing there") {
		t.Errorf("records no sender uses are not said to authenticate nothing:\n%s", text)
	}
	text = mailNoteText(GradeMail(daneFacts(DANEBinding{Host: "mx1.example.net", Validated: true, Usable: 1,
		Outcome: DANEUndetermined, Reason: "a reason"})).Notes)
	if !strings.Contains(text, "was not established for mx1.example.net: a reason") {
		t.Errorf("an open question is not said as one:\n%s", text)
	}
}

// A match is said — and where the records were not reported validated, so is
// that nothing is established about whether they protect anything.
func TestAMatchIsSaidWithWhetherItValidated(t *testing.T) {
	validated := mailNoteText(GradeMail(daneFacts(DANEBinding{Host: "mx1.example.net", Validated: true, Usable: 1, Outcome: DANEMatched})).Notes)
	if !strings.Contains(validated, "presented by mx1.example.net matches") {
		t.Errorf("a match is not said:\n%s", validated)
	}
	if strings.Contains(validated, "did not report the DANE records") {
		t.Errorf("a validated match is said not to have validated:\n%s", validated)
	}

	unvalidated := mailNoteText(GradeMail(daneFacts(DANEBinding{Host: "mx1.example.net", Usable: 1, Outcome: DANEMatched})).Notes)
	if !strings.Contains(unvalidated, "did not report the DANE records of mx1.example.net validated") {
		t.Errorf("a match in records not reported validated is said as if it protected something:\n%s", unvalidated)
	}
}

// The mail path's DANE sentence says where the binding was checked, and does
// not say it was not checked when it was.
func TestTheMailPathSaysWhetherTheBindingsWereChecked(t *testing.T) {
	f := daneFacts(DANEBinding{Host: "mx1.example.net", Validated: true, Usable: 1, Outcome: DANEMatched})
	if text := mailNoteText(GradeMail(f).Notes); !strings.Contains(text, "Whether each binding holds is said below") ||
		strings.Contains(text, "binding holds was not checked") {
		t.Errorf("a scan that checked the bindings does not say so:\n%s", text)
	}

	f.ExchangersContacted, f.Exchangers, f.DANEBindings = false, nil, nil
	if text := mailNoteText(GradeMail(f).Notes); !strings.Contains(text, "Whether each binding holds was not checked") {
		t.Errorf("a scan that contacted no exchanger does not say the bindings went unchecked:\n%s", text)
	}
}
