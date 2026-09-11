package policy

import (
	"strings"
	"testing"
)

func mailRuleIDs(r MailFinding) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.RuleID)
	}
	return out
}

func mailHas(r MailFinding, id string) bool {
	for _, f := range r.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// mailNoteText is everything a report would print, joined, so a test can ask
// whether a sentence was said without caring which section carried it.
func mailNoteText(notes []Note) string {
	var b strings.Builder
	for _, n := range notes {
		b.WriteString(n.Text)
		b.WriteString("\n")
	}
	return b.String()
}

// A domain doing everything right is graded strong and told so.
//
// The first thing to get wrong in a rule set built around permanent errors is
// to find one where there is none.
func TestAWellConfiguredDomainRaisesNothing(t *testing.T) {
	got := GradeMail(MailFacts{
		SPFRecords:     1,
		SPFAll:         "-",
		SPFLookups:     4,
		DMARCRecords:   1,
		DMARCPolicy:    "reject",
		DMARCPercent:   100,
		DMARCReporting: true,
		TLSReporting:   true,
	})

	if got.Verdict != Strong {
		t.Errorf("verdict = %q, want strong. Findings: %v", got.Verdict, mailRuleIDs(got))
	}
	if len(got.Findings) != 0 {
		t.Errorf("a correctly configured domain raised %v", mailRuleIDs(got))
	}
}

// The graded rules, each one a specification calling something an error.
func TestMailGradesWhatASpecificationCallsAnError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		facts   MailFacts
		want    map[string]Verdict
		verdict Verdict
	}{
		{
			name:    "two SPF records",
			facts:   MailFacts{SPFRecords: 2, SPFAll: "-", DMARCRecords: 1, DMARCPolicy: "reject"},
			want:    map[string]Verdict{"mail.spf-duplicate": Insecure},
			verdict: Insecure,
		},
		{
			name: "over the ten lookups RFC 7208 allows",
			facts: MailFacts{
				SPFRecords: 1, SPFAll: "-", SPFLookups: 12, SPFLookupLimit: true,
				DMARCRecords: 1, DMARCPolicy: "reject",
			},
			want:    map[string]Verdict{"mail.spf-lookup-limit": Insecure},
			verdict: Insecure,
		},
		{
			name: "more void lookups than are allowed",
			facts: MailFacts{
				SPFRecords: 1, SPFAll: "-", SPFLookups: 6,
				SPFVoidLookups: 3, SPFVoidLimit: true,
				DMARCRecords: 1, DMARCPolicy: "reject",
			},
			want:    map[string]Verdict{"mail.spf-void-lookups": Weak},
			verdict: Weak,
		},
		{
			name:    "the policy authorises everybody",
			facts:   MailFacts{SPFRecords: 1, SPFAll: "+", DMARCRecords: 1, DMARCPolicy: "reject"},
			want:    map[string]Verdict{"mail.spf-allows-everybody": Insecure},
			verdict: Insecure,
		},
		{
			name:    "a DMARC record with no p=",
			facts:   MailFacts{SPFRecords: 1, SPFAll: "-", DMARCRecords: 1},
			want:    map[string]Verdict{"mail.dmarc-no-policy": Weak},
			verdict: Weak,
		},
		{
			name:    "two DMARC records",
			facts:   MailFacts{SPFRecords: 1, SPFAll: "-", DMARCRecords: 2},
			want:    map[string]Verdict{"mail.dmarc-duplicate": Weak},
			verdict: Weak,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := GradeMail(tc.facts)

			for id, verdict := range tc.want {
				found := false
				for _, f := range got.Findings {
					if f.RuleID != id {
						continue
					}
					found = true
					if f.Verdict != verdict {
						t.Errorf("%s = %q, want %q", id, f.Verdict, verdict)
					}
					if f.Policy != MailVersion {
						t.Errorf("%s carries policy %q, want %q. A finding naming the wrong rule "+
							"set sends a reader to the wrong changelog.", id, f.Policy, MailVersion)
					}
					if len(f.References) == 0 {
						t.Errorf("%s cites no document. A verdict nobody can look up is one "+
							"nobody can argue with.", id)
					}
				}
				if !found {
					t.Errorf("%s was not raised; got %v", id, mailRuleIDs(got))
				}
			}

			if got.Verdict != tc.verdict {
				t.Errorf("verdict = %q, want %q (findings %v)", got.Verdict, tc.verdict, mailRuleIDs(got))
			}
		})
	}
}

// The line this rule set draws, from the other side.
//
// Every case here is a domain some other scanner would mark down, and each is a
// documented, deliberate position rather than an error any specification names.
// Grading one would be reporting a correct decision as a fault (R6, R21), which
// is the failure this project objects to in other tools — so it is asserted
// rather than left to the reader of the rules.
func TestMailDoesNotGradeADeliberatePosition(t *testing.T) {
	for _, tc := range []struct {
		name  string
		facts MailFacts
	}{
		{"no SPF record at all", MailFacts{DMARCRecords: 1, DMARCPolicy: "reject"}},
		{"staging at ~all", MailFacts{SPFRecords: 1, SPFAll: "~", SPFLookups: 3, DMARCRecords: 1, DMARCPolicy: "reject"}},
		{"declining to say with ?all", MailFacts{SPFRecords: 1, SPFAll: "?", DMARCRecords: 1, DMARCPolicy: "reject"}},
		{"a record with no all mechanism", MailFacts{SPFRecords: 1, DMARCRecords: 1, DMARCPolicy: "reject"}},
		{"nine of the ten lookups", MailFacts{SPFRecords: 1, SPFAll: "-", SPFLookups: 9, DMARCRecords: 1, DMARCPolicy: "reject"}},
		{"two void lookups, which are allowed", MailFacts{SPFRecords: 1, SPFAll: "-", SPFVoidLookups: 2, DMARCRecords: 1, DMARCPolicy: "reject"}},
		{"the ptr mechanism", MailFacts{SPFRecords: 1, SPFAll: "-", SPFUsesPTR: true, DMARCRecords: 1, DMARCPolicy: "reject"}},
		{"no DMARC record", MailFacts{SPFRecords: 1, SPFAll: "-"}},
		{"monitoring at p=none", MailFacts{SPFRecords: 1, SPFAll: "-", DMARCRecords: 1, DMARCPolicy: "none"}},
		{"a rollout at 20%", MailFacts{SPFRecords: 1, SPFAll: "-", DMARCRecords: 1, DMARCPolicy: "reject", DMARCPercent: 20}},
		{"nowhere to send reports", MailFacts{SPFRecords: 1, SPFAll: "-", DMARCRecords: 1, DMARCPolicy: "reject"}},
		{"no TLS-RPT record", MailFacts{SPFRecords: 1, SPFAll: "-", DMARCRecords: 1, DMARCPolicy: "reject"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := GradeMail(tc.facts)
			if len(got.Findings) != 0 {
				t.Errorf("graded %v. Nothing here is an error any document names, so a finding "+
					"is this project inventing a threshold.", mailRuleIDs(got))
			}
			if got.Verdict != Strong {
				t.Errorf("verdict = %q, want strong", got.Verdict)
			}
		})
	}
}

// Nine of ten is not a fault, and is still the sentence the report exists for.
//
// Both halves matter. Grading it would penalise a correct configuration;
// staying silent about it would leave a domain one provider away from switching
// its own policy off with no way to find out, which is the finding this check
// was built around arriving too late to act on.
func TestTheLookupCountIsReportedBeforeItIsAFault(t *testing.T) {
	got := GradeMail(MailFacts{
		SPFRecords: 1, SPFAll: "-", SPFLookups: 9,
		SPFIncludes:  []string{"spf.example.net", "_spf.example.org"},
		DMARCRecords: 1, DMARCPolicy: "reject",
	})

	if len(got.Findings) != 0 {
		t.Fatalf("nine of ten was graded %v", mailRuleIDs(got))
	}

	text := mailNoteText(got.Notes)
	if !strings.Contains(text, "9 of the ten") {
		t.Errorf("the count was not reported. Notes:\n%s", text)
	}

	// The domains too, because the count alone tells an operator they have a
	// problem and nothing about where it is.
	for _, name := range []string{"spf.example.net", "_spf.example.org"} {
		if !strings.Contains(text, name) {
			t.Errorf("%q is not named, so the count says a policy is expensive without saying "+
				"which part of it is. Notes:\n%s", name, text)
		}
	}
}

// Over the limit, the count belongs to the finding rather than to a note that
// contradicts it.
func TestOverTheLimitTheCountIsNotAlsoReportedAsFine(t *testing.T) {
	got := GradeMail(MailFacts{
		SPFRecords: 1, SPFAll: "-", SPFLookups: 13, SPFLookupLimit: true,
		DMARCRecords: 1, DMARCPolicy: "reject",
	})

	if !mailHas(got, "mail.spf-lookup-limit") {
		t.Fatalf("the limit was not raised: %v", mailRuleIDs(got))
	}
	if text := mailNoteText(got.Notes); strings.Contains(text, "of the ten DNS lookups RFC 7208 allows") {
		t.Errorf("a report that grades a policy as over the limit also says it takes so many of "+
			"the ten allowed, which reads as though it were within them. Notes:\n%s", text)
	}
}

// A failure to read is not a domain without a policy, and the two send a reader
// to opposite places (R4).
func TestNotReadIsDistinguishableFromNotPublished(t *testing.T) {
	unread := GradeMail(MailFacts{SPFReason: "the resolver returned no answer", DMARCReason: "the DMARC record could not be read"})
	if len(unread.Findings) != 0 {
		t.Errorf("a domain nothing could be read from was graded %v. Nothing was measured, so "+
			"nothing can be wrong.", mailRuleIDs(unread))
	}

	text := mailNoteText(unread.Notes)
	if !strings.Contains(text, "not read") {
		t.Errorf("a failed lookup was not reported as one. Notes:\n%s", text)
	}
	if strings.Contains(text, "publishes no SPF record") || strings.Contains(text, "publishes no DMARC record") {
		t.Errorf("a lookup that failed was reported as a domain publishing nothing, which is a "+
			"claim about the domain this scan did not establish. Notes:\n%s", text)
	}

	// And the unsettled section rather than the observed one, since that is
	// what the two headings mean.
	if len(NotesOfKind(unread.Notes, KindUnsettled)) != 2 {
		t.Errorf("want both failures under \"not established\"; got %d",
			len(NotesOfKind(unread.Notes, KindUnsettled)))
	}
}

// Every mail report carries the limit, whatever the domain looks like.
//
// The check reads DNS and nothing else, so a report listing what a domain
// publishes and saying nothing further reads as a complete picture of its mail.
// It is a complete picture of its DNS.
func TestEveryMailReportSaysItOnlyReadDNS(t *testing.T) {
	for _, facts := range []MailFacts{
		{},
		{SPFRecords: 1, SPFAll: "-", DMARCRecords: 1, DMARCPolicy: "reject", TLSReporting: true},
		{SPFRecords: 4, SPFAll: "+", DMARCRecords: 3},
		{SPFReason: "the resolver returned no answer"},
	} {
		standing := NotesOfKind(GradeMail(facts).Notes, KindStanding)
		if len(standing) != len(MailStandingLimits()) {
			t.Fatalf("got %d standing notes, want %d", len(standing), len(MailStandingLimits()))
		}
		if !strings.Contains(standing[0].Text, "DKIM") {
			t.Errorf("the standing limit does not mention DKIM, so a report that checked no "+
				"selector reads as one that found none: %q", standing[0].Text)
		}
	}
}

// The limits come from the declaration, not from a second copy in the report.
//
// Two versions of the sentence a reader is asked to trust is how the page and
// the terminal stop agreeing, which R16 is about and which has happened here
// before.
func TestTheMailLimitIsTheDeclaredOne(t *testing.T) {
	notes := NotesOfKind(GradeMail(MailFacts{}).Notes, KindStanding)
	limits := MailStandingLimits()

	if len(notes) != len(limits) {
		t.Fatalf("got %d notes for %d limits", len(notes), len(limits))
	}
	for i, l := range limits {
		if notes[i].Text != l.Note().Text {
			t.Errorf("limit %q reads differently in the report than in the declaration", l.ID)
		}
	}
}

// The mail rules grade under the mail rule set and no other (R22).
func TestMailFindingsNameTheMailRuleSet(t *testing.T) {
	got := GradeMail(MailFacts{SPFRecords: 3, SPFAll: "+", DMARCRecords: 2})
	if len(got.Findings) == 0 {
		t.Fatal("a domain this broken raised nothing")
	}
	for _, f := range got.Findings {
		if f.Policy != MailVersion {
			t.Errorf("%s is graded under %q, not %q", f.RuleID, f.Policy, MailVersion)
		}
		if !strings.HasPrefix(f.RuleID, "mail.") {
			t.Errorf("%q is not in the mail namespace, so a pipeline suppressing mail rules by "+
				"prefix would miss it", f.RuleID)
		}
	}
}

// includeList reads as English at every length.
//
// Small, and the reason it is asserted is that the alternative — a list printed
// with a trailing comma, or "It pulls in ." for a policy with no includes — is
// the kind of thing that makes a reader doubt the numbers beside it.
func TestIncludeListReadsAsASentence(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"a.example"}, " It pulls in a.example."},
		{[]string{"a.example", "b.example"}, " It pulls in a.example and b.example."},
		{[]string{"a.example", "b.example", "c.example"}, " It pulls in a.example, b.example and c.example."},
	} {
		if got := includeList(tc.in); got != tc.want {
			t.Errorf("includeList(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
