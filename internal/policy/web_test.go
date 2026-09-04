package policy

import (
	"strings"
	"testing"
)

// answered is a hop that returned a status.
func answered(tls bool, status int) WebHop { return WebHop{TLS: tls, Answered: true, Status: status} }

// dead is a hop that produced no response.
func dead(tls bool) WebHop { return WebHop{TLS: tls} }

func webRuleIDs(r WebResult) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.RuleID)
	}
	return out
}

func webHas(r WebResult, id string) bool {
	for _, f := range r.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestReachGradesHowAVisitorArrives(t *testing.T) {
	secureOK := []WebHop{answered(true, 200)}

	for _, tc := range []struct {
		name    string
		secure  []WebHop
		plain   []WebHop
		want    map[string]Verdict
		verdict Verdict
	}{
		{
			name:    "plaintext redirects straight to TLS",
			secure:  secureOK,
			plain:   []WebHop{answered(false, 301), answered(true, 200)},
			want:    nil,
			verdict: Strong,
		},
		{
			name:    "nothing on port 80 at all",
			secure:  secureOK,
			plain:   []WebHop{dead(false)},
			want:    nil,
			verdict: Strong,
		},
		{
			name:    "a page is served in the clear",
			secure:  secureOK,
			plain:   []WebHop{answered(false, 200)},
			want:    map[string]Verdict{"reach.plaintext-served": Insecure},
			verdict: Insecure,
		},
		{
			name:    "the redirects never arrive at TLS",
			secure:  secureOK,
			plain:   []WebHop{answered(false, 301), answered(false, 302), answered(false, 302)},
			want:    map[string]Verdict{"reach.never-reaches-tls": Insecure},
			verdict: Insecure,
		},
		{
			name:    "plaintext answers, and does not redirect",
			secure:  secureOK,
			plain:   []WebHop{answered(false, 404)},
			want:    map[string]Verdict{"reach.plaintext-not-redirected": Weak},
			verdict: Weak,
		},
		{
			// The common one: apex to www over plaintext, and only then to
			// TLS. Two cleartext requests where one was needed.
			name:    "TLS is reached, but only after a second cleartext request",
			secure:  secureOK,
			plain:   []WebHop{answered(false, 301), answered(false, 301), answered(true, 200)},
			want:    map[string]Verdict{"reach.redirect-via-plaintext": Weak},
			verdict: Weak,
		},
		{
			name:    "the secure address sends visitors back to plaintext",
			secure:  []WebHop{answered(true, 302), answered(false, 200)},
			plain:   []WebHop{answered(false, 200)},
			want:    map[string]Verdict{"reach.downgrades-to-plaintext": Insecure, "reach.plaintext-served": Insecure},
			verdict: Insecure,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := GradeReach(tc.secure, tc.plain)
			if len(got.Findings) != len(tc.want) {
				t.Fatalf("findings %v, want %v", webRuleIDs(got), tc.want)
			}
			// Each finding's own verdict, not only the worst of them. Two
			// insecure findings together hide a softened one behind the
			// aggregate, and a sabotage escaped through exactly that gap.
			for _, f := range got.Findings {
				want, ok := tc.want[f.RuleID]
				if !ok {
					t.Errorf("unexpected finding %s", f.RuleID)
					continue
				}
				if f.Verdict != want {
					t.Errorf("%s is graded %q, want %q", f.RuleID, f.Verdict, want)
				}
			}
			if got.Verdict != tc.verdict {
				t.Errorf("verdict %q, want %q", got.Verdict, tc.verdict)
			}
		})
	}
}

func TestNothingOnPortEightyIsObservedRatherThanGraded(t *testing.T) {
	// A host with no plaintext listener has nothing to intercept. Reporting
	// that as a fault would be penalising the safest arrangement there is.
	got := GradeReach([]WebHop{answered(true, 200)}, []WebHop{dead(false)})
	if len(got.Findings) != 0 {
		t.Fatalf("graded a host with no plaintext listener: %v", webRuleIDs(got))
	}
	if len(got.Notes) == 0 {
		t.Fatal("and said nothing about it either")
	}
}

func TestAHostThatDoesNotAnswerOverTLSIsUnsettledNotGraded(t *testing.T) {
	// Whether the handshake works is the TLS check's question. Saying
	// nothing would be wrong; answering it here would be two rule sets
	// grading one fact.
	got := GradeReach([]WebHop{dead(true)}, []WebHop{dead(false)})
	for _, n := range got.Notes {
		if n.Kind == KindUnsettled {
			return
		}
	}
	t.Fatalf("no unsettled note: %+v", got.Notes)
}

func TestATemporaryRedirectIsDescribedNotGraded(t *testing.T) {
	got := GradeReach([]WebHop{answered(true, 200)}, []WebHop{answered(false, 302), answered(true, 200)})
	if len(got.Findings) != 0 {
		t.Fatalf("a working redirect was graded: %v", webRuleIDs(got))
	}
	if len(got.Notes) == 0 {
		t.Fatal("nothing was said about the redirect being temporary")
	}
}

func TestAPermanentRedirectIsNotCalledTemporary(t *testing.T) {
	// Written because a sabotage escaped on 2026-09-04: reporting 301 and 308
	// as temporary changed nothing any test looked at, so a reader would have
	// been told a correct redirect was the weaker kind. The test above checks
	// that a 302 produces a note; nothing checked that a 301 produces none.
	for _, status := range []int{301, 308} {
		got := GradeReach([]WebHop{answered(true, 200)}, []WebHop{answered(false, status), answered(true, 200)})
		if len(got.Findings) != 0 {
			t.Errorf("%d was graded: %v", status, webRuleIDs(got))
		}
		if strings.Contains(notesText(got), "temporary") {
			t.Errorf("%d is a permanent redirect and was described as temporary: %q", status, notesText(got))
		}
	}
}

func TestAChainEndingOnPlaintextIsNeverSound(t *testing.T) {
	// The worst answer this rule set could give. Pinned directly rather than
	// left to depend on reach.downgrades-to-plaintext continuing to fire,
	// which is what makes it true today.
	got := GradeReach(
		[]WebHop{answered(true, 302), answered(false, 200)},
		[]WebHop{answered(false, 200)},
	)
	if got.Verdict == Strong {
		t.Fatal("a site whose secure address ends on a plaintext one was called sound")
	}
	if got.Verdict != Insecure {
		t.Errorf("verdict %q, want insecure", got.Verdict)
	}
}

func TestParseHSTS(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  HSTS
	}{
		{"the ordinary one", "max-age=31536000", HSTS{Parsed: true, MaxAge: 31536000}},
		{"everything", "max-age=63072000; includeSubDomains; preload",
			HSTS{Parsed: true, MaxAge: 63072000, IncludeSubDomains: true, Preload: true}},
		{"directive names are case-insensitive", "MAX-AGE=1; INCLUDESUBDOMAINS; PRELOAD",
			HSTS{Parsed: true, MaxAge: 1, IncludeSubDomains: true, Preload: true}},
		{"a quoted value is in the grammar", `max-age="31536000"`, HSTS{Parsed: true, MaxAge: 31536000}},
		{"whitespace everywhere", "  max-age = 100 ;  includeSubDomains  ",
			HSTS{Parsed: true, MaxAge: 100, IncludeSubDomains: true}},
		{"zero is a value, not an absence", "max-age=0", HSTS{Parsed: true, MaxAge: 0}},
		{"no max-age at all", "includeSubDomains; preload",
			HSTS{IncludeSubDomains: true, Preload: true}},
		{"a max-age that is not a number", "max-age=forever", HSTS{}},
		{"a negative max-age is not a number here", "max-age=-1", HSTS{}},
		{"the first max-age wins", "max-age=100; max-age=99999", HSTS{Parsed: true, MaxAge: 100}},
		{"empty", "", HSTS{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseHSTS(tc.value); got != tc.want {
				t.Errorf("ParseHSTS(%q) = %+v, want %+v", tc.value, got, tc.want)
			}
		})
	}
}

func TestGradeHSTS(t *testing.T) {
	for _, tc := range []struct {
		name    string
		secure  []string
		plain   []string
		want    string
		verdict Verdict
	}{
		{"absent", nil, nil, "hsts.absent", Weak},
		{"sent only where it is ignored", nil, []string{"max-age=31536000"}, "hsts.plaintext-only", Weak},
		{"no readable max-age", []string{"includeSubDomains"}, nil, "hsts.unparseable", Weak},
		{"withdrawn", []string{"max-age=0"}, nil, "hsts.disabled", Weak},
		{"preload asked for without a year", []string{"max-age=86400; includeSubDomains; preload"}, nil,
			"hsts.preload-ineffective", Weak},
		{"preload asked for without subdomains", []string{"max-age=63072000; preload"}, nil,
			"hsts.preload-ineffective", Weak},
		{"a working policy", []string{"max-age=63072000; includeSubDomains"}, nil, "", Strong},
		{"a working policy that is preloadable", []string{"max-age=31536000; includeSubDomains; preload"}, nil,
			"", Strong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := GradeHSTS(tc.secure, tc.plain, true)
			if tc.want == "" {
				if len(got.Findings) != 0 {
					t.Fatalf("graded a correct policy: %v", webRuleIDs(got))
				}
				if got.Verdict != tc.verdict {
					t.Errorf("a working policy is %q, want %q", got.Verdict, tc.verdict)
				}
				return
			}
			if len(got.Findings) != 1 || got.Findings[0].RuleID != tc.want {
				t.Fatalf("findings %v, want exactly [%s]", webRuleIDs(got), tc.want)
			}
			if got.Verdict != tc.verdict {
				t.Errorf("verdict %q, want %q", got.Verdict, tc.verdict)
			}
		})
	}
}

func TestAShortMaxAgeIsDescribedAndNotGraded(t *testing.T) {
	// No standards body publishes a minimum, and OWASP recommends a short one
	// during a rollout. A rule failing anything under a year would be this
	// project inventing a threshold and then penalising a correct choice.
	got := GradeHSTS([]string{"max-age=86400; includeSubDomains"}, nil, true)
	if len(got.Findings) != 0 {
		t.Fatalf("a short max-age was graded: %v", webRuleIDs(got))
	}
	if len(got.Notes) == 0 {
		t.Fatal("and nothing was said about how long it lasts")
	}

	joined := notesText(got)
	if !strings.Contains(joined, "day") {
		t.Errorf("the note does not say how long the policy lasts: %q", joined)
	}
	if !strings.Contains(joined, "preload") {
		t.Errorf("the note does not say what the one-year figure is for: %q", joined)
	}
}

func TestIncludeSubDomainsIsDescribedAndNotGraded(t *testing.T) {
	// A host with nothing beneath it needs no subdomain clause, and a scan of
	// one host cannot see what is beneath it. R6: correct configuration is
	// not penalised.
	got := GradeHSTS([]string{"max-age=63072000"}, nil, true)
	if len(got.Findings) != 0 {
		t.Fatalf("the absence of includeSubDomains was graded: %v", webRuleIDs(got))
	}
	if !strings.Contains(notesText(got), "subdomain") {
		t.Errorf("nothing was said about subdomains: %q", notesText(got))
	}
}

func TestOnlyTheFirstHSTSHeaderIsGraded(t *testing.T) {
	// RFC 6797 section 8.1: a user agent processes only the first. Grading
	// the most generous of several would describe a policy no browser
	// applies.
	got := GradeHSTS([]string{"max-age=0", "max-age=63072000; includeSubDomains"}, nil, true)
	if !webHas(got, "hsts.disabled") {
		t.Fatalf("the second header was graded instead of the first: %v", webRuleIDs(got))
	}
	if !strings.Contains(notesText(got), "only the first") {
		t.Errorf("the reader is not told that the rest had no effect: %q", notesText(got))
	}
}

func TestEveryWebFindingIsUsableOnItsOwn(t *testing.T) {
	// A finding travels without the code that made it: it has to name its
	// rule set, carry a rule identifier somebody can suppress by, say what is
	// wrong in terms of consequence, and cite something a reader can check.
	var all []Finding
	for _, r := range []WebResult{
		GradeReach([]WebHop{answered(true, 302), answered(false, 200)}, []WebHop{answered(false, 200)}),
		GradeReach([]WebHop{answered(true, 200)}, []WebHop{answered(false, 404)}),
		GradeReach([]WebHop{answered(true, 200)}, []WebHop{answered(false, 301), answered(false, 301), answered(true, 200)}),
		GradeReach([]WebHop{answered(true, 200)}, []WebHop{answered(false, 301), answered(false, 302)}),
		GradeHSTS(nil, nil, true),
		GradeHSTS(nil, []string{"max-age=1"}, true),
		GradeHSTS([]string{"includeSubDomains"}, nil, true),
		GradeHSTS([]string{"max-age=0"}, nil, true),
		GradeHSTS([]string{"max-age=1; preload"}, nil, true),
	} {
		all = append(all, r.Findings...)
	}
	if len(all) < 9 {
		t.Fatalf("only %d findings were produced; the table above is meant to reach every rule", len(all))
	}

	seen := map[string]bool{}
	for _, f := range all {
		if f.Policy != WebVersion {
			t.Errorf("%s names policy %q, want %q", f.RuleID, f.Policy, WebVersion)
		}
		if f.RuleID == "" || f.Title == "" || f.Rationale == "" {
			t.Errorf("incomplete finding: %+v", f)
		}
		if len(f.References) == 0 {
			t.Errorf("%s cites nothing", f.RuleID)
		}
		for _, ref := range f.References {
			if ref.Label == "" || !strings.HasPrefix(ref.URL, "https://") {
				t.Errorf("%s carries a reference a reader cannot follow: %+v", f.RuleID, ref)
			}
		}
		if f.Verdict != Weak && f.Verdict != Insecure {
			t.Errorf("%s is graded %q; a finding is weak or insecure", f.RuleID, f.Verdict)
		}
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
	}

	// Every rule this file defines has to be reachable, or it is a rule that
	// cannot fire and nobody would know.
	for _, id := range []string{
		"reach.plaintext-served", "reach.plaintext-not-redirected", "reach.redirect-via-plaintext",
		"reach.never-reaches-tls", "reach.downgrades-to-plaintext",
		"hsts.absent", "hsts.plaintext-only", "hsts.unparseable", "hsts.disabled",
		"hsts.preload-ineffective",
	} {
		if !seen[id] {
			t.Errorf("%s was never produced by any case above", id)
		}
	}
}

func TestTheWebRuleSetIsNamedForItsCheck(t *testing.T) {
	// A number on its own stops meaning one thing the moment a second check
	// exists, which is now.
	if !strings.HasPrefix(WebVersion, "denyfirst-web-") {
		t.Errorf("WebVersion is %q; it has to name the check it grades", WebVersion)
	}
	if WebVersion == TLSVersion {
		t.Error("the two rule sets share a name")
	}
}

func TestTheWebLimitsAreItsOwn(t *testing.T) {
	// What a TLS scan cannot establish and what a header check cannot
	// establish are different lists. One list read under both headings is a
	// list nobody reads.
	web := WebStandingLimits()
	if len(web) == 0 {
		t.Fatal("the web check declares no limits")
	}
	for _, w := range web {
		if w.ID == "" || w.Title == "" || w.Text == "" {
			t.Errorf("incomplete limit: %+v", w)
		}
		for _, tls := range StandingLimits() {
			if w.ID == tls.ID {
				t.Errorf("%s appears in both sets", w.ID)
			}
		}
		// IsStandingLimit answers for the TLS set. A web limit must not be
		// mistaken for one, or a report could carry it under the wrong
		// heading and the test that guards that heading would pass.
		if IsStandingLimit(w.Text) {
			t.Errorf("%s is indistinguishable from a TLS limit", w.ID)
		}
	}
}

func TestHumanAge(t *testing.T) {
	// A report saying "31536000" asks its reader to divide.
	for _, tc := range []struct {
		seconds int64
		want    string
	}{
		{63072000, "2 years"},
		{31536000, "a year"},
		{15768000, "182 days"},
		{86400, "a day"},
		{3600, "60 minutes"},
		{30, "30 seconds"},
	} {
		if got := humanAge(tc.seconds); got != tc.want {
			t.Errorf("humanAge(%d) = %q, want %q", tc.seconds, got, tc.want)
		}
	}
}

func notesText(r WebResult) string {
	var b strings.Builder
	for _, n := range r.Notes {
		b.WriteString(n.Text)
		b.WriteString(" ")
	}
	return b.String()
}
