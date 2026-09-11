package policy

import (
	"strings"
	"testing"
)

func present(names ...string) HeaderFacts {
	f := HeaderFacts{Answered: true, Present: map[string]bool{}}
	for _, n := range names {
		f.Present[n] = true
	}
	return f
}

// The one header combination a browser refuses is graded.
//
// It is the only one here that meets the test: the scan reads both values, the
// specification forbids the pair, and the browser's answer follows from what
// was read rather than from anything about the site this scan did not see.
func TestCorsHeadersThatContradictEachOtherAreGraded(t *testing.T) {
	f := present("Access-Control-Allow-Origin", "Access-Control-Allow-Credentials")
	f.ACAO = "*"
	f.ACAC = "true"

	got := GradeHeaders(f)
	if !hasFinding(got, "headers.cors-wildcard-with-credentials") {
		t.Errorf("got %v, want the CORS contradiction graded", findingIDs(got))
	}
}

// And each half on its own is not.
//
// A wildcard origin without credentials is how public sharing is configured. A
// credentials header with a named origin is how private sharing is configured.
// Neither is a fault, and a rule that fired on either would be failing sites
// for doing the thing correctly (R6).
func TestEitherHalfOfTheCorsPairAloneIsNotGraded(t *testing.T) {
	for _, tc := range []struct {
		name       string
		acao, acac string
	}{
		{"a wildcard with no credentials", "*", ""},
		{"a named origin with credentials", "https://app.example.test", "true"},
		{"a wildcard with credentials explicitly false", "*", "false"},
		{"neither header", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := present("Content-Security-Policy", "X-Content-Type-Options",
				"Referrer-Policy", "Permissions-Policy",
				"Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy")
			f.ACAO = tc.acao
			f.ACAC = tc.acac

			if got := GradeHeaders(f); len(got.Findings) != 0 {
				t.Errorf("%s was graded %v", tc.name, findingIDs(got))
			}
		})
	}
}

// The well-known security headers are reported and not graded, and this is the
// decision the whole file turns on.
//
// Every one of them is a header a correctly configured site can legitimately
// not send: what each buys depends on what the site does, which a scan of one
// response cannot see. Commercial scanners award points against thresholds
// they wrote themselves, and R21 is the argument against doing that — a
// threshold nobody published is one nobody can correct.
func TestTheRecommendedHeadersAreReportedAndNotGraded(t *testing.T) {
	got := GradeHeaders(HeaderFacts{Answered: true, Present: map[string]bool{}})

	if len(got.Findings) != 0 {
		t.Errorf("a response with no security headers at all was graded %v; no document requires any "+
			"of them", findingIDs(got))
	}
	if got.Verdict == Weak || got.Verdict == Insecure {
		t.Errorf("a response with no security headers was graded %q", got.Verdict)
	}

	// Reported is not hidden: the list is what somebody closing gaps works
	// from, and every name has to be in it with what it does.
	notes := noteText(got)
	for _, want := range []string{
		"Content-Security-Policy", "X-Frame-Options", "Referrer-Policy",
		"Permissions-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("%s is neither graded nor reported, so a reader is told nothing about it", want)
		}
	}
	if !strings.Contains(notes, "clickjacking") {
		t.Error("the list names headers without saying what any of them does, which is a list nobody acts on")
	}
}

// nosniff is reported, and the reason is worth a test of its own.
//
// It was written as a graded finding first, and an existing test caught it: a
// correctly reached site stopped being strong. The argument for grading it is
// good — there is no arrangement that wants nosniff absent — and it is still
// not enough, because whether the absence matters depends on content types
// nothing here read. A finding grading an implication rather than a
// measurement is what R17 forbids.
func TestNosniffIsReportedAndNotGraded(t *testing.T) {
	got := GradeHeaders(present("Content-Security-Policy", "Referrer-Policy",
		"Permissions-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy"))

	if hasFinding(got, "headers.no-nosniff") {
		t.Error("a missing nosniff was graded; this scan reads no content, so whether it matters here " +
			"is not something the scan established")
	}
	if !strings.Contains(noteText(got), "nosniff") {
		t.Error("a missing nosniff was neither graded nor reported")
	}
}

// A policy supersedes the older header it replaced.
//
// frame-ancestors is what a modern site uses, and telling a site with a policy
// that it is missing X-Frame-Options would be reporting a gap it does not have
// (R6).
func TestAContentSecurityPolicySupersedesTheOlderFramingHeader(t *testing.T) {
	got := GradeHeaders(present("Content-Security-Policy"))

	if strings.Contains(noteText(got), "X-Frame-Options") {
		t.Error("a site sending a Content-Security-Policy was told it is missing X-Frame-Options, " +
			"which frame-ancestors replaced")
	}
}

// Report-only is a stage, not a protection, and is described as one.
func TestAReportOnlyPolicyIsDescribedAsNotYetEnforcing(t *testing.T) {
	got := GradeHeaders(present("Content-Security-Policy-Report-Only"))

	if len(got.Findings) != 0 {
		t.Errorf("a report-only policy was graded %v; a rollout is what the mode is for",
			findingIDs(got))
	}
	if !strings.Contains(noteText(got), "report-only") {
		t.Error("a report-only policy was not described, so a reader believes a policy is enforcing")
	}

	// And a site with both is not told its policy does nothing.
	both := GradeHeaders(present("Content-Security-Policy", "Content-Security-Policy-Report-Only"))
	if strings.Contains(noteText(both), "blocks nothing") {
		t.Error("a site enforcing a policy and also reporting on a second one was told it blocks nothing")
	}
}

// Nothing answered is not a response with no headers.
//
// An empty list of headers is what both a silent host and a bare response
// produce, and grading the first as "sends no security headers" would be a
// claim about a server this program never spoke to (R4, R23).
func TestAHostThatAnsweredNothingIsNotDescribedAsSendingNoHeaders(t *testing.T) {
	got := GradeHeaders(HeaderFacts{Answered: false})

	if len(got.Findings) != 0 {
		t.Errorf("a host that answered nothing was graded %v", findingIDs(got))
	}
	if strings.Contains(noteText(got), "did not send") {
		t.Errorf("a host that answered nothing was described as not sending headers:\n%s", noteText(got))
	}
	if !strings.Contains(noteText(got), "different from sending nothing") {
		t.Error("the report does not distinguish silence from a response carrying no headers")
	}
}

// A site that sends everything is told nothing.
//
// R6 again, and the case that keeps the report worth reading: a reader who
// gets a paragraph of observations after doing everything right learns to skip
// the paragraph.
func TestASiteThatSendsEverythingIsToldNothing(t *testing.T) {
	f := present("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options",
		"Referrer-Policy", "Permissions-Policy",
		"Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy")

	got := GradeHeaders(f)
	if len(got.Findings) != 0 || len(got.Notes) != 0 {
		t.Errorf("a fully configured response produced %v and %d notes:\n%s",
			findingIDs(got), len(got.Notes), noteText(got))
	}
}

// The list does not reorder itself between two scans of an unchanged server.
//
// A diff a reader has to work out is not a change is a diff that wastes them.
func TestTheReportedListIsStable(t *testing.T) {
	f := HeaderFacts{Answered: true, Present: map[string]bool{}}

	first := noteText(GradeHeaders(f))
	for range 5 {
		if got := noteText(GradeHeaders(f)); got != first {
			t.Fatalf("two identical responses produced different reports:\n%s\n---\n%s", first, got)
		}
	}
}

// A policy declared in the markup is a policy.
//
// The defect this closes had shipped. CSP was read from headers alone, so a
// site using <meta http-equiv="Content-Security-Policy"> was told it had no
// policy — and then told a second time that it was missing framing protection,
// because the rule that lets a policy supersede X-Frame-Options could not see
// the policy either. One omission, two wrong sentences, both about something
// the operator had already done.
func TestAPolicyInTheMarkupCountsAsAPolicy(t *testing.T) {
	f := present("X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
		"Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy")
	f.MarkupRead = true
	f.MetaCSP = true

	got := GradeHeaders(f)
	text := noteText(got)

	if strings.Contains(text, "Content-Security-Policy —") {
		t.Errorf("a site declaring a policy in its markup was told it sends none:\n%s", text)
	}
	if strings.Contains(text, "X-Frame-Options") {
		t.Errorf("a site with a policy was told it is missing framing protection, which the "+
			"policy's frame-ancestors supersedes:\n%s", text)
	}
	if len(got.Notes) != 0 {
		t.Errorf("a fully configured site with a meta policy was told %d things:\n%s",
			len(got.Notes), text)
	}
}

// A report-only policy in the markup is not an enforcing one.
func TestAReportOnlyPolicyInTheMarkupIsNotProtectionYet(t *testing.T) {
	f := present()
	f.MarkupRead = true
	f.MetaCSPReportOnly = true

	text := noteText(GradeHeaders(f))
	if !strings.Contains(text, "report-only mode") {
		t.Errorf("a report-only meta policy was not described as one:\n%s", text)
	}
	if !strings.Contains(text, "Content-Security-Policy —") {
		t.Errorf("a site with only a report-only policy was not told it sends no enforcing "+
			"policy, which is the thing it does not have:\n%s", text)
	}
}

// A check that read no body says so, where it could have changed the answer.
//
// The distinction R4 exists for: without this sentence a deployment that reads
// no markup produces the same report as one that read the page and found no
// policy in it, and only the second of those established anything.
func TestAReportThatReadNoPageSaysWhatItCouldNotSee(t *testing.T) {
	text := noteText(GradeHeaders(present()))
	if !strings.Contains(text, "<meta http-equiv>") {
		t.Errorf("a report built from headers alone does not say a meta policy would not have "+
			"been seen:\n%s", text)
	}

	// And says it only where it matters. A response carrying the header has
	// been measured; telling that site about a limit on a question already
	// answered is the paragraph R6 is about.
	withHeader := present("Content-Security-Policy")
	if strings.Contains(noteText(GradeHeaders(withHeader)), "<meta http-equiv>") {
		t.Errorf("a site sending the policy header was told about a limit that could not have "+
			"changed its report:\n%s", noteText(GradeHeaders(withHeader)))
	}

	// And not at all once the page has been read.
	read := present()
	read.MarkupRead = true
	if strings.Contains(noteText(GradeHeaders(read)), "<meta http-equiv>") {
		t.Errorf("a report that did read the page still says it did not:\n%s", noteText(GradeHeaders(read)))
	}
}

// A meta policy is not invented out of a deployment that reads no bodies.
//
// The sabotage this is written against is the easy one: wiring MetaCSP true by
// default, or forgetting MarkupRead, credits every site with a policy nobody
// looked for — and the report then claims a measurement it never made, in the
// reassuring direction.
func TestAPolicyIsNotCreditedToAPageNobodyRead(t *testing.T) {
	f := present()
	f.MetaCSP = true // set without MarkupRead, which is the inconsistent state

	if f.MarkupRead {
		t.Fatal("the fixture is not the state being tested")
	}
	text := noteText(GradeHeaders(f))
	if !strings.Contains(text, "<meta http-equiv>") {
		t.Errorf("a report that read no page did not say so:\n%s", text)
	}
}
