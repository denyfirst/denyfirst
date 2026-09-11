package policy

import (
	"strings"
	"testing"
)

func contentText(r WebResult) string {
	var b strings.Builder
	for _, n := range r.Notes {
		b.WriteString(n.Text)
		b.WriteString("\n")
	}
	for _, f := range r.Findings {
		b.WriteString(f.Title)
		b.WriteString(" ")
		b.WriteString(f.Rationale)
		b.WriteString("\n")
	}
	return b.String()
}

// A page nobody read produces nothing at all.
//
// The distinction R4 exists for, and the direction it has to fail in: a
// deployment that reads no bodies must not produce a report that reads like a
// page with nothing wrong in it. Silence here is correct because the admission
// belongs with the header rules, which make it once — two versions of one
// admission in one report is how a reader learns to skip both.
func TestAPageNobodyReadProducesNothing(t *testing.T) {
	got := GradeContent(ContentFacts{})

	if len(got.Findings) != 0 || len(got.Notes) != 0 {
		t.Errorf("a page that was never read produced %d findings and %d notes:\n%s",
			len(got.Findings), len(got.Notes), contentText(got))
	}
	if got.Verdict != "" {
		t.Errorf("verdict = %q, and nothing was measured", got.Verdict)
	}

	// And with the lists filled in, which is the state that matters.
	//
	// Read false beside a list of references is a caller that has wired the
	// fields inconsistently, and the zero value alone cannot tell the early
	// return from its absence: both produce nothing, because there is nothing
	// to produce. A sabotage removing the return escaped on 2026-09-11 for
	// exactly that reason. The safe reading of an inconsistent state is the one
	// that claims less, and grading a page nobody opened is a measurement the
	// report never made.
	inconsistent := GradeContent(ContentFacts{
		Blocking:       []string{"cdn.example"},
		Forms:          []string{"forms.example"},
		Passive:        []string{"images.example"},
		Truncated:      true,
		MoreThanListed: true,
	})
	if len(inconsistent.Findings) != 0 || len(inconsistent.Notes) != 0 {
		t.Errorf("references were graded against a page that was never read:\n%s",
			contentText(inconsistent))
	}
}

// A page that was read and loads nothing over plaintext is told nothing.
func TestACleanPageIsToldNothing(t *testing.T) {
	got := GradeContent(ContentFacts{Read: true})

	if len(got.Findings) != 0 || len(got.Notes) != 0 {
		t.Errorf("a page loading nothing over plaintext produced:\n%s", contentText(got))
	}
}

// What a browser refuses to load is graded.
func TestBlockedMixedContentIsGraded(t *testing.T) {
	got := GradeContent(ContentFacts{
		Read:     true,
		Blocking: []string{"cdn.example", "ads.example"},
	})

	if !hasFinding(got, "content.mixed-blocked") {
		t.Fatalf("blockable mixed content was not graded: %v", findingIDs(got))
	}
	for _, f := range got.Findings {
		if f.RuleID != "content.mixed-blocked" {
			continue
		}
		if f.Verdict != Weak {
			t.Errorf("verdict = %q, want weak", f.Verdict)
		}
		if len(f.References) == 0 {
			t.Error("the finding cites no document, so nobody can argue with it")
		}
		if f.Policy != WebVersion {
			t.Errorf("graded under %q, want %q", f.Policy, WebVersion)
		}
		for _, host := range []string{"cdn.example", "ads.example"} {
			if !strings.Contains(f.Rationale, host) {
				t.Errorf("%q is not named, so an operator is told they have a problem and not "+
					"where it is:\n%s", host, f.Rationale)
			}
		}
	}
}

// A form posting in the clear is the one rule here about the visitor.
func TestAFormPostingInTheClearIsGraded(t *testing.T) {
	got := GradeContent(ContentFacts{Read: true, Forms: []string{"forms.example"}})

	if !hasFinding(got, "content.form-posts-in-the-clear") {
		t.Fatalf("a form posting over plaintext was not graded: %v", findingIDs(got))
	}
	for _, f := range got.Findings {
		if f.RuleID != "content.form-posts-in-the-clear" {
			continue
		}
		if f.Verdict != Insecure {
			t.Errorf("verdict = %q, want insecure. A browser submits the form, so whatever was "+
				"typed goes out in the clear — that is not a degree of weakness.", f.Verdict)
		}
	}
	if got.Verdict != Insecure {
		t.Errorf("overall verdict = %q, want insecure", got.Verdict)
	}
}

// What a specification leaves open is reported and not graded (R21).
//
// Browsers upgrade some optionally-blockable content, block some, and do not
// all agree. A verdict here would be this project deciding something a
// standards body deliberately did not, and it would land on a site whose
// behaviour depends on which browser a visitor uses.
func TestPassiveMixedContentIsReportedAndNotGraded(t *testing.T) {
	got := GradeContent(ContentFacts{Read: true, Passive: []string{"images.example"}})

	if len(got.Findings) != 0 {
		t.Errorf("optionally-blockable content was graded %v", findingIDs(got))
	}
	if got.Verdict != "" {
		t.Errorf("verdict = %q, and nothing here is graded", got.Verdict)
	}
	if !strings.Contains(contentText(got), "images.example") {
		t.Errorf("it was not reported either:\n%s", contentText(got))
	}
	if !strings.Contains(contentText(got), "optionally-blockable") {
		t.Errorf("the report does not say why this is not graded:\n%s", contentText(got))
	}
}

// A sample says it is one.
//
// A list a reader takes for the set is a list they work through, believing they
// are done at the end of it.
func TestASampleSaysItIsASample(t *testing.T) {
	got := GradeContent(ContentFacts{
		Read: true, Passive: []string{"a.example"}, MoreThanListed: true,
	})
	if !strings.Contains(contentText(got), "sample") {
		t.Errorf("a bounded list did not say it was bounded:\n%s", contentText(got))
	}

	full := GradeContent(ContentFacts{Read: true, Passive: []string{"a.example"}})
	if strings.Contains(contentText(full), "sample") {
		t.Errorf("a complete list called itself a sample:\n%s", contentText(full))
	}
}

// Past the bound, nothing was established either way (R4).
func TestATruncatedPageSaysWhatItCouldNotSee(t *testing.T) {
	got := GradeContent(ContentFacts{Read: true, Truncated: true})

	if len(NotesOfKind(got.Notes, KindUnsettled)) == 0 {
		t.Errorf("a page read only in part reported nothing about the rest, so an empty list of "+
			"findings reads as a page with nothing in it:\n%s", contentText(got))
	}
	if len(got.Findings) != 0 {
		t.Errorf("a truncated read graded %v", findingIDs(got))
	}
}

// The sentence reads as English at one and at many.
func TestTheCountReadsAsEnglish(t *testing.T) {
	one := GradeContent(ContentFacts{Read: true, Forms: []string{"a.example"}})
	if text := contentText(one); !strings.Contains(text, "one form") || strings.Contains(text, "1 form") {
		t.Errorf("a single form is described as %q", text)
	}

	two := GradeContent(ContentFacts{Read: true, Forms: []string{"a.example", "b.example"}})
	if text := contentText(two); !strings.Contains(text, "2 forms") {
		t.Errorf("two forms are described as %q", text)
	}
}

// The list does not reorder itself between two scans of an unchanged page.
//
// A diff a reader has to work out is not a change is a diff that wastes them,
// and a map iteration upstream is all it would take.
func TestTheListedHostsAreStable(t *testing.T) {
	f := ContentFacts{Read: true, Blocking: []string{"c.example", "a.example", "b.example"}}

	first := contentText(GradeContent(f))
	for range 5 {
		if got := contentText(GradeContent(f)); got != first {
			t.Fatalf("two gradings of one page differ:\n%s\n---\n%s", first, got)
		}
	}
	if !strings.Contains(first, "a.example, b.example and c.example") {
		t.Errorf("the hosts are not named in a stable order:\n%s", first)
	}
}

// A reference whose host could not be read is still a reference.
//
// Dropping it would let a page hide a finding by writing an address this
// scanner cannot reduce — the reassuring answer, reached by malformed input.
func TestAReferenceWithNoReadableHostIsStillCounted(t *testing.T) {
	got := GradeContent(ContentFacts{Read: true, Blocking: []string{""}})

	if !hasFinding(got, "content.mixed-blocked") {
		t.Fatalf("a reference with an unreadable host was dropped: %v", findingIDs(got))
	}
	if text := contentText(got); !strings.Contains(text, "no host") {
		t.Errorf("the report does not say the host could not be read:\n%s", text)
	}
}

// Every content rule is graded under the web rule set and lives in its own
// namespace (R22).
func TestContentFindingsNameTheWebRuleSet(t *testing.T) {
	got := GradeContent(ContentFacts{
		Read:     true,
		Blocking: []string{"a.example"},
		Forms:    []string{"b.example"},
	})
	if len(got.Findings) == 0 {
		t.Fatal("a page this broken raised nothing")
	}
	for _, f := range got.Findings {
		if f.Policy != WebVersion {
			t.Errorf("%s is graded under %q, not %q", f.RuleID, f.Policy, WebVersion)
		}
		if !strings.HasPrefix(f.RuleID, "content.") {
			t.Errorf("%q is not in the content namespace, so a pipeline suppressing these by "+
				"prefix would miss it", f.RuleID)
		}
	}
}
