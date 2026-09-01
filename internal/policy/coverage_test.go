package policy

import (
	"strings"
	"testing"
)

func full() CoverageFacts {
	return CoverageFacts{
		SuitesGraded:       4,
		CipherListComplete: true,
		ChainRead:          true,
		RevocationRead:     true,
		TransparencyRead:   true,
		IssuanceAnswered:   true,
	}
}

// Every combination, because a sentence assembled from clauses is only as
// honest as its worst combination.
//
// Thirty-two of them, which is cheap, and the alternative is what happened on
// the first attempt at this test: it ran one live scan, that scan had no
// transparency and no CAA, and it therefore never saw two of the five clauses
// it claimed to be checking. A sabotage that put the word "no" into the
// transparency clause went straight past it.
func everyCombination(t *testing.T, check func(t *testing.T, f CoverageFacts, line string)) {
	t.Helper()

	for i := 0; i < 32; i++ {
		f := CoverageFacts{
			CipherListComplete: i&1 != 0,
			ChainRead:          i&2 != 0,
			RevocationRead:     i&4 != 0,
			TransparencyRead:   i&8 != 0,
			IssuanceAnswered:   i&16 != 0,
		}
		if f.CipherListComplete {
			f.SuitesGraded = 4
		}
		check(t, f, Coverage(f))
	}
}

// Coverage says what was reached and never what was missed.
//
// The gaps belong to the unsettled notes, once. Said in two places they can
// disagree, and the place that disagrees loudest is the summary a reader
// stops at.
func TestCoverageNamesNothingItDidNotReach(t *testing.T) {
	everyCombination(t, func(t *testing.T, f CoverageFacts, line string) {
		lower := strings.ToLower(line)
		for _, absence := range []string{
			"no ", "not ", "could not", "never", "without", "missing", "unable", "failed",
		} {
			if strings.Contains(lower, absence) {
				t.Errorf("a coverage line describes an absence with %q:\n  %s\n  facts: %+v",
					absence, line, f)
			}
		}
	})
}

// Nothing reached, nothing claimed.
//
// This is the failure a coverage summary invites: a line listing the
// dimensions it looked at rather than the ones it read would be identical on
// a scan that read none of them.
func TestCoverageIsEmptyWhenNothingWasReached(t *testing.T) {
	if got := Coverage(CoverageFacts{}); got != "" {
		t.Errorf("a scan that reached nothing claims coverage:\n  %s", got)
	}

	// And a suite count with an incomplete list is not a reach either: the
	// table shows those rows whether they were all of them or not.
	if got := Coverage(CoverageFacts{SuitesGraded: 4}); got != "" {
		t.Errorf("a truncated enumeration counts as coverage:\n  %s", got)
	}
}

// Each clause waits for its own measurement, and every one of them appears
// when it holds.
func TestEachClauseWaitsForWhatItDescribes(t *testing.T) {
	clauses := map[string]func(*CoverageFacts){
		"cipher suite": func(f *CoverageFacts) { f.CipherListComplete = false },
		"trust store":  func(f *CoverageFacts) { f.ChainRead = false },
		"stapled":      func(f *CoverageFacts) { f.RevocationRead = false },
		"transparency": func(f *CoverageFacts) { f.TransparencyRead = false },
		"issuance":     func(f *CoverageFacts) { f.IssuanceAnswered = false },
	}

	whole := Coverage(full())
	for fragment := range clauses {
		if !strings.Contains(whole, fragment) {
			t.Errorf("a scan that reached everything does not mention %q:\n  %s", fragment, whole)
		}
	}

	for fragment, absent := range clauses {
		f := full()
		absent(&f)
		if strings.Contains(Coverage(f), fragment) {
			t.Errorf("%q is claimed with the measurement behind it removed", fragment)
		}
	}
}

// One sentence, and it reads as one.
func TestCoverageIsOneSentence(t *testing.T) {
	everyCombination(t, func(t *testing.T, f CoverageFacts, line string) {
		if line == "" {
			return
		}
		if strings.Contains(line, ". ") {
			t.Errorf("the coverage line is more than one sentence:\n  %s", line)
		}
		if first := line[:1]; first != strings.ToUpper(first) {
			t.Errorf("the coverage line does not begin with a capital:\n  %s", line)
		}
	})
}
