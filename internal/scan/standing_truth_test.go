package scan

import (
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/policy"
)

// A standing limit describes what this build actually does.
//
// It is the strongest sentence in a report: findings are about one server, and
// a standing limit says what is true of every scan this program runs. So a
// stale one is the worst kind of wrong — it is wrong about us, on every report,
// and a reader has no way to check it.
//
// One went stale and shipped. "No certificate authority is ever asked ...
// revocation is read only from a response the server stapled into the
// handshake, so where none was stapled it has not been established here by any
// means" stayed word for word while an ordinary build started fetching the
// authority's revocation list — so a single report said the list had been
// fetched and verified, two inches above a limit saying nothing had been asked
// of anybody.
//
// This test lives here rather than in internal/policy because this is the
// package that does the fetching. The limit is written where the rules are; the
// behaviour it describes is here, and only something that can see both can tell
// whether they agree.
func TestTheRevocationLimitDescribesThisBuild(t *testing.T) {
	var limit policy.StandingLimit
	for _, l := range policy.StandingLimits() {
		if l.ID == "no-authority-asked" {
			limit = l
		}
	}
	if limit.ID == "" {
		t.Fatal("the revocation limit is no longer declared, so nothing on a report says what is " +
			"asked of an authority")
	}

	text := limit.Title + " " + limit.Text

	// True of every build, and the whole point of the limit: the question that
	// names a certificate is never put.
	if !strings.Contains(text, "serial number") {
		t.Error("the limit does not say why the question is refused, which is the part that " +
			"makes it a decision rather than an omission")
	}

	if demo.Enabled {
		// This build compiles the fetch out. See scan.go: the branch is behind
		// a constant, so there is nothing to switch on.
		if !strings.Contains(text, "compiled out") {
			t.Error("the demonstration's limit does not say the fetch is compiled out rather " +
				"than merely not configured, which is the difference a reader is being asked " +
				"to trust")
		}
		return
	}

	// An ordinary build fetches a revocation list when a certificate names
	// one. A limit claiming otherwise is a report contradicting itself.
	if !strings.Contains(text, "revocation list") {
		t.Error("this build fetches the authority's revocation list and the limit does not " +
			"mention one, so a report says the list was fetched and also that nothing was asked")
	}

	for _, stale := range []string{
		// The exact sentences that went stale, in the text.
		"No certificate authority is asked anything",
		"read only from a response the server stapled",
		"has not been established here by any means",

		// And in the title, which is the falsest part of all of it and the
		// part a reader skimming a report actually reads. A sabotage putting
		// only the old title back escaped the first version of this test,
		// because the list above described the paragraph and the heading above
		// it said something broader and simply untrue.
		"is ever asked",
	} {
		if strings.Contains(text, stale) {
			t.Errorf("the limit still says %q, which stopped being true when this build started "+
				"fetching revocation lists", stale)
		}
	}

	// The title claims something narrower than "nothing is ever asked",
	// because something is. Asserted as a property rather than as a spelling:
	// whatever it says, it has to be about this certificate rather than about
	// authorities in general.
	if !strings.Contains(limit.Title, "this certificate") {
		t.Errorf("the title is %q. It has to name what is actually refused — a question about "+
			"this certificate — rather than claim nothing is asked of anybody.", limit.Title)
	}
}

// And the fetch it describes is really in this build.
//
// The other direction. If the fetch were removed and the limit kept, the limit
// would be describing something that no longer happens — the same defect
// pointing the other way, and the one a reader could not detect at all because
// it errs towards claiming less.
func TestThisBuildReallyFetchesWhatTheLimitDescribes(t *testing.T) {
	s := &Scanner{}

	if demo.Enabled {
		if s.revocationFetched() {
			t.Error("the demonstration fetches a revocation list, and its limit says the call is " +
				"compiled out")
		}
		return
	}

	if !s.revocationFetched() {
		t.Error("this build fetches no revocation list, and the limit on every report says it " +
			"does. A limit claiming less than the truth is one nobody can check.")
	}
}
