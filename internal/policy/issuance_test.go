package policy

import (
	"strings"
	"testing"
)

// Every state a resolver's answer can put a name in, and no two of them read
// the same.
//
// The cases below are not invented. Each was seen against a live host while
// the DNS client was being written, which is where the distinction the second
// one draws came from: microsoft.com publishes a CAA record set carrying only
// contactemail, and a report saying "CAA present" would have been true and
// useless.
func TestDescribeIssuanceSeparatesEveryState(t *testing.T) {
	cases := []struct {
		name  string
		facts IssuanceFacts
		want  string
	}{
		{
			name: "one authority",
			facts: IssuanceFacts{
				Checked: true, Exists: true, Validated: true,
				Authorities: []string{"letsencrypt.org"},
				FoundAt:     "denyfirst.dev", SearchedTo: "denyfirst.dev",
			},
			want: "issuance limited to letsencrypt.org (from denyfirst.dev)",
		},
		{
			name: "four authorities and separate wildcards",
			facts: IssuanceFacts{
				Checked: true, Exists: true,
				Authorities: []string{"digicert.com", "globalsign.com", "letsencrypt.org", "sectigo.com"},
				Wildcards:   []string{"sectigo.com", "digicert.com"},
				FoundAt:     "github.com", SearchedTo: "github.com",
			},
			want: "issuance limited to digicert.com, globalsign.com, letsencrypt.org and sectigo.com; " +
				"wildcards limited to sectigo.com and digicert.com (from github.com)",
		},
		{
			// The case that looks like protection and is not.
			name: "a record set that restricts nobody",
			facts: IssuanceFacts{
				Checked: true, Exists: true, Other: 1,
				FoundAt: "microsoft.com", SearchedTo: "microsoft.com",
			},
			want: "CAA present at microsoft.com, and none of it restricts issuance",
		},
		{
			name: "nothing anywhere up the tree",
			facts: IssuanceFacts{
				Checked: true, Exists: true, Validated: true,
				SearchedTo: "az", SearchComplete: true,
			},
			want: "no CAA at this name or above it, searched to az",
		},
		{
			// The same empty answer, reached the other way. The walk ran out
			// of budget, so the names above it were never asked, and the
			// sentence above would be claiming an absence nobody looked for.
			name: "nothing found, but the walk stopped short",
			facts: IssuanceFacts{
				Checked: true, Exists: true, Validated: true,
				SearchedTo: "d.example.com", SearchComplete: false,
			},
			want: "no CAA found, but the search stopped at d.example.com before reaching the top",
		},
		{
			name: "nobody may issue",
			facts: IssuanceFacts{
				Checked: true, Exists: true,
				Authorities: []string{";"},
				FoundAt:     "locked.example", SearchedTo: "locked.example",
			},
			want: "no authority is permitted to issue (from locked.example)",
		},
		{
			// issuewild without issue leaves ordinary issuance open, which is
			// worth saying rather than leaving a reader to infer from silence.
			name: "wildcards restricted and nothing else",
			facts: IssuanceFacts{
				Checked: true, Exists: true,
				Wildcards: []string{"digicert.com"},
				FoundAt:   "wild.example", SearchedTo: "wild.example",
			},
			want: "ordinary issuance is not restricted; wildcards limited to digicert.com (from wild.example)",
		},
		{
			name: "wildcards refused outright",
			facts: IssuanceFacts{
				Checked: true, Exists: true,
				Authorities: []string{"letsencrypt.org"},
				Wildcards:   []string{";"},
				FoundAt:     "nowild.example", SearchedTo: "nowild.example",
			},
			want: "issuance limited to letsencrypt.org; wildcards refused (from nowild.example)",
		},
		{
			// Not a finding about the name. No resolver, or the budget went
			// elsewhere.
			name:  "no lookup happened",
			facts: IssuanceFacts{},
			want:  "not checked",
		},
		{
			name:  "the name does not exist",
			facts: IssuanceFacts{Checked: true},
			want:  "the name does not resolve",
		},
	}

	seen := map[string]string{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DescribeIssuance(tc.facts)

			if got.Line != tc.want {
				t.Errorf("line is\n  %q\nwant\n  %q", got.Line, tc.want)
			}
			if len(got.Notes) == 0 {
				t.Error("no note; a line without one leaves a reader with a verdict and no reason")
			}
			if other, dup := seen[got.Line]; dup {
				t.Errorf("this reads the same as %q", other)
			}
			seen[got.Line] = tc.name
		})
	}
}

// Not checking is not a finding, and must not read like one.
func TestNotCheckedIsNotAnAccusation(t *testing.T) {
	got := DescribeIssuance(IssuanceFacts{})

	joined := strings.Join(got.Notes, " ")
	if !strings.Contains(joined, "not a finding about the name") {
		t.Errorf("the note does not say a missing lookup is not a fault: %s", joined)
	}
	for _, wrong := range []string{"any publicly trusted", "may therefore issue"} {
		if strings.Contains(joined, wrong) {
			t.Errorf("the note for an unchecked name borrows wording from a checked one: %q", wrong)
		}
	}
}

// The answer came from somewhere, and the report says where. Everything else
// this policy describes arrives in the handshake; this arrives from a resolver
// over a path nothing here authenticates, and a reader deciding how much to
// rely on it needs that.
func TestProvenanceIsAlwaysStated(t *testing.T) {
	validated := DescribeIssuance(IssuanceFacts{
		Checked: true, Exists: true, Validated: true,
		Authorities: []string{"letsencrypt.org"}, FoundAt: "x.test", SearchedTo: "x.test",
	})
	plain := DescribeIssuance(IssuanceFacts{
		Checked: true, Exists: true,
		Authorities: []string{"letsencrypt.org"}, FoundAt: "x.test", SearchedTo: "x.test",
	})

	v := strings.Join(validated.Notes, " ")
	p := strings.Join(plain.Notes, " ")

	if !strings.Contains(v, "DNSSEC-validated") {
		t.Error("a validated answer does not say so")
	}
	if !strings.Contains(v, "its claim rather than a check this service performed") {
		t.Error("a validated answer is presented as this service's own work")
	}

	// The ambiguity has to be stated. Most zones are unsigned, so an absent
	// AD bit usually means there was nothing to validate rather than that
	// validation failed, and the two are the same bit from here.
	if !strings.Contains(p, "not signed") || !strings.Contains(p, "look the same") {
		t.Errorf("an unvalidated answer does not say why the bit is ambiguous: %s", p)
	}
}

// Prevention and detection are two halves of one question, and the report puts
// them on adjacent lines. A reader told that issuance is restricted is exactly
// the reader most likely to stop there.
func TestEveryCheckedStateMentionsTransparency(t *testing.T) {
	states := []IssuanceFacts{
		{Checked: true, Exists: true, Authorities: []string{"letsencrypt.org"}, FoundAt: "x.test"},
		{Checked: true, Exists: true, Other: 1, FoundAt: "x.test"},
		{Checked: true, Exists: true, SearchedTo: "com"},
	}

	for _, facts := range states {
		joined := strings.Join(DescribeIssuance(facts).Notes, " ")
		if !strings.Contains(joined, "transparency") {
			t.Errorf("a checked state does not mention what records issuance when a restriction fails: %s", joined)
		}
	}
}

// The finding a name with no CAA most needs to read.
func TestNoRecordSaysWhatFollowsFromIt(t *testing.T) {
	joined := strings.Join(DescribeIssuance(IssuanceFacts{
		Checked: true, Exists: true, SearchedTo: "az", SearchComplete: true,
	}).Notes, " ")

	for _, required := range []string{
		"Any publicly trusted certificate authority may therefore issue",
		"around a hundred",
		"mandatory for authorities since 2017",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("the note does not say %q", required)
		}
	}
}

// A walk that ran out of budget must not be reported as one that found
// nothing.
//
// The two produce the same empty record list and lead to opposite
// conclusions. CAA is inherited, so a policy on example.com governs
// a.b.c.d.example.com — and with a budget of four the walk reached only
// d.example.com and reported that any authority may issue. The sentence was a
// claim about every parent, made after visiting some of them.
func TestAnUnfinishedWalkDoesNotClaimNobodyIsRestricted(t *testing.T) {
	short := DescribeIssuance(IssuanceFacts{
		Checked: true, Exists: true,
		SearchedTo: "d.example.com", SearchComplete: false,
	})

	joined := strings.Join(short.Notes, " ") + " " + short.Line
	for _, forbidden := range []string{
		"Any publicly trusted certificate authority may therefore issue",
		"no CAA at this name or above it",
	} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("an unfinished walk said %q, which is a claim about parents it never asked", forbidden)
		}
	}
	for _, required := range []string{"stopped", "not established"} {
		if !strings.Contains(strings.ToLower(joined), required) {
			t.Errorf("an unfinished walk does not say %q, so a reader cannot tell it from a finished one", required)
		}
	}
}
