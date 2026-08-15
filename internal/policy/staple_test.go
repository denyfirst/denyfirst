package policy

import (
	"strings"
	"testing"
)

// The whole rule, stated as a table. Four inputs, and the grade turns on
// exactly one of the four combinations.
func TestGradeStaplingGradesOnlyTheBrokenPromise(t *testing.T) {
	cases := []struct {
		name  string
		facts StapleFacts
		want  Verdict
	}{
		{
			// The one graded case. The certificate told clients to refuse
			// without a status response and the server sent none.
			name:  "must-staple demanded and not honoured",
			facts: StapleFacts{MustStaple: true, HasResponder: true},
			want:  Insecure,
		},
		{
			name:  "must-staple demanded and honoured",
			facts: StapleFacts{MustStaple: true, HasResponder: true, Stapled: true},
			want:  Strong,
		},
		{
			// Stapling without being asked to is good practice and is not
			// graded either way. Nothing here validates the response, so
			// awarding a grade for it would be awarding a grade for a byte
			// count.
			name:  "stapled without being required",
			facts: StapleFacts{HasResponder: true, Stapled: true},
			want:  Strong,
		},
		{
			// The case every scanner that still grades this gets wrong. The
			// authority decides whether a response exists; the server does
			// not.
			name:  "not stapled, responder exists",
			facts: StapleFacts{HasResponder: true, HasCRL: true},
			want:  Strong,
		},
		{
			// A certificate issued under the current requirements: no OCSP,
			// revocation published as a list. Nothing to staple and nothing
			// to say against the server.
			name:  "not stapled, revocation published as a list",
			facts: StapleFacts{HasCRL: true},
			want:  Strong,
		},
		{
			// Neither mechanism. Still not the server's fault, so still not
			// graded, but the reader is owed a different sentence.
			name:  "no responder and no list",
			facts: StapleFacts{},
			want:  Strong,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GradeStapling(tc.facts)
			if got.Verdict != tc.want {
				t.Errorf("verdict = %q, want %q", got.Verdict, tc.want)
			}

			// Every branch says something. Silence about revocation is read
			// as a clean bill of health, which is the failure this file
			// exists to prevent.
			if len(got.Notes) == 0 {
				t.Error("no note; a reader told nothing about revocation assumes it was checked")
			}
		})
	}
}

// A missing staple is a fact, not a fault, and it must not become one by
// accident. A rule added to this file without the reasoning at the top being
// revisited would show up here first.
func TestMissingStapleIsNotAFinding(t *testing.T) {
	for _, facts := range []StapleFacts{
		{},
		{HasCRL: true},
		{HasResponder: true, HasCRL: true},
		{Stapled: true},
		{HasResponder: true, HasCRL: true, Stapled: true},
	} {
		got := GradeStapling(facts)
		if len(got.Findings) != 0 {
			t.Errorf("%+v produced %d findings; only an unhonoured must-staple is graded",
				facts, len(got.Findings))
		}
	}
}

// The finding has to carry the documents behind it, like every other finding
// in this package. A verdict without a citation is an opinion.
func TestMustStapleFindingCitesItsSources(t *testing.T) {
	got := GradeStapling(StapleFacts{MustStaple: true, HasResponder: true})

	if len(got.Findings) != 1 {
		t.Fatalf("%d findings, want exactly 1", len(got.Findings))
	}
	f := got.Findings[0]

	if f.RuleID != "cert.must-staple-not-stapled" {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	if f.Policy != Version {
		t.Errorf("Policy = %q, want %q", f.Policy, Version)
	}
	if len(f.References) == 0 {
		t.Fatal("the finding cites nothing")
	}

	var found bool
	for _, ref := range f.References {
		if strings.Contains(ref.URL, "rfc7633") {
			found = true
		}
		if ref.Label == "" || !strings.HasPrefix(ref.URL, "https://") {
			t.Errorf("reference %+v is not usable", ref)
		}
	}
	if !found {
		t.Error("the finding does not cite RFC 7633, which is the document that defines the requirement")
	}
}

// A stapled response is not a checked response, and the note has to say so.
//
// This is the sentence that stops the report from claiming more than it
// measured: nothing in this project parses an OCSP response, verifies its
// signature, or matches its serial. A reader who sees "stapled" and is not
// told that will conclude revocation was checked.
func TestStapledNoteDoesNotClaimTheResponseWasChecked(t *testing.T) {
	note := strings.ToLower(strings.Join(GradeStapling(StapleFacts{Stapled: true}).Notes, " "))

	for _, required := range []string{"not read", "signature was not verified"} {
		if !strings.Contains(note, required) {
			t.Errorf("the note for a stapled response does not say %q; it reads: %s", required, note)
		}
	}
}

// The three unstapled cases are different situations and must not share a
// sentence. One describes a server that could have stapled; one a certificate
// whose revocation is published as a list; one a certificate with no published
// revocation channel at all.
func TestUnstapledNotesDistinguishThreeSituations(t *testing.T) {
	responder := strings.Join(GradeStapling(StapleFacts{HasResponder: true, HasCRL: true}).Notes, " ")
	listOnly := strings.Join(GradeStapling(StapleFacts{HasCRL: true}).Notes, " ")
	neither := strings.Join(GradeStapling(StapleFacts{}).Notes, " ")

	if responder == listOnly || listOnly == neither || responder == neither {
		t.Fatal("two unstapled cases produce the same note; the difference between them is the point")
	}
	if !strings.Contains(listOnly, "published as a list") {
		t.Errorf("the note for a list-only certificate does not say so: %s", listOnly)
	}
	if !strings.Contains(neither, "nowhere to ask") {
		t.Errorf("the note for a certificate with no revocation channel does not say so: %s", neither)
	}
}

// The claim in the list-only note is a claim about data, and it must not be
// made when the data does not support it.
//
// This is the bug the first version of this file shipped with: the note said
// revocation was published as a list for every certificate that named no
// responder, including the ones that named no list either. The certificate
// carried the answer — CRLDistributionPoints — and the rule was not given it.
func TestListClaimIsNotMadeWithoutAList(t *testing.T) {
	notes := strings.Join(GradeStapling(StapleFacts{}).Notes, " ")

	if strings.Contains(notes, "published as a list") {
		t.Errorf("a certificate with no distribution point is described as publishing a list: %s", notes)
	}
}
