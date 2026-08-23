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
			// Honoured means a response that verifies. Bytes alone used to
			// satisfy this, so a certificate demanding a staple and getting
			// sixteen bytes of rubbish passed.
			name:  "must-staple demanded and honoured",
			facts: StapleFacts{MustStaple: true, HasResponder: true, Stapled: true, Validated: true, Status: "good"},
			want:  Strong,
		},
		{
			// To a client honouring the extension this is the same outcome as
			// no response at all: the handshake fails.
			name:  "must-staple demanded and the response does not verify",
			facts: StapleFacts{MustStaple: true, HasResponder: true, Stapled: true, Unverifiable: "the response expired"},
			want:  Insecure,
		},
		{
			// Stapling without being asked to is good practice and is not
			// graded upward. A response that verifies and says good earns no
			// points; it removes a doubt.
			name:  "stapled without being required",
			facts: StapleFacts{HasResponder: true, Stapled: true, Validated: true, Status: "good"},
			want:  Strong,
		},
		{
			// The finding this whole path exists for.
			name:  "the authority says the certificate is revoked",
			facts: StapleFacts{HasResponder: true, Stapled: true, Validated: true, Status: "revoked"},
			want:  Insecure,
		},
		{
			// Not the same as not revoked.
			name:  "the authority does not recognise the certificate",
			facts: StapleFacts{HasResponder: true, Stapled: true, Validated: true, Status: "unknown"},
			want:  Weak,
		},
		{
			// The certificate may be fine; the stapling is not, and a reader
			// shown a check that did not happen is the harm.
			name:  "stapled and unverifiable",
			facts: StapleFacts{HasResponder: true, Stapled: true, Unverifiable: "the signature does not verify"},
			want:  Weak,
		},
		{
			// Nothing could be checked and it is not the response's fault.
			// cert.chain-incomplete already grades the omission.
			name:  "stapled with no issuer in the chain",
			facts: StapleFacts{HasResponder: true, Stapled: true, IssuerMissing: true},
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
		{Stapled: true, Validated: true, Status: "good"},
		{HasResponder: true, HasCRL: true, Stapled: true, Validated: true, Status: "good"},
		// Verified, current, and about this certificate: there is nothing
		// left to say against the server.
		{MustStaple: true, HasResponder: true, Stapled: true, Validated: true, Status: "good"},
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

// The note has to distinguish the three things a stapled response can be.
//
// This test used to require the note to say the response was "not read",
// which was the honest sentence while nothing parsed one. It is now false,
// and a test asserting a false sentence is worse than no test: it would have
// kept the old claim in place through the change that made it wrong.
//
// What replaces it is the distinction, which is what a reader actually needs:
// a response that was verified, one that was not, and one that could not be
// because the issuer was missing.
func TestTheStapledNoteSaysWhichOfTheThreeHappened(t *testing.T) {
	verified := strings.ToLower(strings.Join(
		GradeStapling(StapleFacts{Stapled: true, Validated: true, Status: "good"}).Notes, " "))
	unverified := strings.ToLower(strings.Join(
		GradeStapling(StapleFacts{Stapled: true, Unverifiable: "the signature does not verify"}).Notes, " "))
	noIssuer := strings.ToLower(strings.Join(
		GradeStapling(StapleFacts{Stapled: true, IssuerMissing: true}).Notes, " "))

	if verified == unverified || unverified == noIssuer || verified == noIssuer {
		t.Fatal("two of the three stapled cases share a sentence; the difference between them is the point")
	}

	// A verified response must not be described as though nothing was
	// checked, and must still name what remains unchecked.
	if strings.Contains(verified, "established nothing") {
		t.Errorf("a verified response is described as establishing nothing: %s", verified)
	}
	if !strings.Contains(verified, "responder's own revocation") {
		t.Errorf("the verified note does not say what is still not checked: %s", verified)
	}

	// An unverified one must not read as a check.
	if !strings.Contains(unverified, "established nothing") {
		t.Errorf("an unverifiable response is not described as establishing nothing: %s", unverified)
	}
	if !strings.Contains(noIssuer, "issued this one") {
		t.Errorf("the missing-issuer note does not say what was missing: %s", noIssuer)
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
