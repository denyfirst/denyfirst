package scan

import (
	"slices"
	"testing"

	"github.com/denyfirst/denyfirst/internal/certinfo"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

// A server presenting a different chain at an older version is described
// twice: certinfo runs over the chain and over each alternate, and both
// produce the notes that belong to a certificate.
//
// Read against cloudflare.com on 2026-09-01, the report said "This
// certificate covers 5 names" and "Revocation was not checked" once for the
// newest handshake and again for the one served at TLS 1.1, with nothing to
// say which was which. The note that names the alternate chain carries its
// subject, its signature algorithm and its fingerprint, so the repeats added
// nothing and cost a reader the assumption that two sentences meant two
// facts.
// obs builds observed notes. The kind is irrelevant to what these two tests
// check — that a repeated sentence is said once and a differing one is kept —
// so one kind is used throughout and the dedup is exercised on the sentence,
// which is what it compares.
func obs(texts ...string) []policy.Note {
	out := make([]policy.Note, 0, len(texts))
	for _, t := range texts {
		out = append(out, policy.Observed(t))
	}
	return out
}

func TestARepeatedNoteIsSaidOnce(t *testing.T) {
	r := &Result{
		TLS:         &tlsprobe.Report{Notes: obs("a version note")},
		Certificate: &certinfo.Report{Notes: obs("covers 5 names", "revocation was not checked")},
		AlternateCertificates: []*certinfo.Report{{
			Notes: obs("covers 5 names", "revocation was not checked", "the alternate is CN=x"),
		}},
		Stapling: &policy.StapleFinding{Notes: obs("a stapling note", "a version note")},
		Issuance: &policy.Issuance{Notes: obs("an issuance note")},
	}

	want := obs(
		"a version note",
		"covers 5 names",
		"revocation was not checked",
		"the alternate is CN=x",
		"a stapling note",
		"an issuance note",
	)
	if got := r.Notes(); !slices.Equal(got, want) {
		t.Errorf("notes are wrong\n got: %q\nwant: %q", got, want)
	}
}

// Anything that differs between two chains reads differently and survives.
// Dropping repeats must not drop a second, different sentence about the same
// subject.
func TestNotesThatDifferAreBothKept(t *testing.T) {
	r := &Result{
		Certificate: &certinfo.Report{Notes: obs("covers 5 names")},
		AlternateCertificates: []*certinfo.Report{{
			Notes: obs("covers 2 names"),
		}},
	}

	want := obs("covers 5 names", "covers 2 names")
	if got := r.Notes(); !slices.Equal(got, want) {
		t.Errorf("a differing note was lost\n got: %q\nwant: %q", got, want)
	}
}
