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
func TestARepeatedNoteIsSaidOnce(t *testing.T) {
	r := &Result{
		TLS:         &tlsprobe.Report{Notes: []string{"a version note"}},
		Certificate: &certinfo.Report{Notes: []string{"covers 5 names", "revocation was not checked"}},
		AlternateCertificates: []*certinfo.Report{{
			Notes: []string{"covers 5 names", "revocation was not checked", "the alternate is CN=x"},
		}},
		Stapling: &policy.StapleFinding{Notes: []string{"a stapling note", "a version note"}},
		Issuance: &policy.Issuance{Notes: []string{"an issuance note"}},
	}

	want := []string{
		"a version note",
		"covers 5 names",
		"revocation was not checked",
		"the alternate is CN=x",
		"a stapling note",
		"an issuance note",
	}
	if got := r.Notes(); !slices.Equal(got, want) {
		t.Errorf("notes are wrong\n got: %q\nwant: %q", got, want)
	}
}

// Anything that differs between two chains reads differently and survives.
// Dropping repeats must not drop a second, different sentence about the same
// subject.
func TestNotesThatDifferAreBothKept(t *testing.T) {
	r := &Result{
		Certificate: &certinfo.Report{Notes: []string{"covers 5 names"}},
		AlternateCertificates: []*certinfo.Report{{
			Notes: []string{"covers 2 names"},
		}},
	}

	want := []string{"covers 5 names", "covers 2 names"}
	if got := r.Notes(); !slices.Equal(got, want) {
		t.Errorf("a differing note was lost\n got: %q\nwant: %q", got, want)
	}
}
