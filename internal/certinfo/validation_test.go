package certinfo

import (
	"crypto/x509"
	"strings"
	"testing"
)

func policyOID(t *testing.T, arcs ...uint64) x509.OID {
	t.Helper()
	oid, err := x509.OIDFromInts(arcs)
	if err != nil {
		t.Fatalf("building an object identifier from %v: %v", arcs, err)
	}
	return oid
}

// The four levels, named.
//
// This is the one thing about a certificate a reader cannot infer from
// anything else on the page, and browsers stopped distinguishing them: a
// visitor to a bank cannot tell from the address bar whether the certificate
// proves only control of a name or whether an authority checked the company
// exists. The certificate says so, and until now nothing showed it.
func TestTheValidationLevelIsNamed(t *testing.T) {
	for _, c := range []struct {
		name  string
		arcs  []uint64
		level string
	}{
		{"domain validation", []uint64{2, 23, 140, 1, 2, 1}, "domain validated"},
		{"organisation validation", []uint64{2, 23, 140, 1, 2, 2}, "organisation validated"},
		{"individual validation", []uint64{2, 23, 140, 1, 2, 3}, "individual validated"},
		{"extended validation", []uint64{2, 23, 140, 1, 1}, "extended validation"},
	} {
		root := newRoot(t)
		leaf := newLeaf(t, root, leafOpts{policies: []x509.OID{policyOID(t, c.arcs...)}})

		report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "example.test", refNow)
		if err != nil {
			t.Fatalf("%s: Analyse: %v", c.name, err)
		}
		if got := report.Chain[0].Validation; got != c.level {
			t.Errorf("%s: the report says %q, want %q", c.name, got, c.level)
		}
	}
}

// A certificate naming no policy this list knows says nothing.
//
// Empty rather than a guess. A private authority issues under its own
// identifiers, which say nothing this table can read, and an older public
// certificate may predate the requirement. Printing "unknown" would put a
// word where a measurement is missing, and this report does not do that.
func TestACertificateWithNoKnownPolicySaysNothing(t *testing.T) {
	root := newRoot(t)

	for _, c := range []struct {
		name     string
		policies []x509.OID
	}{
		{"no policies at all", nil},
		{"a private authority's own identifier", []x509.OID{policyOID(t, 1, 3, 6, 1, 4, 1, 99999, 2, 1)}},
	} {
		leaf := newLeaf(t, root, leafOpts{policies: c.policies})

		report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "example.test", refNow)
		if err != nil {
			t.Fatalf("%s: Analyse: %v", c.name, err)
		}
		if got := report.Chain[0].Validation; got != "" {
			t.Errorf("%s: the report says %q, and nothing was established", c.name, got)
		}
	}
}

// A certificate carrying more than one is described by the strongest.
//
// That is the claim its issuer is standing behind. Certificates carrying a
// CA/Browser Forum identifier alongside the authority's own are ordinary; two
// Forum identifiers on one certificate are not, and picking the weaker would
// understate what was vetted.
func TestTheStrongestPolicyIsTheOneNamed(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{policies: []x509.OID{
		policyOID(t, 2, 23, 140, 1, 2, 1), // domain
		policyOID(t, 2, 23, 140, 1, 1),    // extended
	}})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if got := report.Chain[0].Validation; got != "extended validation" {
		t.Errorf("a certificate naming both domain and extended validation is described as %q", got)
	}
}

// And it is never a finding.
//
// Which level to buy is the operator's decision, and a cheaper one is not a
// fault: a domain-validated certificate protects the connection exactly as
// well as an extended-validation one. Grading it would be this project
// selling certificates.
func TestTheValidationLevelIsNotGraded(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{policies: []x509.OID{policyOID(t, 2, 23, 140, 1, 2, 1)}})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	for _, f := range report.Grade.Findings {
		if strings.Contains(strings.ToLower(f.Rationale), "validat") &&
			strings.Contains(strings.ToLower(f.Title), "validat") {
			t.Errorf("a finding grades the validation level: %s — %s", f.RuleID, f.Title)
		}
	}
	if report.Chain[0].Validation == "" {
		t.Fatal("the level was not read, so this test proves nothing about grading it")
	}
}
