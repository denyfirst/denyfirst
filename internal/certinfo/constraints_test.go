package certinfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
)

func constraintNotes(r *Report) []string {
	var out []string
	for _, n := range r.Notes {
		if strings.Contains(n.Text, "A constrained authority bounds what a stolen key could do") {
			out = append(out, n.Text)
		}
	}
	return out
}

func analyseWithIssuer(t *testing.T, o intermediateOpts) *Report {
	t.Helper()
	root := newRoot(t)
	ca := newIntermediate(t, root, o)
	leaf := leafUnder(t, ca, "example.test")

	report, err := Analyse([]*x509.Certificate{leaf, ca.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	return report
}

// What an authority is not allowed to do, where it says.
//
// The point is what it means if the key is stolen. An unconstrained
// intermediate that is compromised issues certificates for any name on the
// internet; one constrained to a handful of domains issues for those and
// nothing else, which is the difference between an incident and a
// catastrophe. Nothing on the report said which kind a chain carried.
func TestAConstrainedIssuerIsDescribed(t *testing.T) {
	for _, c := range []struct {
		name  string
		opts  constraintOpts
		wants []string
	}{
		{
			"permitted names",
			constraintOpts{permittedDNS: []string{"example.test", "example.invalid"}},
			[]string{"may issue only for names under example.test and example.invalid"},
		},
		{
			"excluded names",
			constraintOpts{excludedDNS: []string{"gov.test"}},
			[]string{"may not issue for names under gov.test"},
		},
		{
			"no further authorities",
			constraintOpts{statePathLen: true, pathLen: 0},
			[]string{"may not create further authorities"},
		},
		{
			"one further authority",
			constraintOpts{statePathLen: true, pathLen: 1},
			[]string{"may create at most 1 further authority beneath it"},
		},
		{
			"two further authorities",
			constraintOpts{statePathLen: true, pathLen: 2},
			[]string{"may create at most 2 further authorities beneath it"},
		},
		{
			"names and depth together",
			constraintOpts{permittedDNS: []string{"example.test"}, statePathLen: true, pathLen: 0},
			[]string{
				"may issue only for names under example.test",
				"and may not create further authorities",
			},
		},
		{
			"a kind this report does not list",
			constraintOpts{permittedDNS: []string{"example.test"}, permittedIP: []string{"192.0.2.0/24"}},
			[]string{"constraints on other kinds of name, which this report does not list"},
		},
	} {
		report := analyseWithIssuer(t, intermediateOpts{
			commonName:  "constrained issuing CA",
			constraints: c.opts,
		})

		notes := constraintNotes(report)
		if len(notes) != 1 {
			t.Errorf("%s: %d notes about constraints, want 1", c.name, len(notes))
			continue
		}
		for _, want := range c.wants {
			if !strings.Contains(notes[0], want) {
				t.Errorf("%s: the note does not say %q:\n  %s", c.name, want, notes[0])
			}
		}
		if !strings.Contains(notes[0], "constrained issuing CA") {
			t.Errorf("%s: the note does not name the certificate it is about:\n  %s", c.name, notes[0])
		}
	}
}

// An ordinary issuer produces no sentence, and that is a decision.
//
// It is the state of nearly every certificate on the internet. A sentence
// saying so would appear on almost every report, be true, add nothing, and
// teach a reader to skip the block it sits in — which is precisely how the old
// "What this did not measure" heading stopped being read.
//
// The silences this project has spent its time closing were different in kind:
// one hop, one address, one root store each changed what a claim covered. This
// one changes nothing a reader could misread.
func TestAnUnconstrainedIssuerSaysNothing(t *testing.T) {
	report := analyseWithIssuer(t, intermediateOpts{commonName: "ordinary issuing CA"})

	if notes := constraintNotes(report); len(notes) != 0 {
		t.Errorf("an ordinary issuer produced %d sentences about constraints it does not have:\n  %s",
			len(notes), strings.Join(notes, "\n  "))
	}
}

// A root's constraints are not reported.
//
// For the same reason its signature is not graded: the root a client uses is
// the copy in its own store, not the one the server sent, and the two need not
// carry the same extensions. Reading constraints off the server's copy and
// reporting them as binding would describe a limit no client is necessarily
// applying.
func TestARootsConstraintsAreNotReported(t *testing.T) {
	root := newRoot(t)
	ca := newIntermediate(t, root, intermediateOpts{commonName: "ordinary issuing CA"})
	leaf := leafUnder(t, ca, "example.test")

	// Self-signed, which is what makes it a root and what makes it skipped.
	// An earlier version of this test built it with newIntermediate, so it
	// was signed by the real root, was not self-signed, and was correctly
	// treated as an issuer — the test was wrong and the code was right.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "a root that says it is constrained"},
		NotBefore:             refNow.AddDate(-1, 0, 0),
		NotAfter:              refNow.AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		PermittedDNSDomains:   []string{"nowhere.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the root: %v", err)
	}
	constrainedRoot, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the root: %v", err)
	}
	if !isSelfSigned(constrainedRoot) {
		t.Fatal("the certificate this test built is not self-signed, so it exercises nothing")
	}

	report, err := Analyse([]*x509.Certificate{leaf, ca.cert, constrainedRoot}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	for _, note := range constraintNotes(report) {
		if strings.Contains(note, "nowhere.test") {
			t.Errorf("a constraint was read off a self-signed certificate in the chain:\n  %s", note)
		}
	}
}

// Nothing in a constraint can rewrite the report.
//
// The permitted names are text the scanned server chose and they reach a
// sentence, so they go through the same sanitiser as everything else. R10.
//
// Built as a struct rather than signed and parsed, and the reason is worth
// recording: Go refuses to encode a dnsName constraint carrying an escape, so
// a certificate like this cannot be made with CreateCertificate at all. That
// is one more layer between a hostile certificate and this report, and it is
// not the layer under test. What is under test is this package's own guard,
// which has to hold whether or not the ones above it do.
func TestAConstraintCannotRewriteTheReport(t *testing.T) {
	var trim trimmer
	got := issuerConstraints(&x509.Certificate{
		PermittedDNSDomains: []string{"a\x1b[2K.test"},
		ExcludedDNSDomains:  []string{"b\u202egnv.test"},
	}, "CN=evil issuing CA", &trim)

	if got == "" {
		t.Fatal("a constrained issuer produced no sentence, so nothing was sanitised or not")
	}
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("an escape from a name constraint reached the sentence:\n  %q", got)
	}
	if strings.ContainsRune(got, 0x202e) {
		t.Errorf("a bidirectional override from a name constraint reached the sentence:\n  %q", got)
	}
}
