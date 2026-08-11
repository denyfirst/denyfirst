package certinfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
)

// The scanner connects to a server chosen by whoever asked for the scan, and
// that server decides what to send back. Everything below is what a hostile
// one can inflate.

func hostileCertificate(t *testing.T, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}

	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = big.NewInt(1)
	}
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = refNow.AddDate(0, 0, -10)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = refNow.AddDate(0, 0, 80)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the certificate: %v", err)
	}
	return cert
}

func hasNoteAbout(r *Report, phrase string) bool {
	for _, note := range r.Notes {
		if strings.Contains(strings.ToLower(note), strings.ToLower(phrase)) {
			return true
		}
	}
	return false
}

// A name list of a few hundred entries would make one small request produce a
// response measured in megabytes, paid for by the person who asked for the
// scan rather than by the server that sent it.
func TestManyNamesAreCutAndDeclared(t *testing.T) {
	names := make([]string, 0, 500)
	for i := range 500 {
		names = append(names, "host-"+strconv.Itoa(i)+".hostile.test")
	}

	cert := hostileCertificate(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: "hostile.test"},
		DNSNames: names,
	})

	report, err := Analyse([]*x509.Certificate{cert}, "hostile.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	got := len(report.Chain[0].DNSNames)
	if got > maxListEntries {
		t.Errorf("the report carries %d names, above the limit of %d", got, maxListEntries)
	}
	if !hasNoteAbout(report, "shortened") {
		t.Errorf("names were cut without saying so; notes: %v", report.Notes)
	}
}

// A subject thousands of characters long is legal and useless. Passing it
// through would make the report unreadable.
func TestLongFieldsAreCutAndDeclared(t *testing.T) {
	cert := hostileCertificate(t, &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   strings.Repeat("a", 3000),
			Organization: []string{strings.Repeat("b", 3000)},
		},
		DNSNames: []string{"hostile.test"},
	})

	report, err := Analyse([]*x509.Certificate{cert}, "hostile.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	subject := report.Chain[0].Subject
	if len(subject) > maxFieldLength+8 {
		t.Errorf("the subject is %d characters, above the limit of %d", len(subject), maxFieldLength)
	}
	if !strings.HasSuffix(subject, "…") {
		t.Error("the shortened field carries no marker, so a reader looking at it alone cannot tell it is incomplete")
	}
	if !hasNoteAbout(report, "shortened") {
		t.Errorf("a field was cut without saying so; notes: %v", report.Notes)
	}
}

// A chain of dozens is not a chain; it is a way of making this package do
// work chosen by the server being examined.
func TestLongChainIsCutAndDeclared(t *testing.T) {
	chain := make([]*x509.Certificate, 0, 40)
	for i := range 40 {
		chain = append(chain, hostileCertificate(t, &x509.Certificate{
			Subject:  pkix.Name{CommonName: "link-" + strconv.Itoa(i) + ".hostile.test"},
			DNSNames: []string{"hostile.test"},
		}))
	}

	report, err := Analyse(chain, "hostile.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if got := len(report.Chain); got > maxChainLength {
		t.Errorf("the report describes %d certificates, above the limit of %d", got, maxChainLength)
	}
	if !hasNoteAbout(report, "only the first") {
		t.Errorf("a chain was cut without saying so; notes: %v", report.Notes)
	}
}

// The fingerprint is what somebody pins, so it has to identify the whole
// certificate rather than the shortened description of it.
func TestFingerprintCoversTheWholeCertificate(t *testing.T) {
	long := hostileCertificate(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: strings.Repeat("c", 3000)},
		DNSNames: []string{"hostile.test"},
	})

	report, err := Analyse([]*x509.Certificate{long}, "hostile.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	leaf := report.Chain[0]
	if len(leaf.FingerprintSHA256) != 64 {
		t.Fatalf("fingerprint has %d characters, want 64", len(leaf.FingerprintSHA256))
	}

	// Two certificates that differ only past the point where the description
	// is cut must still be told apart.
	other := hostileCertificate(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: strings.Repeat("c", 2999) + "d"},
		DNSNames: []string{"hostile.test"},
	})
	otherReport, err := Analyse([]*x509.Certificate{other}, "hostile.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if leaf.FingerprintSHA256 == otherReport.Chain[0].FingerprintSHA256 {
		t.Error("two different certificates share a fingerprint")
	}
}

// The grade must describe the certificate that was sent, not the shortened
// description of it. Cutting the report must not cut the analysis.
func TestTruncationDoesNotChangeTheVerdict(t *testing.T) {
	names := make([]string, 0, 400)
	names = append(names, "graded.test")
	for i := range 399 {
		names = append(names, "filler-"+strconv.Itoa(i)+".test")
	}

	cert := hostileCertificate(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "graded.test"},
		DNSNames:    names,
		IPAddresses: []net.IP{net.ParseIP("192.0.2.1")},
	})

	report, err := Analyse([]*x509.Certificate{cert}, "graded.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	// The name is in the certificate, so the name check must pass even though
	// the list shown was cut.
	for _, f := range report.Grade.Findings {
		if f.RuleID == "cert.hostname-mismatch" {
			t.Error("a hostname present in the certificate was reported as missing, so truncation reached the analysis")
		}
		if f.RuleID == "cert.no-san" {
			t.Error("a certificate with names was reported as having none")
		}
	}
}

// A name buried past the limit still has to be honoured. If truncation
// happened before the check rather than after, this is where it would show.
func TestAHiddenNameStillMatches(t *testing.T) {
	names := make([]string, 0, 300)
	for i := range 299 {
		names = append(names, "filler-"+strconv.Itoa(i)+".test")
	}
	names = append(names, "buried.test")

	cert := hostileCertificate(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: "buried.test"},
		DNSNames: names,
	})

	report, err := Analyse([]*x509.Certificate{cert}, "buried.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	for _, f := range report.Grade.Findings {
		if f.RuleID == "cert.hostname-mismatch" {
			t.Error("a name beyond the display limit was treated as absent")
		}
	}
}

// An ordinary certificate must produce no note about cutting, or the notice
// becomes noise that a reader learns to skip.
func TestOrdinaryCertificateIsNotCut(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{dnsNames: []string{"example.test", "www.example.test"}})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if hasNoteAbout(report, "shortened") {
		t.Errorf("an ordinary certificate produced a truncation note: %v", report.Notes)
	}
	if hasNoteAbout(report, "only the first") {
		t.Errorf("an ordinary chain produced a truncation note: %v", report.Notes)
	}
}

// The verification error comes from a library reading attacker-supplied
// input, so it is bounded like everything else.
func TestVerifyErrorIsBounded(t *testing.T) {
	cert := hostileCertificate(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: strings.Repeat("e", 3000)},
		DNSNames: []string{strings.Repeat("f", 3000) + ".test"},
	})

	report, err := Analyse([]*x509.Certificate{cert}, "somewhere.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if len(report.VerifyError) > maxFieldLength+8 {
		t.Errorf("VerifyError is %d characters, above the limit of %d", len(report.VerifyError), maxFieldLength)
	}
}
