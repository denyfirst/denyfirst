package certinfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
)

// Certificates are generated in memory rather than checked in as fixtures.
// A fixture expires, and a test that starts failing on a calendar date
// teaches maintainers to ignore it.

var refNow = time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)

type issuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newRoot(t *testing.T) issuer {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating root key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "denyfirst test root"},
		NotBefore:             refNow.AddDate(-1, 0, 0),
		NotAfter:              refNow.AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating root: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing root: %v", err)
	}
	return issuer{cert: cert, key: key}
}

type leafOpts struct {
	notBefore time.Time
	notAfter  time.Time
	dnsNames  []string
	ips       []net.IP
	rsaBits   int // zero means ECDSA P-256
	selfSign  bool

	// unknownEKU carries extended key usages Go has no constant for, which
	// is where a certificate's unnamed capabilities end up.
	unknownEKU []asn1.ObjectIdentifier
}

func newLeaf(t *testing.T, root issuer, o leafOpts) *x509.Certificate {
	t.Helper()

	if o.notBefore.IsZero() {
		o.notBefore = refNow.AddDate(0, 0, -10)
	}
	if o.notAfter.IsZero() {
		o.notAfter = refNow.AddDate(0, 0, 80)
	}
	if o.dnsNames == nil && o.ips == nil {
		o.dnsNames = []string{"example.test"}
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "example.test"},
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		DNSNames:              o.dnsNames,
		IPAddresses:           o.ips,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		UnknownExtKeyUsage:    o.unknownEKU,
		BasicConstraintsValid: true,
	}

	var (
		pub    any
		signer any
		parent = root.cert
	)

	if o.rsaBits > 0 {
		key, err := rsa.GenerateKey(rand.Reader, o.rsaBits)
		if err != nil {
			t.Fatalf("generating %d-bit RSA key: %v", o.rsaBits, err)
		}
		pub = &key.PublicKey
		signer = root.key
		if o.selfSign {
			signer = key
			parent = tmpl
		}
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating leaf key: %v", err)
		}
		pub = &key.PublicKey
		signer = root.key
		if o.selfSign {
			signer = key
			parent = tmpl
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("creating leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing leaf: %v", err)
	}
	return cert
}

func ruleIDs(r *Report) []string {
	out := make([]string, 0, len(r.Grade.Findings))
	for _, f := range r.Grade.Findings {
		out = append(out, f.RuleID)
	}
	return out
}

func TestAnalyseRejectsEmptyChain(t *testing.T) {
	if _, err := Analyse(nil, "example.test", refNow); err == nil {
		t.Error("Analyse accepted an empty chain")
	}
}

func TestDescribesTheLeaf(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{
		dnsNames: []string{"example.test", "www.example.test"},
		ips:      []net.IP{net.ParseIP("192.0.2.1")},
	})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if len(report.Chain) != 2 {
		t.Fatalf("Chain has %d entries, want 2", len(report.Chain))
	}

	got := report.Chain[0]
	if !strings.Contains(got.Subject, "example.test") {
		t.Errorf("Subject = %q, want it to name example.test", got.Subject)
	}
	if !slices.Contains(got.DNSNames, "www.example.test") {
		t.Errorf("DNSNames = %v, want it to include www.example.test", got.DNSNames)
	}
	if !slices.Contains(got.IPAddresses, "192.0.2.1") {
		t.Errorf("IPAddresses = %v, want it to include 192.0.2.1", got.IPAddresses)
	}
	if got.KeyAlgorithm != "ECDSA" || got.KeyBits != 256 {
		t.Errorf("key = %s/%d, want ECDSA/256", got.KeyAlgorithm, got.KeyBits)
	}
	if len(got.FingerprintSHA256) != 64 {
		t.Errorf("FingerprintSHA256 has %d characters, want 64", len(got.FingerprintSHA256))
	}
	if !slices.Contains(got.ExtKeyUsage, "serverAuth") {
		t.Errorf("ExtKeyUsage = %v, want it to include serverAuth", got.ExtKeyUsage)
	}
	// Against the constant rather than a literal. A hardcoded "denyfirst-v1"
	// here is a second copy of the version, and the rule set changed under it
	// on 2026-08-22 while this test went on asserting the old number.
	if report.Policy != policy.Version {
		t.Errorf("Policy = %q, want %q", report.Policy, policy.Version)
	}
}

// A certificate signed by a root the system does not know is untrusted, which
// is the correct result: the test root is deliberately not installed.
func TestUnknownRootIsUntrusted(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if report.Trusted {
		t.Error("a chain rooted in an uninstalled CA was reported as trusted")
	}
	if report.VerifyError == "" {
		t.Error("VerifyError is empty; the reason for the failure must be reported")
	}
	if !slices.Contains(ruleIDs(report), "cert.chain-untrusted") {
		t.Errorf("cert.chain-untrusted not raised; got %v", ruleIDs(report))
	}
}

// The issuer was sent, so the chain is not incomplete. Reporting both an
// untrusted root and a missing issuer would describe one fault twice.
func TestPresentIssuerIsNotAnIncompleteChain(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if slices.Contains(ruleIDs(report), "cert.chain-incomplete") {
		t.Errorf("cert.chain-incomplete raised although the issuer was sent; got %v", ruleIDs(report))
	}
}

// A leaf sent on its own, with an issuer neither included nor trusted, is the
// case the incompleteness rule exists for.
func TestMissingIssuerIsAnIncompleteChain(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{})

	report, err := Analyse([]*x509.Certificate{leaf}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if !slices.Contains(ruleIDs(report), "cert.chain-incomplete") {
		t.Errorf("cert.chain-incomplete not raised; got %v", ruleIDs(report))
	}
	if len(report.Notes) == 0 {
		t.Error("sending only a leaf produced no note explaining the consequence")
	}
}

func TestSelfSignedIsDetected(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{selfSign: true})

	report, err := Analyse([]*x509.Certificate{leaf}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if !report.Chain[0].SelfSigned {
		t.Error("SelfSigned = false for a self-signed certificate")
	}
	ids := ruleIDs(report)
	if !slices.Contains(ids, "cert.self-signed") {
		t.Errorf("cert.self-signed not raised; got %v", ids)
	}
	if slices.Contains(ids, "cert.chain-incomplete") {
		t.Errorf("cert.chain-incomplete raised for a self-signed certificate; got %v", ids)
	}
}

func TestHostnameMismatch(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{dnsNames: []string{"example.test"}})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "other.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if !slices.Contains(ruleIDs(report), "cert.hostname-mismatch") {
		t.Errorf("cert.hostname-mismatch not raised; got %v", ruleIDs(report))
	}
}

// Without a hostname there is no name check. Saying nothing would let a
// reader assume the name was checked and matched.
func TestNoHostnameIsNoted(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if slices.Contains(ruleIDs(report), "cert.hostname-mismatch") {
		t.Error("a name mismatch was reported although no name was supplied")
	}

	var noted bool
	for _, n := range report.Notes {
		if strings.Contains(strings.ToLower(n.Text), "hostname") {
			noted = true
		}
	}
	if !noted {
		t.Errorf("the missing name check was not noted; notes: %v", report.Notes)
	}
}

func TestExpiredCertificate(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{
		notBefore: refNow.AddDate(0, 0, -100),
		notAfter:  refNow.AddDate(0, 0, -5),
	})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if !slices.Contains(ruleIDs(report), "cert.expired") {
		t.Errorf("cert.expired not raised; got %v", ruleIDs(report))
	}
	if report.Grade.DaysRemaining >= 0 {
		t.Errorf("DaysRemaining = %d, want it negative", report.Grade.DaysRemaining)
	}
}

func TestSmallRSAKey(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{rsaBits: 1024})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if got := report.Chain[0]; got.KeyAlgorithm != "RSA" || got.KeyBits != 1024 {
		t.Errorf("key = %s/%d, want RSA/1024", got.KeyAlgorithm, got.KeyBits)
	}
	if !slices.Contains(ruleIDs(report), "cert.rsa-key-too-small") {
		t.Errorf("cert.rsa-key-too-small not raised; got %v", ruleIDs(report))
	}
}

// A certificate without a subject alternative name asserts identity only
// through the Common Name, which browsers stopped honouring in 2017.
func TestNoSubjectAlternativeName(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{dnsNames: []string{}, ips: []net.IP{}})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if !slices.Contains(ruleIDs(report), "cert.no-san") {
		t.Errorf("cert.no-san not raised; got %v", ruleIDs(report))
	}
}

func TestSummaryIsReadable(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	got := report.Summary()
	if !strings.Contains(got, "example.test") {
		t.Errorf("Summary() = %q, want it to name the subject", got)
	}
	if !strings.Contains(got, "days remaining") {
		t.Errorf("Summary() = %q, want it to state the remaining lifetime", got)
	}
}

// Paste this at the very end of internal/certinfo/certinfo_test.go,
// after the final closing brace of the last function.
//
// The imports it needs — crypto/x509, strings, testing — are already there.

// This package says nothing about revocation, because it cannot know.
//
// It used to. Every report carried "Revocation was not checked", written when
// nothing here parsed a stapled response — and this test asserted the word was
// present, which is why the sentence survived v0.3.0 teaching this project to
// read a response and verify it against the issuer. From then on a stapling
// server got both claims in one report: revocation not checked, directly above
// the stapled response read and verified. Around a third of hosts staple.
//
// This is the third time in this repository that a test held a stale sentence
// in place by nailing its words. The rule those produced is the one applied
// here: assert the property, and assert it in the package that can establish
// it. Whether a response verified is settled in policy.GradeStapling, which
// has every branch; this package knows only that a certificate exists.
//
// R3 is not weakened by the move. The claim is still made on every report —
// see TestNoAuthorityIsAskedOnAnyStapleOutcome in internal/policy — and it is
// now made where it can be made conditionally.
func TestThisPackageClaimsNothingAboutRevocation(t *testing.T) {
	root := newRoot(t)
	leaf := newLeaf(t, root, leafOpts{})

	report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	for _, note := range report.Notes {
		if strings.Contains(strings.ToLower(note.Text), "revocation") ||
			strings.Contains(strings.ToLower(note.Text), "revoked") {
			t.Errorf("this package cannot know whether revocation was established, and claims it anyway:\n  %s",
				note.Text)
		}
	}
}
