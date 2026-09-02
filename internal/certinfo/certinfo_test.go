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

// newRoot returns the root these tests trust.
//
// One root for the package, installed by TestMain through SSL_CERT_FILE, so a
// chain built here verifies the way a real one does. It used to generate a
// fresh authority per call and nothing verified at all; see main_test.go for
// what that was hiding. A test that wants a chain which does not verify calls
// newUntrustedRoot instead, and says so by calling it.
func newRoot(t *testing.T) issuer {
	t.Helper()
	if sharedRoot.cert == nil {
		t.Fatal("the shared root is missing, so TestMain did not run")
	}
	return sharedRoot
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

	// isCA and keyUsage describe what the certificate says it may be and
	// what it says its key may do. Zero means the ordinary case: not an
	// authority, permitted to sign.
	isCA     bool
	keyUsage x509.KeyUsage

	// subject replaces the default common name, for the cases where what is
	// under test is the name itself.
	subject *pkix.Name

	// policies are the certificate policy identifiers to carry, for the cases
	// about what an issuer says it checked.
	policies []x509.OID
}

// constraintOpts are the limits an intermediate carries, for the cases about
// what an authority is not allowed to do.
type constraintOpts struct {
	permittedDNS []string
	excludedDNS  []string
	permittedIP  []string

	// pathLen is stated when statePathLen is set, so that zero — which is the
	// interesting value — can be told from absent.
	pathLen      int
	statePathLen bool
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

	subject := pkix.Name{CommonName: "example.test"}
	if o.subject != nil {
		subject = *o.subject
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               subject,
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		DNSNames:              o.dnsNames,
		IPAddresses:           o.ips,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		UnknownExtKeyUsage:    o.unknownEKU,
		BasicConstraintsValid: true,
		IsCA:                  o.isCA,
		Policies:              o.policies,
	}
	if o.keyUsage != 0 {
		tmpl.KeyUsage = o.keyUsage
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

// A certificate signed by a root the system does not know is untrusted.
//
// This used to be true of every chain in this package by accident. It is now
// asked for: newUntrustedRoot builds an authority that is in no store, while
// newRoot returns the one TestMain installed. An assertion about untrusted
// chains should have to say which root it means.
func TestUnknownRootIsUntrusted(t *testing.T) {
	root := newUntrustedRoot(t)
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

// Two measurements a caller needs and "trusted" does not carry.
//
// Trusted here means the chain reaches a root, and for an expired certificate
// it is re-asked at a moment the certificate was valid — deliberately, since
// Go checks dates before it looks for an issuer. The consequence is that a
// certificate which expired eleven years ago, and one issued to a different
// name, are both reported as trusted.
//
// Measured on 2026-09-01 against badssl.com: expired.badssl.com, valid for
// three days in 2015, and wrong.host.badssl.com, whose certificate covers
// *.badssl.com. Both produced "the chain is complete and reaches a root in
// this machine's trust store" under a heading called What holds, above a
// verdict of insecure. The sentences were true. What they were read as was
// not, and the two fields below are what a caller needs to tell them apart.
func TestTheReportSaysWhetherTheNameAndTheDatesHold(t *testing.T) {
	root := newRoot(t)

	cases := []struct {
		name     string
		leaf     leafOpts
		hostname string
		inDate   bool
		matches  bool
	}{
		{
			name:     "in date and for this name",
			leaf:     leafOpts{},
			hostname: "example.test",
			inDate:   true,
			matches:  true,
		},
		{
			name: "expired",
			leaf: leafOpts{
				notBefore: refNow.Add(-400 * 24 * time.Hour),
				notAfter:  refNow.Add(-40 * 24 * time.Hour),
			},
			hostname: "example.test",
			inDate:   false,
			matches:  true,
		},
		{
			name: "not yet valid",
			leaf: leafOpts{
				notBefore: refNow.Add(10 * 24 * time.Hour),
				notAfter:  refNow.Add(100 * 24 * time.Hour),
			},
			hostname: "example.test",
			inDate:   false,
			matches:  true,
		},
		{
			name:     "for another name",
			leaf:     leafOpts{dnsNames: []string{"elsewhere.test"}},
			hostname: "example.test",
			inDate:   true,
			matches:  false,
		},
	}

	for _, c := range cases {
		leaf := newLeaf(t, root, c.leaf)

		report, err := Analyse([]*x509.Certificate{leaf, root.cert}, c.hostname, refNow)
		if err != nil {
			t.Fatalf("%s: Analyse: %v", c.name, err)
		}

		if report.InDate != c.inDate {
			t.Errorf("%s: InDate=%v, want %v", c.name, report.InDate, c.inDate)
		}
		if report.HostnameMatches != c.matches {
			t.Errorf("%s: HostnameMatches=%v, want %v", c.name, report.HostnameMatches, c.matches)
		}
	}
}

// The facts about what a certificate may be reach the report.
//
// Between the certificate and the rule sit two steps that can each fail
// silently: reading the extension here, and carrying it into LeafFacts. A
// test over the rule alone passes with either of them broken, which is how a
// grading change ships doing nothing.
//
// This is the same shape as the ROCA test: build a certificate that should be
// accused, run the whole of Analyse, and read the findings that come out.
func TestWhatACertificateMayBeReachesTheReport(t *testing.T) {
	root := newRoot(t)

	cases := []struct {
		name string
		leaf leafOpts
		rule string
	}{
		{
			name: "a leaf that may issue other certificates",
			leaf: leafOpts{isCA: true},
			rule: "cert.leaf-is-ca",
		},
		{
			name: "a key usage that permits signing certificates",
			leaf: leafOpts{keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign},
			rule: "cert.key-usage-cert-sign",
		},
		{
			name: "a key usage that does not permit signing",
			leaf: leafOpts{keyUsage: x509.KeyUsageKeyEncipherment},
			rule: "cert.no-digital-signature",
		},
	}

	for _, c := range cases {
		leaf := newLeaf(t, root, c.leaf)

		report, err := Analyse([]*x509.Certificate{leaf, root.cert}, "example.test", refNow)
		if err != nil {
			t.Fatalf("%s: Analyse: %v", c.name, err)
		}

		var found bool
		for _, finding := range report.Grade.Findings {
			if finding.RuleID == c.rule {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: %s did not reach the report", c.name, c.rule)
		}
	}

	// And the ordinary certificate every other test in this file uses is
	// accused of none of them, or the wiring is reading the wrong bit.
	report, err := Analyse([]*x509.Certificate{newLeaf(t, root, leafOpts{}), root.cert},
		"example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	for _, finding := range report.Grade.Findings {
		switch finding.RuleID {
		case "cert.leaf-is-ca", "cert.key-usage-cert-sign", "cert.no-digital-signature":
			t.Errorf("an ordinary certificate is accused by %s", finding.RuleID)
		}
	}
}
