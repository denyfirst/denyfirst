package certinfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
)

type intermediateOpts struct {
	commonName string
	sha1       bool
	rsaBits    int // zero means ECDSA P-256
	notBefore  time.Time
	notAfter   time.Time
}

// newIntermediate signs a certificate authority with the root, so that a test
// can build the chain a server actually sends: leaf, issuer, and sometimes the
// root behind it.
func newIntermediate(t *testing.T, root issuer, o intermediateOpts) issuerAny {
	t.Helper()

	if o.commonName == "" {
		o.commonName = "denyfirst test issuing CA"
	}
	if o.notBefore.IsZero() {
		o.notBefore = refNow.AddDate(-1, 0, 0)
	}
	if o.notAfter.IsZero() {
		o.notAfter = refNow.AddDate(5, 0, 0)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: o.commonName},
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	if o.sha1 {
		tmpl.SignatureAlgorithm = x509.ECDSAWithSHA1
	}

	var (
		pub  any
		priv any
	)
	if o.rsaBits > 0 {
		key, err := rsa.GenerateKey(rand.Reader, o.rsaBits)
		if err != nil {
			t.Fatalf("generating a %d-bit intermediate key: %v", o.rsaBits, err)
		}
		pub, priv = &key.PublicKey, key
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating an intermediate key: %v", err)
		}
		pub, priv = &key.PublicKey, key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, pub, root.key)
	if err != nil {
		t.Fatalf("creating the intermediate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the intermediate: %v", err)
	}
	return issuerAny{cert: cert, key: priv}
}

// issuerAny is an intermediate whose key may be of either type, which the
// root helper's issuer cannot hold.
type issuerAny struct {
	cert *x509.Certificate
	key  any
}

// leafUnder signs a leaf with the given intermediate.
func leafUnder(t *testing.T, ca issuerAny, name string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the leaf key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano() + 1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             refNow.AddDate(0, 0, -10),
		NotAfter:              refNow.AddDate(0, 0, 80),
		DNSNames:              []string{name},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("creating the leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the leaf: %v", err)
	}
	return cert
}

func chainRuleIDs(r *Report) []string {
	out := make([]string, 0, 8)
	for _, g := range r.IssuerGrades {
		for _, f := range g.Findings {
			out = append(out, f.RuleID)
		}
	}
	return out
}

// A weak issuer reaches the verdict.
//
// The whole point. Before 2026-09-02 this chain graded strong: the leaf was
// impeccable, the chain reached a root, and the certificate that signed the
// leaf was graded by nothing at all.
func TestAWeakIssuerReachesTheVerdict(t *testing.T) {
	root := newRoot(t)

	for _, c := range []struct {
		name string
		opts intermediateOpts
		rule string
	}{
		{"signed with SHA-1", intermediateOpts{commonName: "sha1 issuing CA", sha1: true}, "chain.signature-sha1"},
		{"a 1024-bit key", intermediateOpts{commonName: "small key issuing CA", rsaBits: 1024}, "chain.rsa-key-too-small"},
		{"expired", intermediateOpts{
			commonName: "expired issuing CA",
			notBefore:  refNow.AddDate(-5, 0, 0),
			notAfter:   refNow.AddDate(0, 0, -1),
		}, "chain.expired"},
	} {
		ca := newIntermediate(t, root, c.opts)
		leaf := leafUnder(t, ca, "example.test")

		report, err := Analyse([]*x509.Certificate{leaf, ca.cert}, "example.test", refNow)
		if err != nil {
			t.Fatalf("%s: Analyse: %v", c.name, err)
		}

		ids := chainRuleIDs(report)
		found := false
		for _, id := range ids {
			if id == c.rule {
				found = true
			}
		}
		if !found {
			t.Errorf("an issuer %s did not raise %s: %v", c.name, c.rule, ids)
			continue
		}
		if report.Verdict != policy.Insecure {
			t.Errorf("an issuer %s left the report %s", c.name, report.Verdict)
		}

		// And the finding says which certificate, using the name as the
		// report renders it.
		named := false
		for _, g := range report.IssuerGrades {
			for _, f := range g.Findings {
				if f.RuleID == c.rule && strings.Contains(f.Rationale, c.opts.commonName) {
					named = true
				}
			}
		}
		if !named {
			t.Errorf("an issuer %s: the finding does not name %q", c.name, c.opts.commonName)
		}
	}
}

// A sound chain stays sound.
func TestASoundChainIsStillStrong(t *testing.T) {
	root := newRoot(t)
	ca := newIntermediate(t, root, intermediateOpts{})
	leaf := leafUnder(t, ca, "example.test")

	report, err := Analyse([]*x509.Certificate{leaf, ca.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if ids := chainRuleIDs(report); len(ids) != 0 {
		t.Errorf("a sound issuer produced findings: %v", ids)
	}
	if len(report.IssuerGrades) != 1 {
		t.Errorf("one issuer was sent and %d were graded", len(report.IssuerGrades))
	}
}

// The root is not graded, and the report says why.
//
// A root is trusted because a client already holds a copy, not because of the
// signature on it. Grading that signature would warn about a risk no client
// runs — and roots older than SHA-256 sit in every store today, doing no
// harm. So the test builds the worst root it can and expects silence.
func TestARootIsNotGradedAndTheReportSaysWhy(t *testing.T) {
	root := newRoot(t)
	ca := newIntermediate(t, root, intermediateOpts{})
	leaf := leafUnder(t, ca, "example.test")

	// The server sends the root as well, which many do.
	report, err := Analyse([]*x509.Certificate{leaf, ca.cert, root.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if len(report.IssuerGrades) != 1 {
		t.Errorf("the chain held one issuer and a root, and %d certificates were graded",
			len(report.IssuerGrades))
	}

	var said bool
	for _, note := range report.Notes {
		if strings.Contains(note.Text, "self-signed and was not graded") {
			said = true
			if note.Kind != policy.KindObserved {
				t.Errorf("the note about the root carries kind %q", note.Kind)
			}
			if !strings.Contains(note.Text, "denyfirst test root") {
				t.Errorf("the note does not name the certificate it is about:\n  %s", note.Text)
			}
		}
	}
	if !said {
		t.Error("a root was sent, was skipped, and the report did not say so — which is the silence " +
			"this whole change exists to end")
	}
}

// And the verdict of a sound leaf follows its issuer.
//
// This is the observation that was impossible until 2026-09-02, and its
// absence had already let a sabotage through: with no root installed, every
// chain a test built failed verification, so every report was insecure from
// cert.chain-untrusted whatever else was true. The fold over the issuers could
// be replaced by the leaf's own verdict and nothing noticed, because the leaf
// was already as bad as a report could be.
//
// With a root the tests trust, an impeccable leaf under an issuer that expires
// in ten days produces exactly the shape that was invisible: the chain
// verifies, the leaf grades strong, and the report grades weak because of a
// certificate the reader would otherwise never have been told about.
//
// The issuer's fault is chosen to be one Go's verifier tolerates. A SHA-1
// issuer would break the chain and put the leaf back at insecure, which is the
// blind spot all over again.
func TestASoundLeafTakesItsIssuersVerdict(t *testing.T) {
	root := newRoot(t)
	ca := newIntermediate(t, root, intermediateOpts{
		commonName: "soon issuing CA",
		notBefore:  refNow.AddDate(-2, 0, 0),
		notAfter:   refNow.AddDate(0, 0, 10),
	})
	leaf := leafUnder(t, ca, "example.test")

	report, err := Analyse([]*x509.Certificate{leaf, ca.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	if !report.Trusted {
		t.Fatalf("the chain did not verify, so this test is back in the blind spot it was written "+
			"to leave: %s", report.VerifyError)
	}
	if report.Grade.Verdict != policy.Strong {
		t.Fatalf("the leaf is not strong on its own (%s), so the report's verdict says nothing about "+
			"the issuer: %v", report.Grade.Verdict, ruleIDs(report))
	}
	if report.Verdict != policy.Weak {
		t.Errorf("a strong leaf under an issuer expiring in ten days produced %s, not weak — the "+
			"issuer's verdict did not reach the report", report.Verdict)
	}
}

// Nothing from an issuer's subject can rewrite the report.
//
// The subject reaches a sentence in policy.GradeIssuer, and it is text the
// scanned server chose. R10 holds because certinfo hands over the value it
// has already sanitised — this checks that it does, rather than trusting that
// it does.
func TestAnIssuerSubjectCannotRewriteTheReport(t *testing.T) {
	root := newRoot(t)
	ca := newIntermediate(t, root, intermediateOpts{
		commonName: "evil\x1b[2K\x1b[1A CA",
		sha1:       true,
	})
	leaf := leafUnder(t, ca, "example.test")

	report, err := Analyse([]*x509.Certificate{leaf, ca.cert}, "example.test", refNow)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	for _, g := range report.IssuerGrades {
		for _, f := range g.Findings {
			if strings.ContainsRune(f.Rationale, 0x1b) {
				t.Errorf("an escape from an issuer's subject reached a finding:\n  %q", f.Rationale)
			}
		}
	}
}

// The verdict is the worst across the whole chain, as a rule.
//
// The fold itself, over every combination that matters. The test below is the
// one that watches it happen on a real chain.
func TestTheVerdictIsTheWorstAcrossTheChain(t *testing.T) {
	weak := policy.IssuerFinding{Verdict: policy.Weak}
	insecure := policy.IssuerFinding{Verdict: policy.Insecure}
	strong := policy.IssuerFinding{Verdict: policy.Strong}

	for _, c := range []struct {
		name    string
		leaf    policy.Verdict
		issuers []policy.IssuerFinding
		want    policy.Verdict
	}{
		{"nothing above the leaf", policy.Strong, nil, policy.Strong},
		{"sound issuers", policy.Strong, []policy.IssuerFinding{strong, strong}, policy.Strong},
		{"a weak issuer under a strong leaf", policy.Strong, []policy.IssuerFinding{weak}, policy.Weak},
		{"an insecure issuer under a strong leaf", policy.Strong, []policy.IssuerFinding{insecure}, policy.Insecure},
		{"an insecure issuer among sound ones", policy.Strong, []policy.IssuerFinding{strong, insecure, strong}, policy.Insecure},
		{"a strong issuer does not rescue a weak leaf", policy.Weak, []policy.IssuerFinding{strong}, policy.Weak},
		{"a weak issuer does not soften an insecure leaf", policy.Insecure, []policy.IssuerFinding{weak}, policy.Insecure},
	} {
		if got := worstAcross(c.leaf, c.issuers); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}
