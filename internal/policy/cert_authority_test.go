package policy

import (
	"strings"
	"testing"
)

// What a certificate says it may be, and what it says its key may do.
//
// All three extensions below were read, displayed in the report and graded by
// nothing: a reader saw "CA: true" beside a leaf certificate with no finding
// next to it, and the key usage line was decoration.
func TestACertificateThatMayIssueOtherCertificates(t *testing.T) {
	cases := []struct {
		name    string
		change  func(*LeafFacts)
		accused bool
	}{
		{"an ordinary subscriber certificate", func(f *LeafFacts) {}, false},

		{"basic constraints say cA:TRUE", func(f *LeafFacts) {
			f.IsCA = true
		}, true},

		// Absent is not false. With no basic constraints extension the
		// question was not answered, and reading "not a CA" out of silence is
		// drawing a measurement that did not happen.
		{"no basic constraints extension at all", func(f *LeafFacts) {
			f.BasicConstraintsValid = false
			f.IsCA = true
		}, false},
	}

	for _, c := range cases {
		facts := ordinaryLeaf()
		c.change(&facts)
		if got := fires(facts, "cert.leaf-is-ca"); got != c.accused {
			t.Errorf("%s: accused=%v, want %v", c.name, got, c.accused)
		}
	}
}

// The same power arriving by the other extension.
//
// RFC 5280 permits keyCertSign only where basic constraints say cA:TRUE, so a
// certificate carrying one without the other is claiming a power its own
// constraints deny it — and clients disagree about which half to believe.
func TestAKeyUsageThatPermitsSigningCertificates(t *testing.T) {
	cases := []struct {
		name    string
		change  func(*LeafFacts)
		accused bool
	}{
		{"an ordinary subscriber certificate", func(f *LeafFacts) {}, false},

		{"keyCertSign without cA:TRUE", func(f *LeafFacts) {
			f.KeyCertSign = true
		}, true},

		// Graded by cert.leaf-is-ca instead. Charging one mistake twice
		// reports it as two.
		{"keyCertSign with cA:TRUE", func(f *LeafFacts) {
			f.KeyCertSign = true
			f.IsCA = true
		}, false},

		{"no key usage extension at all", func(f *LeafFacts) {
			f.HasKeyUsage = false
			f.KeyCertSign = true
		}, false},
	}

	for _, c := range cases {
		facts := ordinaryLeaf()
		c.change(&facts)
		if got := fires(facts, "cert.key-usage-cert-sign"); got != c.accused {
			t.Errorf("%s: accused=%v, want %v", c.name, got, c.accused)
		}
	}
}

// A key usage that does not permit what TLS needs.
//
// Every TLS 1.3 handshake and every ECDHE handshake at TLS 1.2 has the server
// sign with this key. Absent is not excluding: with no extension the key may
// be used for anything, which older certificates commonly rely on.
func TestAKeyUsageWithoutDigitalSignature(t *testing.T) {
	cases := []struct {
		name    string
		change  func(*LeafFacts)
		accused bool
	}{
		{"lists digitalSignature", func(f *LeafFacts) {}, false},
		{"lists other things only", func(f *LeafFacts) { f.DigitalSignature = false }, true},
		{"lists nothing at all", func(f *LeafFacts) {
			f.HasKeyUsage = false
			f.DigitalSignature = false
		}, false},
	}

	for _, c := range cases {
		facts := ordinaryLeaf()
		c.change(&facts)
		if got := fires(facts, "cert.no-digital-signature"); got != c.accused {
			t.Errorf("%s: accused=%v, want %v", c.name, got, c.accused)
		}
	}
}

// A critical extension nobody here understands.
//
// RFC 5280 requires a client meeting one to reject the certificate, and Go's
// verifier does — so such a certificate already produced cert.chain-untrusted
// with no reason attached. Naming the reason is the difference between an
// operator who can fix it and one who cannot.
func TestACriticalExtensionThisCheckerDoesNotRecognise(t *testing.T) {
	facts := ordinaryLeaf()
	if fires(facts, "cert.critical-extension-unrecognised") {
		t.Error("an ordinary certificate is accused of carrying an unknown critical extension")
	}

	facts.UnhandledCriticalExtensions = []string{"1.3.6.1.4.1.99999.1"}
	if !fires(facts, "cert.critical-extension-unrecognised") {
		t.Fatal("a certificate with an unrecognised critical extension raises nothing")
	}

	var rationale string
	for _, finding := range GradeLeaf(facts, certNow).Findings {
		if finding.RuleID == "cert.critical-extension-unrecognised" {
			rationale = finding.Rationale
		}
	}
	if !strings.Contains(rationale, "1.3.6.1.4.1.99999.1") {
		t.Errorf("the finding does not name the extension:\n  %s", rationale)
	}

	// It says what it does not know, rather than what it concludes. Whether
	// the clients an operator cares about recognise the extension is not
	// something this scan can see.
	if !strings.Contains(rationale, "this one does not") {
		t.Errorf("the finding claims more than it measured:\n  %s", rationale)
	}
}

// The list is chosen by the server being examined, like every other list.
func TestAnUnknownExtensionListCannotBeMadeHuge(t *testing.T) {
	var many []string
	for i := 0; i < 5000; i++ {
		many = append(many, "1.3.6.1.4.1."+strings.Repeat("9", 200))
	}

	facts := ordinaryLeaf()
	facts.UnhandledCriticalExtensions = many

	const ceiling = 2048
	for _, finding := range GradeLeaf(facts, certNow).Findings {
		if len(finding.Rationale) > ceiling {
			t.Errorf("%s is %d bytes, which a server chose. The bound is %d.",
				finding.RuleID, len(finding.Rationale), ceiling)
		}
	}
}
