package policy

import (
	"strings"
	"testing"
	"time"
)

var chainNow = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

func soundIssuer() IssuerFacts {
	return IssuerFacts{
		Subject:            "CN=Example Issuing CA,O=Example,C=GB",
		NotBefore:          chainNow.AddDate(-2, 0, 0),
		NotAfter:           chainNow.AddDate(8, 0, 0),
		SignatureAlgorithm: "SHA256-RSA",
		KeyAlgorithm:       "RSA",
		KeyBits:            4096,
	}
}

func issuerRuleIDs(f IssuerFinding) []string {
	out := make([]string, 0, len(f.Findings))
	for _, finding := range f.Findings {
		out = append(out, finding.RuleID)
	}
	return out
}

func has(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// An ordinary issuer is graded and passes.
//
// The point of saying so: a grader that fires on everything is as useless as
// one that fires on nothing, and every chain served today carries an issuer
// that ought to produce silence.
func TestASoundIssuerRaisesNothing(t *testing.T) {
	got := GradeIssuer(soundIssuer(), chainNow)
	if got.Verdict != Strong {
		t.Errorf("a sound issuer graded %s: %v", got.Verdict, issuerRuleIDs(got))
	}
	if len(got.Findings) != 0 {
		t.Errorf("a sound issuer produced findings: %v", issuerRuleIDs(got))
	}
}

// What an issuer is graded on.
func TestWhatAnIssuerIsGradedOn(t *testing.T) {
	for _, c := range []struct {
		name    string
		change  func(*IssuerFacts)
		rule    string
		verdict Verdict
	}{
		{"a SHA-1 signature", func(f *IssuerFacts) { f.SignatureAlgorithm = "SHA1-RSA" }, "chain.signature-sha1", Insecure},
		{"an MD5 signature", func(f *IssuerFacts) { f.SignatureAlgorithm = "MD5-RSA" }, "chain.signature-md5", Insecure},
		{"a signature nobody named", func(f *IssuerFacts) { f.SignatureAlgorithm = "0" }, "chain.signature-algorithm-unrecognised", Weak},
		{"a 1024-bit RSA key", func(f *IssuerFacts) { f.KeyBits = 1024 }, "chain.rsa-key-too-small", Insecure},
		{"a factorable RSA key", func(f *IssuerFacts) { f.KeyFromBrokenGenerator = true }, "chain.roca", Insecure},
		{"a curve below P-256", func(f *IssuerFacts) { f.KeyAlgorithm, f.KeyBits = "ECDSA", 224 }, "chain.ec-key-too-small", Insecure},
		{"a key type nobody named", func(f *IssuerFacts) { f.KeyAlgorithm, f.KeyBits = "DSA", 2048 }, "chain.key-algorithm-unrecognised", Weak},
		{"an expired issuer", func(f *IssuerFacts) { f.NotAfter = chainNow.AddDate(0, 0, -1) }, "chain.expired", Insecure},
		{"an issuer not yet valid", func(f *IssuerFacts) { f.NotBefore = chainNow.AddDate(0, 0, 1) }, "chain.not-yet-valid", Insecure},
		{"an issuer expiring soon", func(f *IssuerFacts) { f.NotAfter = chainNow.AddDate(0, 0, 10) }, "chain.expiring-soon", Weak},
		{"a critical extension nobody here knows", func(f *IssuerFacts) {
			f.UnhandledCriticalExtensions = []string{"1.3.6.1.4.1.99999.1"}
		}, "chain.critical-extension-unrecognised", Weak},
	} {
		facts := soundIssuer()
		c.change(&facts)
		got := GradeIssuer(facts, chainNow)

		if !has(issuerRuleIDs(got), c.rule) {
			t.Errorf("%s did not raise %s: %v", c.name, c.rule, issuerRuleIDs(got))
			continue
		}
		if got.Verdict != c.verdict {
			t.Errorf("%s graded %s, want %s", c.name, got.Verdict, c.verdict)
		}

		// The certificate a finding is about has to be named, or a reader
		// with three issuers cannot tell which one it means.
		for _, finding := range got.Findings {
			if finding.RuleID != c.rule {
				continue
			}
			if !strings.Contains(finding.Rationale, "Example Issuing CA") {
				t.Errorf("%s: the finding does not name the certificate it is about:\n  %s",
					c.name, finding.Rationale)
			}
			if len(finding.References) == 0 {
				t.Errorf("%s: %s cites nothing, and R2 requires every verdict to cite a document",
					c.name, c.rule)
			}
		}
	}
}

// The two graders agree about the cryptography.
//
// The conditions are written twice — once for the certificate served for the
// host, once for the certificates above it — because the consequence differs
// and the sentences have to say so. What must not differ is *when* they fire.
// A rule tightened on the leaf and left loose on the chain would be a scanner
// that grades the same key two ways depending on where it sits.
func TestBothGradersFireOnTheSameCryptography(t *testing.T) {
	for _, c := range []struct {
		name         string
		algorithm    string
		keyAlgorithm string
		bits         int
		broken       bool
	}{
		{"sha256 rsa4096", "SHA256-RSA", "RSA", 4096, false},
		{"sha1", "SHA1-RSA", "RSA", 4096, false},
		{"md5", "MD5-RSA", "RSA", 4096, false},
		{"md2", "MD2-RSA", "RSA", 4096, false},
		{"unnamed signature", "99", "RSA", 4096, false},
		{"rsa 1024", "SHA256-RSA", "RSA", 1024, false},
		{"rsa 2048", "SHA256-RSA", "RSA", 2048, false},
		{"roca", "SHA256-RSA", "RSA", 2048, true},
		{"ecdsa 224", "ECDSA-SHA256", "ECDSA", 224, false},
		{"ecdsa 256", "ECDSA-SHA256", "ECDSA", 256, false},
		{"ed25519", "Ed25519", "Ed25519", 256, false},
		{"unnamed key", "SHA256-RSA", "DSA", 2048, false},
		{"no key type at all", "SHA256-RSA", "", 0, false},
	} {
		leaf := GradeLeaf(LeafFacts{
			NotBefore:              chainNow.AddDate(0, 0, -10),
			NotAfter:               chainNow.AddDate(0, 0, 60),
			SignatureAlgorithm:     c.algorithm,
			KeyAlgorithm:           c.keyAlgorithm,
			KeyBits:                c.bits,
			KeyFromBrokenGenerator: c.broken,
			ChainTrusted:           true,
			ChainComplete:          true,
			HostnameMatches:        true,
			DNSNames:               []string{"example.test"},
			SerialBits:             80,
			HasKeyUsage:            true,
			DigitalSignature:       true,
			BasicConstraintsValid:  true,
		}, chainNow)

		issuer := GradeIssuer(IssuerFacts{
			Subject:                "CN=Example Issuing CA",
			NotBefore:              chainNow.AddDate(-2, 0, 0),
			NotAfter:               chainNow.AddDate(8, 0, 0),
			SignatureAlgorithm:     c.algorithm,
			KeyAlgorithm:           c.keyAlgorithm,
			KeyBits:                c.bits,
			KeyFromBrokenGenerator: c.broken,
		}, chainNow)

		// Compared by the part of the identifier after the prefix, which is
		// the rule, not the face it was applied on.
		for _, suffix := range []string{
			"signature-sha1", "signature-md5", "signature-algorithm-unrecognised",
			"roca", "rsa-key-too-small", "ec-key-too-small", "key-algorithm-unrecognised",
		} {
			onLeaf := false
			for _, f := range leaf.Findings {
				if f.RuleID == "cert."+suffix {
					onLeaf = true
				}
			}
			onChain := has(issuerRuleIDs(issuer), "chain."+suffix)
			if onLeaf != onChain {
				t.Errorf("%s: %q fires on the leaf=%v and on an issuer=%v — the same key is graded "+
					"two ways depending on where it sits", c.name, suffix, onLeaf, onChain)
			}
		}
	}
}

// What an issuer is deliberately not graded on.
//
// Each of these fires on the leaf and must not fire here, and each would be
// wrong for its own reason: an authority is issued for decades, is presented
// for no name, is required to be an authority, and — where it is a root — is
// self-signed by definition.
func TestAnIssuerIsNotGradedOnWhatItIsNot(t *testing.T) {
	facts := soundIssuer()
	// Twenty years, no names, and the shape of a certificate authority.
	facts.NotBefore = chainNow.AddDate(-10, 0, 0)
	facts.NotAfter = chainNow.AddDate(10, 0, 0)

	got := GradeIssuer(facts, chainNow)

	for _, forbidden := range []string{
		"chain.validity-too-long",
		"chain.self-signed",
		"chain.hostname-mismatch",
		"chain.no-san",
		"chain.wildcard-shape",
		"chain.cn-not-in-san",
		"chain.leaf-is-ca",
		"chain.key-usage-cert-sign",
		"chain.no-digital-signature",
		"chain.no-server-auth",
	} {
		if has(issuerRuleIDs(got), forbidden) {
			t.Errorf("%s fired on an issuer, where it describes something an authority is supposed to be",
				forbidden)
		}
	}
	if got.Verdict != Strong {
		t.Errorf("a twenty-year authority certificate graded %s: %v", got.Verdict, issuerRuleIDs(got))
	}
}

// An issuer with no subject still produces a sentence.
func TestAnIssuerWithNoSubjectIsStillDescribed(t *testing.T) {
	facts := soundIssuer()
	facts.Subject = ""
	facts.SignatureAlgorithm = "SHA1-RSA"

	got := GradeIssuer(facts, chainNow)
	if len(got.Findings) == 0 {
		t.Fatal("a SHA-1 issuer with no subject was not graded at all")
	}
	for _, f := range got.Findings {
		if strings.Contains(f.Rationale, "  ") || strings.HasPrefix(f.Rationale, " ") {
			t.Errorf("the sentence has a hole where the subject should be:\n  %s", f.Rationale)
		}
	}
}
