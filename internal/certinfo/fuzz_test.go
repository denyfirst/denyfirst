package certinfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// FuzzAnalyse feeds arbitrary DER to the parser and, when something parses,
// through the analysis.
//
// x509.ParseCertificate does the hard part and is fuzzed by the Go project
// itself. What this target covers is the code after it: a certificate can
// parse cleanly and still carry an empty subject, a nil public key, dates
// centuries apart, or a hundred subject alternative names. Those are the
// shapes our own code has to survive.
func FuzzAnalyse(f *testing.F) {
	// A real certificate gives the fuzzer somewhere to start; mutating valid
	// DER reaches far more of the parser than random bytes ever will.
	root := mustSeedCertificate(f)
	f.Add(root, "example.test")
	f.Add(root, "")
	f.Add([]byte{}, "example.test")
	f.Add([]byte{0x30, 0x00}, "example.test")

	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)

	f.Fuzz(func(t *testing.T, der []byte, hostname string) {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return // not a certificate; the parser's own fuzzing covers that
		}

		report, err := Analyse([]*x509.Certificate{cert}, hostname, now)
		if err != nil {
			return
		}

		if report == nil {
			t.Fatal("Analyse returned no report and no error")
		}
		if report.Policy == "" {
			t.Fatal("the report does not name the policy that graded it")
		}
		if len(report.Chain) != 1 {
			t.Fatalf("the chain has %d entries, want 1", len(report.Chain))
		}

		leaf := report.Chain[0]
		if len(leaf.FingerprintSHA256) != 64 {
			t.Fatalf("fingerprint has %d characters, want 64", len(leaf.FingerprintSHA256))
		}

		// The verdict must be one the caller can act on. Ungraded is reserved
		// for the case where nothing could be measured, and a parsed
		// certificate is always measurable.
		switch report.Verdict {
		case "strong", "weak", "insecure":
		default:
			t.Fatalf("verdict %q is not one a caller can act on", report.Verdict)
		}

		// An untrusted chain is the normal case here, since these
		// certificates reach no root. It must never be graded strong.
		if !report.Trusted && report.Verdict == "strong" {
			t.Fatal("an untrusted chain was graded strong")
		}
	})
}

// mustSeedCertificate builds one valid certificate so the fuzzer has real DER
// to mutate. Random bytes almost never reach past the first few fields of an
// ASN.1 parser.
func mustSeedCertificate(f *testing.F) []byte {
	f.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generating a key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.test"},
		NotBefore:             time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:              []string{"example.test"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		f.Fatalf("creating a certificate: %v", err)
	}
	return der
}
