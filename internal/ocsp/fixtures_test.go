package ocsp

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Responses from real certificate authorities, captured from live servers.
//
// Everything else in this package reads responses the tests built, and they
// share whatever assumptions the person writing them held. These do not: they
// are the bytes DigiCert, Sectigo, Apple and Microsoft actually put on the
// wire, with four different encoders behind them and both signing
// arrangements — the issuer signing directly, and a delegated responder.
//
// The failure this guards is the one the project minds most. A response this
// parser cannot read is reported as cert.staple-unverifiable, which is Weak,
// against a server doing everything correctly — a false accusation, and a
// reader cannot tell one from a real finding. Until these existed, nothing
// stood between that and the next encoding nobody had thought of.
//
// Each fixture carries the moment to judge it at, because a real response
// expires within days of capture and a test that goes red on a Tuesday
// teaches people to ignore it. Freshness is exercised against built responses
// instead, where the clock is ours to choose.
var captured = map[string]time.Time{
	// Signed by the issuing authority itself.
	"www.digicert.com": time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC),
	"sectigo.com":      time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC),
	"www.paypal.com":   time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),

	// Signed by a delegated responder the authority marked for the purpose.
	"www.apple.com":     time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC),
	"www.microsoft.com": time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),
}

func TestRealResponsesFromRealAuthorities(t *testing.T) {
	present, err := filepath.Glob(filepath.Join("testdata", "*.ocsp.der"))
	if err != nil {
		t.Fatalf("reading testdata: %v", err)
	}
	if len(present) == 0 {
		t.Fatal("no captured responses in internal/ocsp/testdata. " +
			"A fixture test with no fixtures asserts nothing; either add the files or delete this test.")
	}

	for _, path := range present {
		host := strings.TrimSuffix(filepath.Base(path), ".ocsp.der")

		at, known := captured[host]
		if !known {
			t.Errorf("%s: no capture time recorded for this fixture, so it cannot be judged", host)
			continue
		}

		der := readFixture(t, path)
		leaf := readCertificate(t, filepath.Join("testdata", host+".leaf.der"))
		issuer := readCertificate(t, filepath.Join("testdata", host+".issuer.der"))

		got, err := Check(der, leaf, issuer, at)
		if err != nil {
			t.Errorf("%s: a real response from a real authority was refused: %v", host, err)
			continue
		}
		if got.Status != Good {
			t.Errorf("%s: status = %q, want %q", host, got.Status, Good)
		}
		if got.ThisUpdate.After(at) || (!got.NextUpdate.IsZero() && got.NextUpdate.Before(at)) {
			t.Errorf("%s: the recorded time %s is outside the response's own window %s..%s",
				host, at.Format(time.RFC3339),
				got.ThisUpdate.Format(time.RFC3339), got.NextUpdate.Format(time.RFC3339))
		}
	}
}

// Both signing arrangements have to be represented. A corpus of five
// responses that all took the same path proves less than it looks.
func TestTheFixturesCoverBothSigningArrangements(t *testing.T) {
	var direct, delegated int

	for host, at := range captured {
		path := filepath.Join("testdata", host+".ocsp.der")
		if _, err := os.Stat(path); err != nil {
			continue
		}
		got, err := Check(readFixture(t, path),
			readCertificate(t, filepath.Join("testdata", host+".leaf.der")),
			readCertificate(t, filepath.Join("testdata", host+".issuer.der")), at)
		if err != nil {
			continue // reported by the test above
		}
		if got.SignedByDelegate {
			delegated++
		} else {
			direct++
		}
	}

	if direct == 0 {
		t.Error("no captured response is signed by the issuer itself")
	}
	if delegated == 0 {
		t.Error("no captured response is signed by a delegated responder")
	}
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return body
}

func readCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(readFixture(t, path))
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return cert
}
