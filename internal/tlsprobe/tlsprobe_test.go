package tlsprobe

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// Suites whose properties follow from the protocol rather than from a policy
// decision. TLS 1.3 mandates AEAD and ephemeral key exchange; ECDHE with GCM
// has both by construction. These expectations cannot drift with a Go release.
func TestStrongSuitesAreGradedStrong(t *testing.T) {
	strong := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	for _, id := range strong {
		got := describeCipher(id)

		if got.Name == "" || strings.Contains(got.Name, "0x") {
			t.Errorf("describeCipher(%#04x) produced no readable name: %q", id, got.Name)
		}
		if !got.ForwardSecret {
			t.Errorf("%s: ForwardSecret = false, but the suite is ephemeral", got.Name)
		}
		if !got.AEAD {
			t.Errorf("%s: AEAD = false, but the suite is AEAD", got.Name)
		}
		if got.Grade != "strong" {
			t.Errorf("%s: Grade = %q, want \"strong\"", got.Name, got.Grade)
		}
	}
}

// Forward secrecy is read from the key exchange named in the suite. Without
// it, one compromised private key decrypts every session ever recorded.
func TestForwardSecrecyDetection(t *testing.T) {
	ephemeral := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_AES_128_GCM_SHA256,
	}
	for _, id := range ephemeral {
		if got := describeCipher(id); !got.ForwardSecret {
			t.Errorf("%s: ForwardSecret = false, want true", got.Name)
		}
	}

	static := []uint16{
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	}
	for _, id := range static {
		if got := describeCipher(id); got.ForwardSecret {
			t.Errorf("%s: ForwardSecret = true, but the key exchange is static RSA", got.Name)
		}
	}
}

// AEAD is read from the cipher mode. CBC in TLS has a long history of
// padding-oracle attacks.
func TestAEADDetection(t *testing.T) {
	aead := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}
	for _, id := range aead {
		if got := describeCipher(id); !got.AEAD {
			t.Errorf("%s: AEAD = false, want true", got.Name)
		}
	}

	notAEAD := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_RC4_128_SHA,
	}
	for _, id := range notAEAD {
		if got := describeCipher(id); got.AEAD {
			t.Errorf("%s: AEAD = true, but the suite is CBC or a stream cipher", got.Name)
		}
	}
}

// Grading follows rules, not a hardcoded verdict per suite. Asserting that a
// named suite is "weak" rather than "insecure" bakes in one Go release's
// judgement: Go has already moved static-RSA AEAD suites from one category to
// the other. These rules hold whatever it decides next.
func TestGradingRulesHoldForEverySuite(t *testing.T) {
	insecure := tls.InsecureCipherSuites()
	secure := tls.CipherSuites()

	if len(insecure)+len(secure) == 0 {
		t.Fatal("crypto/tls reported no cipher suites at all")
	}

	for _, cs := range insecure {
		got := describeCipher(cs.ID)
		if !got.Insecure {
			t.Errorf("%s: Insecure = false, but crypto/tls lists it as insecure", cs.Name)
		}
		if got.Grade != "insecure" {
			t.Errorf("%s: Grade = %q, want \"insecure\"", cs.Name, got.Grade)
		}
	}

	for _, cs := range secure {
		got := describeCipher(cs.ID)
		if got.Insecure {
			t.Errorf("%s: Insecure = true, but crypto/tls lists it as secure", cs.Name)
		}

		want := "weak"
		if got.ForwardSecret && got.AEAD {
			want = "strong"
		}
		if got.Grade != want {
			t.Errorf("%s: Grade = %q, want %q (ForwardSecret=%v AEAD=%v)",
				cs.Name, got.Grade, want, got.ForwardSecret, got.AEAD)
		}
	}
}

// Every suite Go exposes must land in one of the three grades. A suite added
// in a future release that fell through the classification shows up here.
func TestEverySuiteReceivesAGrade(t *testing.T) {
	valid := []string{"strong", "weak", "insecure"}

	for _, cs := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if got := describeCipher(cs.ID); !slices.Contains(valid, got.Grade) {
			t.Errorf("%s: grade %q is not one of %v", cs.Name, got.Grade, valid)
		}
	}
}

func TestCandidateSuites(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
		suites := candidateSuites(version)
		if len(suites) == 0 {
			t.Errorf("candidateSuites(%s) returned nothing", versionName(version))
			continue
		}
		// Duplicates would make the enumeration loop remove one entry per
		// round while the server keeps answering with the same suite.
		seen := map[uint16]bool{}
		for _, id := range suites {
			if seen[id] {
				t.Errorf("candidateSuites(%s) contains %s twice", versionName(version), tls.CipherSuiteName(id))
			}
			seen[id] = true
		}
	}
}

// Go ignores Config.CipherSuites for TLS 1.3. candidateSuites must return
// nothing for it, because handing those IDs to a handshake would suggest a
// selection that the library will not honour.
func TestCandidateSuitesSkipsTLS13(t *testing.T) {
	if got := candidateSuites(tls.VersionTLS13); len(got) != 0 {
		t.Errorf("candidateSuites(TLS 1.3) returned %d suites; Go does not permit selecting them", len(got))
	}
}

func TestVersionName(t *testing.T) {
	cases := map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}
	for version, want := range cases {
		if got := versionName(version); got != want {
			t.Errorf("versionName(%#04x) = %q, want %q", version, got, want)
		}
	}
	if got := versionName(0x0002); !strings.Contains(got, "unknown") {
		t.Errorf("versionName of an unrecognised value = %q, want it marked unknown", got)
	}
}

// A version our own client declined must not be reported as a server refusal.
// Conflating the two turns a gap in the probe into a false clean result.
func TestClassifyHandshakeError(t *testing.T) {
	local := classifyHandshakeError(
		errors.New("tls: no supported versions satisfy MinVersion and MaxVersion"),
		tls.VersionTLS10,
	)
	if !strings.Contains(local, "not tested") {
		t.Errorf("a client-side refusal was classified as %q; it must say it was not tested", local)
	}

	remote := classifyHandshakeError(
		errors.New("remote error: tls: protocol version not supported"),
		tls.VersionTLS10,
	)
	if !strings.Contains(remote, "server refused") {
		t.Errorf("a server refusal was classified as %q; it must name the server", remote)
	}
}

func TestDefaults(t *testing.T) {
	zero := &Prober{}
	if got := zero.handshakeTimeout(); got != defaultHandshakeTimeout {
		t.Errorf("handshakeTimeout() = %v, want %v", got, defaultHandshakeTimeout)
	}
	if got := zero.totalTimeout(); got != defaultTotalTimeout {
		t.Errorf("totalTimeout() = %v, want %v", got, defaultTotalTimeout)
	}
	if zero.dial() == nil {
		t.Error("dial() returned nil; a zero Prober must fall back to safedial")
	}

	set := &Prober{HandshakeTimeout: time.Second, TotalTimeout: 2 * time.Second}
	if got := set.handshakeTimeout(); got != time.Second {
		t.Errorf("handshakeTimeout() = %v, want 1s", got)
	}
	if got := set.totalTimeout(); got != 2*time.Second {
		t.Errorf("totalTimeout() = %v, want 2s", got)
	}
}

// The default dialer must refuse private destinations. If this ever passes
// without error, the SSRF guard has been disconnected from the probe.
func TestDefaultDialerRefusesPrivateTargets(t *testing.T) {
	p := &Prober{}
	targets := []string{"127.0.0.1:443", "169.254.169.254:80", "10.0.0.1:443"}

	for _, target := range targets {
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			t.Fatalf("bad test data %q: %v", target, err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		report, err := p.Probe(ctx, host, port)
		cancel()

		if err != nil {
			continue // refused before producing a report: also correct
		}
		for _, v := range report.Versions {
			if v.Supported {
				t.Errorf("Probe(%s) completed a handshake against a private address", target)
			}
		}
		if len(report.Certificates) != 0 {
			t.Errorf("Probe(%s) returned a certificate chain from a private address", target)
		}
	}
}

// A caller's deadline must bound the probe regardless of TotalTimeout. The
// dialer here never returns on its own, so only a deadline can end the probe.
func TestCallerDeadlineWins(t *testing.T) {
	p := &Prober{
		TotalTimeout: time.Hour,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	report, err := p.Probe(ctx, "example.test", "443")
	elapsed := time.Since(start)

	if elapsed > 10*time.Second {
		t.Fatalf("probe took %v; the caller's 200ms deadline was not honoured", elapsed)
	}
	if err != nil {
		return // an error is an acceptable outcome
	}
	for _, v := range report.Versions {
		if v.Supported {
			t.Errorf("%s reported as supported although the dialer never connected", v.Name)
		}
	}
}
