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

func TestDescribeCipherGrading(t *testing.T) {
	cases := []struct {
		id            uint16
		wantForward   bool
		wantAEAD      bool
		wantGrade     string
		wantInsecure  bool
	}{
		{
			id:          tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			wantForward: true,
			wantAEAD:    true,
			wantGrade:   "strong",
		},
		{
			id:          tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			wantForward: true,
			wantAEAD:    true,
			wantGrade:   "strong",
		},
		{
			// TLS 1.3: forward secrecy and AEAD are protocol requirements.
			id:          tls.TLS_AES_128_GCM_SHA256,
			wantForward: true,
			wantAEAD:    true,
			wantGrade:   "strong",
		},
		{
			id:          tls.TLS_AES_256_GCM_SHA384,
			wantForward: true,
			wantAEAD:    true,
			wantGrade:   "strong",
		},
		{
			id:          tls.TLS_CHACHA20_POLY1305_SHA256,
			wantForward: true,
			wantAEAD:    true,
			wantGrade:   "strong",
		},
		{
			// AEAD but static RSA key exchange: one leaked key exposes every
			// session ever recorded.
			id:          tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			wantForward: false,
			wantAEAD:    true,
			wantGrade:   "weak",
		},
		{
			// Forward secret but CBC: the padding-oracle family applies.
			id:          tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			wantForward: true,
			wantAEAD:    false,
			wantGrade:   "weak",
		},
		{
			id:           tls.TLS_RSA_WITH_RC4_128_SHA,
			wantForward:  false,
			wantAEAD:     false,
			wantGrade:    "insecure",
			wantInsecure: true,
		},
		{
			id:           tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			wantForward:  false,
			wantAEAD:     false,
			wantGrade:    "insecure",
			wantInsecure: true,
		},
	}

	for _, tc := range cases {
		got := describeCipher(tc.id)

		if got.Name == "" || strings.Contains(got.Name, "0x") {
			t.Errorf("describeCipher(%#04x) produced no readable name: %q", tc.id, got.Name)
		}
		if got.ForwardSecret != tc.wantForward {
			t.Errorf("%s: ForwardSecret = %v, want %v", got.Name, got.ForwardSecret, tc.wantForward)
		}
		if got.AEAD != tc.wantAEAD {
			t.Errorf("%s: AEAD = %v, want %v", got.Name, got.AEAD, tc.wantAEAD)
		}
		if got.Insecure != tc.wantInsecure {
			t.Errorf("%s: Insecure = %v, want %v", got.Name, got.Insecure, tc.wantInsecure)
		}
		if got.Grade != tc.wantGrade {
			t.Errorf("%s: Grade = %q, want %q", got.Name, got.Grade, tc.wantGrade)
		}
	}
}

// Every suite Go exposes must receive a grade. A new suite in a future Go
// release that fell through the classification would show up here.
func TestEveryKnownSuiteIsGraded(t *testing.T) {
	all := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	if len(all) == 0 {
		t.Fatal("crypto/tls reported no cipher suites at all")
	}

	valid := []string{"strong", "weak", "insecure"}
	for _, cs := range all {
		got := describeCipher(cs.ID)
		if !slices.Contains(valid, got.Grade) {
			t.Errorf("%s: grade %q is not one of %v", cs.Name, got.Grade, valid)
		}
		if got.Insecure != cs.Insecure {
			t.Errorf("%s: Insecure = %v, but crypto/tls says %v", cs.Name, got.Insecure, cs.Insecure)
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

	// Go does not allow choosing TLS 1.3 suites, so there is nothing to
	// enumerate and the probe reports the negotiated suite instead.
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

// A caller's deadline must bound the probe regardless of TotalTimeout.
func TestCallerDeadlineWins(t *testing.T) {
	p := &Prober{TotalTimeout: time.Hour}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := p.Probe(ctx, "example.com", "443"); err != nil {
		t.Logf("probe returned %v", err)
	}

	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("probe took %v; the caller's 100ms deadline was not honoured", elapsed)
	}
}
