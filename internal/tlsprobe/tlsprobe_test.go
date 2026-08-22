package tlsprobe

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
)

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

// gradeCipher must reach the policy package rather than carry its own
// opinion. If grading logic ever creeps back into this package, the verdict
// here will stop matching.
func TestGradeCipherDelegatesToPolicy(t *testing.T) {
	cases := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_RC4_128_SHA,
	}

	for _, id := range cases {
		name := tls.CipherSuiteName(id)
		got := gradeCipher(id)

		if got.ID != id {
			t.Errorf("%s: ID = %#04x, want %#04x", name, got.ID, id)
		}
		want := policy.GradeCipher(name)
		if got.Verdict != want.Verdict {
			t.Errorf("%s: Verdict = %q, but policy says %q", name, got.Verdict, want.Verdict)
		}
		if got.Name != name {
			t.Errorf("Name = %q, want %q", got.Name, name)
		}
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
	local, _ := classifyHandshakeError(
		errors.New("tls: no supported versions satisfy MinVersion and MaxVersion"),
		tls.VersionTLS10,
	)
	if !strings.Contains(local, "not tested") {
		t.Errorf("a client-side refusal was classified as %q; it must say it was not tested", local)
	}

	remote, _ := classifyHandshakeError(
		errors.New("remote error: tls: protocol version not supported"),
		tls.VersionTLS10,
	)
	if !strings.Contains(remote, "server refused") {
		t.Errorf("a server refusal was classified as %q; it must name the server", remote)
	}
}

// A server that refuses TLS 1.0 has done the right thing. Grading the refusal
// would report a correct configuration as insecure.
func TestUnsupportedVersionsDoNotContributeFindings(t *testing.T) {
	results := []VersionResult{
		{
			Version:   tls.VersionTLS10,
			Name:      "TLS 1.0",
			Supported: false,
			Error:     "server refused TLS 1.0",
		},
		{
			Version:   tls.VersionTLS13,
			Name:      "TLS 1.3",
			Supported: true,
			Grade:     policy.GradeVersion(tls.VersionTLS13),
			Ciphers:   []CipherResult{gradeCipher(tls.TLS_AES_128_GCM_SHA256)},

			// Set deliberately, and the zero value is deliberately the other
			// way. An unfinished suite list forfeits a verdict of strong, so
			// a producer that forgets this field gets ungraded rather than a
			// grade it did not earn. Fixtures have to say so too.
			CipherListComplete: true,
		},
	}

	verdict, findings := summarise(results)

	if verdict != policy.Strong {
		t.Errorf("Verdict = %q, want %q", verdict, policy.Strong)
	}
	for _, f := range findings {
		if f.RuleID == "version.deprecated" {
			t.Error("a refused version produced a deprecation finding; refusing it is correct behaviour")
		}
	}
}

// One insecure suite makes the configuration insecure, because the attacker
// picks which suite is negotiated.
func TestWorstCaseAggregation(t *testing.T) {
	results := []VersionResult{{
		Version:   tls.VersionTLS12,
		Name:      "TLS 1.2",
		Supported: true,
		Grade:     policy.GradeVersion(tls.VersionTLS12),
		Ciphers: []CipherResult{
			gradeCipher(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),   // strong
			gradeCipher(tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384), // strong
			gradeCipher(tls.TLS_RSA_WITH_RC4_128_SHA),                // insecure
		},
	}}

	verdict, findings := summarise(results)

	if verdict != policy.Insecure {
		t.Errorf("Verdict = %q, want %q: two strong suites do not offset one insecure suite", verdict, policy.Insecure)
	}
	if len(findings) == 0 {
		t.Fatal("graded insecure with no finding to explain it")
	}
	if findings[0].Verdict != policy.Insecure {
		t.Errorf("findings are not sorted by severity: first is %q", findings[0].Verdict)
	}
}

// Nothing measured must not read as passing.
func TestNothingMeasuredIsUngraded(t *testing.T) {
	results := []VersionResult{
		{Version: tls.VersionTLS13, Name: "TLS 1.3", Supported: false, Error: "connection refused"},
		{Version: tls.VersionTLS12, Name: "TLS 1.2", Supported: false, Error: "connection refused"},
	}

	verdict, findings := summarise(results)

	if verdict != policy.Ungraded {
		t.Errorf("Verdict = %q, want it ungraded: an unreachable server has not passed anything", verdict)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %+v", findings)
	}
}

// The same problem seen at several versions must appear once.
func TestFindingsAreDeduplicated(t *testing.T) {
	rc4 := gradeCipher(tls.TLS_RSA_WITH_RC4_128_SHA)

	results := []VersionResult{
		{
			Version: tls.VersionTLS11, Name: "TLS 1.1", Supported: true,
			Grade: policy.GradeVersion(tls.VersionTLS11), Ciphers: []CipherResult{rc4},
		},
		{
			Version: tls.VersionTLS12, Name: "TLS 1.2", Supported: true,
			Grade: policy.GradeVersion(tls.VersionTLS12), Ciphers: []CipherResult{rc4},
		},
	}

	_, findings := summarise(results)

	seen := map[string]int{}
	for _, f := range findings {
		seen[f.RuleID]++
	}
	for id, count := range seen {
		if count > 1 {
			t.Errorf("rule %s appears %d times, want once", id, count)
		}
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

// Every report must name the policy that graded it, so a verdict can be
// reproduced after the rules change.
func TestReportNamesThePolicy(t *testing.T) {
	p := &Prober{
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, errors.New("no network in this test")
		},
	}

	report, err := p.Probe(context.Background(), "example.test", "443")
	if err != nil {
		t.Fatalf("Probe returned %v", err)
	}
	if report.Policy != policy.Version {
		t.Errorf("Policy = %q, want %q", report.Policy, policy.Version)
	}
	if report.Verdict != policy.Ungraded {
		t.Errorf("Verdict = %q, want it ungraded when nothing connected", report.Verdict)
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
