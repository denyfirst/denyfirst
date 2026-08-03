package scan

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

func TestSplitTarget(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort string
	}{
		{"example.com", "example.com", "443"},
		{"example.com:8443", "example.com", "8443"},

		// Surrounding whitespace is trimmed rather than refused: people paste
		// it constantly, and after trimming there is nothing left to exploit.
		{"  example.com  ", "example.com", "443"},
		{"example.com\n", "example.com", "443"},
		{"\texample.com:8443\r\n", "example.com", "8443"},

		// A pasted URL is a likely mistake, not an error worth refusing.
		{"https://example.com", "example.com", "443"},
		{"http://example.com", "example.com", "443"},
		{"https://example.com/", "example.com", "443"},
		{"https://example.com/path/to/page", "example.com", "443"},
		{"https://example.com:8443/x", "example.com", "8443"},

		{"[2606:4700:4700::1111]:443", "2606:4700:4700::1111", "443"},
	}

	for _, tc := range cases {
		host, port, err := SplitTarget(tc.in)
		if err != nil {
			t.Errorf("SplitTarget(%q) returned %v", tc.in, err)
			continue
		}
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("SplitTarget(%q) = %q, %q; want %q, %q", tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

// Interior control characters survive trimming, and they are the ones that
// matter: a newline inside a hostname is how header injection starts, and a
// NUL byte is how a truncating parser is made to read a different name than
// the one that was checked.
func TestSplitTargetRejectsMalformedInput(t *testing.T) {
	bad := []string{
		"",
		"   ",
		"https://",
		"exa mple.com",
		"exam\nple.com",
		"example\r.com",
		"example.com\x00.evil.test",
		strings.Repeat("a", 300),
	}

	for _, in := range bad {
		if _, _, err := SplitTarget(in); err == nil {
			t.Errorf("SplitTarget(%q) accepted malformed input", in)
		}
	}
}

func TestCheckPort(t *testing.T) {
	for _, port := range AllowedPorts {
		if err := CheckPort(port); err != nil {
			t.Errorf("CheckPort(%s) rejected an allowed port: %v", port, err)
		}
	}

	// STARTTLS ports are absent on purpose: the probe speaks TLS from the
	// first byte, so a scan of port 25 would fail in a way that reads as a
	// server fault rather than as a missing feature.
	refused := []string{"22", "25", "80", "110", "143", "587", "3389", "9999"}
	for _, port := range refused {
		if err := CheckPort(port); err == nil {
			t.Errorf("CheckPort(%s) accepted a port outside the allow list", port)
		}
	}
}

// The allow list must not grow to include ports that would let this project
// be used to probe a third party's network.
func TestAllowedPortsAreImplicitTLS(t *testing.T) {
	startTLS := map[string]string{
		"25":  "SMTP",
		"110": "POP3",
		"143": "IMAP",
		"587": "SMTP submission",
		"21":  "FTP",
		"389": "LDAP",
	}

	for _, port := range AllowedPorts {
		if proto, found := startTLS[port]; found {
			t.Errorf("port %s (%s) negotiates TLS after a plaintext greeting; the probe cannot speak it", port, proto)
		}
	}
}

// A zero Scanner must reach safedial. If this ever succeeds against a private
// address, the guard has been disconnected from the pipeline.
func TestZeroScannerRefusesPrivateTargets(t *testing.T) {
	s := &Scanner{}

	for _, target := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1"} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		result, err := s.Scan(ctx, target)
		cancel()

		if err != nil {
			continue // refused before producing a result: also correct
		}
		if result.Certificate != nil {
			t.Errorf("Scan(%s) returned a certificate from a private address", target)
		}
		for _, v := range result.TLS.Versions {
			if v.Supported {
				t.Errorf("Scan(%s) completed a handshake against a private address", target)
			}
		}
	}
}

// Nothing measured must not read as passing, and the policy version must be
// stated whatever the outcome.
func TestUnreachableTargetIsUngraded(t *testing.T) {
	s := &Scanner{
		Prober: &tlsprobe.Prober{
			Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
				return nil, errors.New("no network in this test")
			},
		},
	}

	result, err := s.Scan(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("Scan returned %v", err)
	}

	if result.Verdict != policy.Ungraded {
		t.Errorf("Verdict = %q, want it ungraded", result.Verdict)
	}
	if result.Policy != policy.Version {
		t.Errorf("Policy = %q, want %q", result.Policy, policy.Version)
	}
	if result.Certificate != nil {
		t.Error("a certificate report was produced although nothing connected")
	}
	if len(result.Findings()) != 0 {
		t.Errorf("findings were reported although nothing was measured: %v", result.Findings())
	}
}

func TestScanRejectsMalformedTarget(t *testing.T) {
	s := &Scanner{}
	if _, err := s.Scan(context.Background(), "exam\nple.com"); err == nil {
		t.Error("Scan accepted a host containing a newline")
	}
}
