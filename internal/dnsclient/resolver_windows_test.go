//go:build windows

package dnsclient

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// The registry cannot be faked without writing to it, which a test has no
// business doing. So the parsing is tested directly, and the walk itself is
// tested against the machine the test runs on — which is the only place it can
// be, and is the machine whose answer was wrong.

// A nameserver list is split however Windows happened to write it.
//
// Splitting only. Which of the pieces can be dialled is resolverList's
// question, tested portably, because it was in both platform files once and a
// duplicate suppressed in one of them was not suppressed in the other.
func TestANameserverListIsSplitHoweverItWasWritten(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  []string
	}{
		{"192.0.2.1", []string{"192.0.2.1"}},
		{"192.0.2.1 192.0.2.2", []string{"192.0.2.1", "192.0.2.2"}},
		{"192.0.2.1,192.0.2.2", []string{"192.0.2.1", "192.0.2.2"}},
		{"192.0.2.1, 192.0.2.2", []string{"192.0.2.1", "192.0.2.2"}},
		{"192.0.2.1\t192.0.2.2", []string{"192.0.2.1", "192.0.2.2"}},
		{"2001:db8::1 192.0.2.2", []string{"2001:db8::1", "192.0.2.2"}},
		{"", nil},

		// Passed through rather than judged here, so that one place decides
		// what is usable.
		{"0.0.0.0 192.0.2.3", []string{"0.0.0.0", "192.0.2.3"}},
	} {
		got := addresses(tc.value)
		if len(got) != len(tc.want) {
			t.Errorf("addresses(%q) = %v, want %v", tc.value, got, tc.want)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("addresses(%q)[%d] = %q, want %q", tc.value, i, got[i], tc.want[i])
			}
		}
	}
}

// A registry string is decoded without pointing a uint16 slice at it.
func TestARegistryStringIsDecoded(t *testing.T) {
	// "1.2" in UTF-16LE, with the terminating NUL the registry includes.
	raw := []byte{'1', 0, '.', 0, '2', 0, 0, 0}

	if got := utf16BytesToString(raw); got != "1.2" {
		t.Errorf("utf16BytesToString = %q, want %q", got, "1.2")
	}

	// An odd length cannot be a UTF-16 string. Dropping the stray byte is
	// what keeps a malformed value from panicking a scan.
	if got := utf16BytesToString([]byte{'1', 0, '.'}); got != "1" {
		t.Errorf("utf16BytesToString on an odd length = %q, want %q", got, "1")
	}
	if got := utf16BytesToString(nil); got != "" {
		t.Errorf("utf16BytesToString(nil) = %q, want empty", got)
	}
}

// What the machine this runs on actually reports.
//
// Machine-dependent by necessity: there is no portable registry to fixture, and
// the defect this replaces was precisely that the answer read from a real
// machine was wrong. A machine with no network configuration is skipped rather
// than failed.
func TestTheMachineReportsUsableResolvers(t *testing.T) {
	got, err := systemResolvers()
	if errors.Is(err, ErrNoResolver) {
		t.Skip("this machine has no resolver configured")
	}
	if err != nil {
		t.Fatalf("systemResolvers: %v", err)
	}

	if len(got) == 0 {
		t.Fatal("systemResolvers returned no error and no resolvers")
	}
	if len(got) > maxResolvers {
		t.Errorf("returned %d resolvers, and the bound is %d", len(got), maxResolvers)
	}

	seen := map[string]bool{}
	for _, addr := range got {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			t.Errorf("%q is not host:port: %v", addr, err)
			continue
		}
		if port != "53" {
			t.Errorf("%q names port %s, want 53", addr, port)
		}
		if net.ParseIP(host) == nil {
			t.Errorf("%q does not carry an address", addr)
		}
		if seen[addr] {
			t.Errorf("%q appears twice; one adapter's entry repeated is a timeout paid twice "+
				"for the same unreachable resolver", addr)
		}
		seen[addr] = true
	}

	t.Logf("this machine reports %s", strings.Join(got, ", "))
}
