package scan

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// FuzzSplitTarget drives the function that decides what this project will
// connect to. Its example-based tests cover the cases somebody thought of;
// this covers the ones nobody did.
//
// The assertions are properties rather than expected outputs, because the
// input is generated. What matters is not which host comes back but that
// whatever comes back cannot be dangerous.
func FuzzSplitTarget(f *testing.F) {
	seeds := []string{
		"example.com",
		"example.com:8443",
		"  example.com  ",
		"https://example.com/path",
		"[2606:4700:4700::1111]:443",
		"",
		":",
		"::",
		":::",
		"a:1:2:3",
		"example.com:",
		":443",
		"exam ple.com",
		"exam\nple.com",
		"example.com\x00.evil.test",
		"https://",
		"http://:@example.com",
		"example.com:99999999999999999999",
		"[::1]",
		"[",
		"]",
		"[]",
		"[]:443",
		strings.Repeat("a", 253),
		strings.Repeat("a", 254),
		strings.Repeat("a.", 200),
		"xn--e1afmkfd.xn--p1ai",
		"EXAMPLE.COM",
		"example.com.",
		"..",
		"../../etc/passwd",
		"%2e%2e%2f",
		"example.com#fragment",
		"example.com?query=1",
		"user:pass@example.com",

		// Seeds that broke an earlier version of this function. Keeping them
		// here means the cases cannot come back unnoticed.
		"example.com:",
		"[::1]",
		"[::1]:8443",
		"[::1]x",
		"a:1:2:3",
		"::1",
		"::ffff:127.0.0.1",
		"example.com:0",
		"example.com:65536",
		"example.com:abc",
		"münchen.de",
		"example.com:+443",
		"example.com:0443",
		"example.com:00443",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		host, port, err := SplitTarget(in)
		if err != nil {
			// A refusal is always an acceptable answer.
			return
		}

		// Everything below describes what an accepted result must satisfy.

		if host == "" {
			t.Fatalf("SplitTarget(%q) accepted an empty host", in)
		}
		if port == "" {
			t.Fatalf("SplitTarget(%q) accepted an empty port", in)
		}

		if len(host) > maxHostLen {
			t.Fatalf("SplitTarget(%q) returned a host of %d bytes, above the %d-byte limit",
				in, len(host), maxHostLen)
		}

		// This is the property that matters most. A newline inside a hostname
		// is where header injection starts, and a NUL byte is how a
		// truncating parser is made to read a name other than the one that
		// was checked.
		if strings.ContainsAny(host, " \t\r\n\x00") {
			t.Fatalf("SplitTarget(%q) returned a host containing a control character or space: %q", in, host)
		}
		if strings.ContainsAny(port, " \t\r\n\x00") {
			t.Fatalf("SplitTarget(%q) returned a port containing a control character or space: %q", in, port)
		}

		// The port must be a number in range before anything consults the
		// allow list, or an arbitrary string reaches CheckPort.
		n, convErr := strconv.Atoi(port)
		if convErr != nil || n < 1 || n > 65535 {
			t.Fatalf("SplitTarget(%q) returned port %q, which is not a number between 1 and 65535", in, port)
		}

		// One port, one spelling. Atoi accepts "+443" and "0443" and reports
		// 443 for both, and several spellings of one value is where
		// parser-mismatch bugs begin.
		if strconv.Itoa(n) != port {
			t.Fatalf("SplitTarget(%q) returned port %q, which is not the canonical spelling of %d", in, port, n)
		}

		// Brackets must never survive into the host. Handing the resolver
		// "[::1]" gives it a name it can never look up, and the earlier
		// version of this function did exactly that.
		if strings.ContainsAny(host, "[]") {
			t.Fatalf("SplitTarget(%q) returned a host containing a bracket: %q", in, host)
		}

		// A colon in the host is legitimate only inside an IPv6 literal.
		if strings.Contains(host, ":") {
			if _, err := netip.ParseAddr(host); err != nil {
				t.Fatalf("SplitTarget(%q) returned host %q, which has a colon but is not an IPv6 address", in, host)
			}
		}

		// Rejoining and re-splitting must not change the answer. If it did,
		// a check performed on one form would not describe the form that is
		// eventually dialled.
		again := net.JoinHostPort(host, port)
		host2, port2, err2 := SplitTarget(again)
		if err2 != nil {
			t.Fatalf("SplitTarget(%q) produced %q, which SplitTarget then rejected: %v", in, again, err2)
		}
		if host2 != host || port2 != port {
			t.Fatalf("SplitTarget is not stable: %q gave (%q, %q), rejoined as %q it gives (%q, %q)",
				in, host, port, again, host2, port2)
		}
	})
}

// FuzzCheckPort asserts that the allow list cannot be talked past, whatever
// shape the port takes. SplitHostPort does not require a port to be numeric,
// so this receives more than digits.
func FuzzCheckPort(f *testing.F) {
	for _, s := range []string{"443", "22", "", "0443", "443 ", " 443", "٤٤٣", "443\n", "+443", "0x1bb"} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, port string) {
		if err := CheckPort(port); err != nil {
			return
		}

		// An accepted port must appear in the list verbatim. Anything else
		// means a comparison somewhere is doing more than comparing.
		for _, allowed := range AllowedPorts {
			if port == allowed {
				return
			}
		}
		t.Fatalf("CheckPort(%q) accepted a port that is not in AllowedPorts", port)
	})
}
