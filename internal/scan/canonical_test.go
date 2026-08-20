package scan

import (
	"net"
	"testing"
)

// One host, one string.
//
// DNS is case-insensitive and a trailing dot names the same zone, so
// EXAMPLE.COM, example.com and example.com. all reach one server. Anything
// downstream that compares hostnames has to see one form, and the thing that
// compares hostnames here is the per-target rate limit — the only limit in
// this project that protects the party being scanned rather than the service
// doing the scanning.
//
// Before this, a caller spelled the name differently on each request and
// received a fresh budget every time. Two thousand spellings of an
// eleven-letter name is not an exotic attack; it is a loop.
func TestSplitTargetFoldsSpelling(t *testing.T) {
	spellings := []string{
		"example.com",
		"EXAMPLE.COM",
		"Example.Com",
		"eXaMpLe.CoM",
		"example.com.",
		"ExAmPlE.cOm.",
		"  EXAMPLE.COM.  ",
		"https://ExAmPlE.cOm/path",
	}

	for _, in := range spellings {
		host, port, err := SplitTarget(in)
		if err != nil {
			t.Fatalf("SplitTarget(%q): %v", in, err)
		}
		if host != "example.com" {
			t.Errorf("SplitTarget(%q) gave host %q, want example.com: every spelling of one name has to reduce to one string", in, host)
		}
		if port != DefaultPort {
			t.Errorf("SplitTarget(%q) gave port %q, want %s", in, port, DefaultPort)
		}
	}
}

// An address is a name too, and it has more spellings than a hostname does.
func TestSplitTargetFoldsAddresses(t *testing.T) {
	for _, in := range []string{"[0:0:0:0:0:0:0:1]", "[::1]", "[::0001]", "[0::1]"} {
		host, _, err := SplitTarget(in)
		if err != nil {
			t.Fatalf("SplitTarget(%q): %v", in, err)
		}
		if host != "::1" {
			t.Errorf("SplitTarget(%q) gave host %q, want ::1", in, host)
		}
	}

	// Folding must not turn one address into another, so the mapped form is
	// pinned rather than assumed.
	host, _, err := SplitTarget("[::FFFF:127.0.0.1]")
	if err != nil {
		t.Fatalf("SplitTarget: %v", err)
	}
	if host != "::ffff:127.0.0.1" {
		t.Errorf("host = %q, want ::ffff:127.0.0.1", host)
	}
}

// Folding removes one trailing dot because one trailing dot is the root. Two
// is an empty label: a name no resolver will accept and a spelling the
// canonical form cannot reduce, so it has to be refused rather than folded.
func TestHostWithATrailingEmptyLabelIsRefused(t *testing.T) {
	for _, in := range []string{"example.com..", "example.com...", "example..com"} {
		if host, _, err := SplitTarget(in); err == nil {
			t.Errorf("SplitTarget(%q) accepted an empty label and returned %q", in, host)
		}
	}
}

// The canonical form has to survive the round trip, or a check performed on
// one form would not describe the form that is eventually dialled. The fuzz
// target asserts this for generated input; this pins the folding cases so a
// failure names what broke.
func TestFoldingIsStable(t *testing.T) {
	for _, in := range []string{"EXAMPLE.COM.", "Example.Com:8443", "[0:0:0:0:0:0:0:1]:8443"} {
		host, port, err := SplitTarget(in)
		if err != nil {
			t.Fatalf("SplitTarget(%q): %v", in, err)
		}

		host2, port2, err := SplitTarget(net.JoinHostPort(host, port))
		if err != nil {
			t.Fatalf("SplitTarget rejected its own output for %q: %v", in, err)
		}
		if host2 != host || port2 != port {
			t.Errorf("folding is not stable: %q gave (%q, %q), which re-split gives (%q, %q)",
				in, host, port, host2, port2)
		}
	}
}
