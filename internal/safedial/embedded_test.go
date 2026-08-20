package safedial

import (
	"net/netip"
	"testing"
)

// An IPv6 address can carry an IPv4 address inside it, and every predicate in
// checkAddr answers for the address it is handed rather than for the one
// hidden in the low bits.
//
// ::ffff:127.0.0.1 is the well-known case and Unmap deals with it. The others
// are not mapped, so Unmap leaves them alone: IsLoopback, IsPrivate and
// IsLinkLocalUnicast all return false for ::127.0.0.1, and without a prefix
// covering the range it reaches the dialler as an ordinary global address.
//
// These are the addresses somebody reaches for after the obvious form is
// refused, which is why they are tested by name rather than left to the
// general shape of the list.
func TestEmbeddedIPv4FormsAreBlocked(t *testing.T) {
	blocked := []struct {
		addr string
		why  string
	}{
		// RFC 4291 IPv4-compatible, deprecated but still parsed by stacks.
		{"::127.0.0.1", "IPv4-compatible loopback"},
		{"::10.0.0.1", "IPv4-compatible RFC 1918"},
		{"::169.254.169.254", "IPv4-compatible cloud metadata"},
		{"::192.168.1.1", "IPv4-compatible RFC 1918"},

		// The mapped form, which Unmap rewrites before the checks run.
		{"::ffff:127.0.0.1", "IPv4-mapped loopback"},
		{"::ffff:169.254.169.254", "IPv4-mapped cloud metadata"},

		// RFC 2765's IPv4-translated form, ::ffff:0:a.b.c.d. Sixteen bits
		// longer than the mapped form above and therefore a different prefix,
		// which is how it stayed out of this list while its neighbour was in
		// it. A stock Linux stack does not route it, so nothing broke while it
		// was missing — the reason it is here is that a deny list is worth
		// only its completeness, and "not exploitable on the kernel we happen
		// to run" is a property of the kernel rather than of this code.
		{"::ffff:0:7f00:1", "IPv4-translated loopback, RFC 2765"},
		{"::ffff:0:a9fe:a9fe", "IPv4-translated cloud metadata, RFC 2765"},

		// Teredo carries the client's IPv4 address in its low thirty-two bits
		// and its server's in bits 32 to 63. Both are attacker-chosen.
		{"2001:0:4136:e378:8000:63bf:3fff:fdd2", "Teredo"},
		{"2001::1", "Teredo prefix"},

		// The rest of IANA's special-purpose block, caught by the same /23.
		{"2001:2::1", "benchmarking"},
		{"2001:3::1", "AMT"},
		{"2001:4:112::1", "AS112-v6"},
		{"2001:10::1", "ORCHID, deprecated"},
		{"2001:20::1", "ORCHIDv2"},
		{"2001:30::1", "DRIP"},

		// 6to4 and NAT64 embed IPv4 at fixed offsets.
		{"2002:7f00:1::1", "6to4 wrapping loopback"},
		{"2002:a00:1::1", "6to4 wrapping RFC 1918"},
		{"64:ff9b::7f00:1", "NAT64 wrapping loopback"},
		{"64:ff9b:1::a00:1", "local-use NAT64 wrapping RFC 1918"},

		// Documentation and discard ranges: nothing is reachable there, so a
		// request naming one is either a mistake or a probe.
		{"2001:db8::1", "documentation"},
		{"3fff::1", "documentation, RFC 9637"},
		{"100::1", "discard-only"},
		{"5f00::1", "SRv6 segment identifier"},
	}

	for _, tc := range blocked {
		addr, err := netip.ParseAddr(tc.addr)
		if err != nil {
			t.Fatalf("test data is wrong: cannot parse %q: %v", tc.addr, err)
		}
		if err := CheckAddr(addr); err == nil {
			t.Errorf("CheckAddr(%s) allowed the connection; expected it blocked (%s)", tc.addr, tc.why)
		}
	}
}

// The block above is wide, so this pins the other edge of it.
//
// 2001::/23 stops at 2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff. Everything from
// 2001:200:: upward is delegated to a regional registry and carries ordinary
// servers. A prefix written one bit too long here would refuse a large part
// of the IPv6 internet, and the refusal would read as a target being
// unreachable rather than as a fault in this list.
func TestSpecialPurposeBlockDoesNotReachDelegatedSpace(t *testing.T) {
	allowed := []struct {
		addr string
		what string
	}{
		{"2001:200::1", "APNIC, the first address above the special-purpose block"},
		{"2001:470:1f0b::1", "Hurricane Electric"},
		{"2001:4860:4860::8888", "Google"},
		{"2606:4700:4700::1111", "Cloudflare"},
		{"2a00:1450:4001::1", "Google, Europe"},
		{"2620:fe::fe", "Quad9"},
	}

	for _, tc := range allowed {
		addr, err := netip.ParseAddr(tc.addr)
		if err != nil {
			t.Fatalf("test data is wrong: cannot parse %q: %v", tc.addr, err)
		}
		if err := CheckAddr(addr); err != nil {
			t.Errorf("CheckAddr(%s) blocked %s: %v", tc.addr, tc.what, err)
		}
	}
}
