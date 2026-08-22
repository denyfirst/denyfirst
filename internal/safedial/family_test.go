package safedial

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
)

// "Unreachable" and "unreachable from here" are different findings.
//
// A name that publishes only AAAA records is unreachable from a host with no
// IPv6 route however healthy the server is, and the report said the host
// could not be reached — which is a statement about somebody else's server
// arrived at from a fact about this scanner. R3 requires the opposite.
func TestASingleFamilyIsNamedAndAMixedOneIsNot(t *testing.T) {
	addr := netip.MustParseAddr

	cases := map[string]struct {
		attempted []netip.Addr
		want      string
	}{
		"only v6": {
			[]netip.Addr{addr("2606:4700::1111"), addr("2606:4700::1001")}, "IPv6",
		},
		"only v4": {
			[]netip.Addr{addr("198.51.100.7")}, "IPv4",
		},
		"both": {
			[]netip.Addr{addr("198.51.100.7"), addr("2606:4700::1111")}, "",
		},
		"nothing was tried": {
			nil, "",
		},
		// The dialler unmaps before the policy check, so a v4-mapped address
		// is the IPv4 address it is. Counting it as IPv6 would name the
		// family that was not tried.
		"v4 written as v6": {
			[]netip.Addr{addr("::ffff:198.51.100.7")}, "IPv4",
		},
	}

	for name, tc := range cases {
		if got := soleFamily(tc.attempted); got != tc.want {
			t.Errorf("%s: soleFamily = %q, want %q", name, got, tc.want)
		}
	}
}

// The wrapper has to stay transparent. A caller that unwraps for the real
// failure, or asks whether policy refused the destination, must get the same
// answer it did before this type existed.
func TestTheFamilyWrapperHidesNothing(t *testing.T) {
	inner := fmt.Errorf("safedial: connect %q: %w", "example.test:443", errors.New("network is unreachable"))
	wrapped := &SingleFamilyError{Family: "IPv6", Err: inner}

	if !errors.Is(wrapped, inner) {
		t.Error("the underlying failure cannot be recovered through the wrapper")
	}
	if wrapped.Error() != inner.Error() {
		t.Errorf("the wrapper changed the message:\n  %q\n  %q", wrapped.Error(), inner.Error())
	}
	if errors.Is(wrapped, ErrBlocked) {
		t.Error("a network failure now reads as a policy refusal")
	}
}
