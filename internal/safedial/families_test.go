package safedial

import (
	"net/netip"
	"testing"
)

func addrs(t *testing.T, list ...string) []netip.Addr {
	t.Helper()

	out := make([]netip.Addr, 0, len(list))
	for _, s := range list {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("test data is wrong: cannot parse %q: %v", s, err)
		}
		out = append(out, a)
	}
	return out
}

func families(list []netip.Addr) (v4, v6 int) {
	for _, a := range list {
		if a.Unmap().Is4() {
			v4++
		} else {
			v6++
		}
	}
	return v4, v6
}

// A budget spent entirely on one family is a report that blames the wrong
// party.
//
// The cap on attempted addresses is there so one hostname cannot consume the
// whole time budget. Applied to the resolver's order as it arrives, it can take
// eight addresses of a single family — and a host with no route for that family
// then fails every attempt, reports the target as unreachable, and tells the
// person reading the report that a working server is down.
//
// This is the case that produces it: a content network answering with far more
// AAAA records than A, scanned from a machine with no IPv6 route.
func TestBudgetIsNotSpentOnOneFamily(t *testing.T) {
	list := addrs(t,
		"2606:4700::1", "2606:4700::2", "2606:4700::3", "2606:4700::4",
		"2606:4700::5", "2606:4700::6", "2606:4700::7", "2606:4700::8",
		"104.16.0.1", "104.16.0.2",
	)

	got, truncated := interleaveFamilies(list, 8)

	if !truncated {
		t.Error("ten addresses into a budget of eight was not reported as truncated")
	}
	if len(got) != 8 {
		t.Fatalf("returned %d addresses, want 8", len(got))
	}

	v4, v6 := families(got)
	if v4 == 0 {
		t.Error("no IPv4 address survived the cut; a host without IPv6 would report this target unreachable")
	}
	if v6 == 0 {
		t.Error("no IPv6 address survived the cut; the same failure in the other direction")
	}
	if v4 != 2 || v6 != 6 {
		t.Errorf("kept %d IPv4 and %d IPv6; both available addresses of the smaller family should be kept", v4, v6)
	}
}

// A resolver that rotates its records is doing load balancing, and reordering
// within a family would quietly undo it.
func TestOrderWithinAFamilyIsKept(t *testing.T) {
	list := addrs(t,
		"2606:4700::1", "104.16.0.1", "2606:4700::2", "104.16.0.2",
		"2606:4700::3", "104.16.0.3", "2606:4700::4", "104.16.0.4",
		"2606:4700::5", "104.16.0.5",
	)

	got, _ := interleaveFamilies(list, 6)

	var seen4, seen6 []string
	for _, a := range got {
		if a.Unmap().Is4() {
			seen4 = append(seen4, a.String())
		} else {
			seen6 = append(seen6, a.String())
		}
	}

	for i, want := range []string{"104.16.0.1", "104.16.0.2", "104.16.0.3"} {
		if i < len(seen4) && seen4[i] != want {
			t.Errorf("IPv4 position %d is %s, want %s", i, seen4[i], want)
		}
	}
	for i, want := range []string{"2606:4700::1", "2606:4700::2", "2606:4700::3"} {
		if i < len(seen6) && seen6[i] != want {
			t.Errorf("IPv6 position %d is %s, want %s", i, seen6[i], want)
		}
	}
}

// The common cases, which must not be disturbed by the uncommon one.
func TestInterleaveLeavesOrdinaryListsAlone(t *testing.T) {
	t.Run("under the limit is returned unchanged", func(t *testing.T) {
		list := addrs(t, "2606:4700::1", "104.16.0.1")
		got, truncated := interleaveFamilies(list, 8)

		if truncated {
			t.Error("a list under the limit was reported as truncated")
		}
		if len(got) != len(list) {
			t.Fatalf("returned %d addresses, want %d", len(got), len(list))
		}
		for i := range list {
			if got[i] != list[i] {
				t.Errorf("position %d changed from %s to %s", i, list[i], got[i])
			}
		}
	})

	t.Run("one family only is cut in resolver order", func(t *testing.T) {
		list := addrs(t,
			"104.16.0.1", "104.16.0.2", "104.16.0.3", "104.16.0.4",
			"104.16.0.5", "104.16.0.6", "104.16.0.7", "104.16.0.8",
			"104.16.0.9",
		)

		got, truncated := interleaveFamilies(list, 8)

		if !truncated {
			t.Error("nine addresses into a budget of eight was not reported as truncated")
		}
		if len(got) != 8 {
			t.Fatalf("returned %d addresses, want 8", len(got))
		}
		// Alternating with an empty family is the same list back again, so the
		// resolver's order must survive intact.
		for i := 0; i < 8; i++ {
			if got[i] != list[i] {
				t.Errorf("position %d changed from %s to %s", i, list[i], got[i])
			}
		}
	})

	t.Run("a single address of the smaller family is kept", func(t *testing.T) {
		list := []netip.Addr{addrs(t, "104.16.0.1")[0]}
		for i := 1; i <= 20; i++ {
			list = append(list, netip.AddrFrom16([16]byte{
				0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i),
			}))
		}

		got, _ := interleaveFamilies(list, 8)

		if v4, _ := families(got); v4 != 1 {
			t.Errorf("kept %d IPv4 addresses out of one available; the only reachable address was dropped", v4)
		}
	})
}
