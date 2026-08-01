package safedial

import (
	"errors"
	"net/netip"
	"testing"
)

func TestCheckAddrBlocks(t *testing.T) {
	blocked := []struct {
		addr string
		why  string
	}{
		{"127.0.0.1", "loopback"},
		{"127.0.0.53", "loopback, systemd-resolved"},
		{"0.0.0.0", "unspecified"},
		{"10.0.0.1", "RFC 1918"},
		{"172.16.0.1", "RFC 1918"},
		{"172.31.255.254", "RFC 1918 upper bound"},
		{"192.168.1.1", "RFC 1918"},
		{"169.254.169.254", "cloud metadata endpoint"},
		{"169.254.1.1", "link-local"},
		{"100.64.0.1", "carrier-grade NAT"},
		{"192.0.2.1", "TEST-NET-1"},
		{"198.18.0.1", "benchmarking"},
		{"198.51.100.1", "TEST-NET-2"},
		{"203.0.113.1", "TEST-NET-3"},
		{"224.0.0.1", "multicast"},
		{"255.255.255.255", "broadcast"},
		{"240.0.0.1", "reserved"},

		{"::1", "IPv6 loopback"},
		{"::", "IPv6 unspecified"},
		{"fc00::1", "IPv6 unique local"},
		{"fd00::1", "IPv6 unique local"},
		{"fe80::1", "IPv6 link-local"},
		{"ff02::1", "IPv6 multicast"},
		{"2001:db8::1", "documentation"},
		{"2002::1", "6to4"},
		{"64:ff9b::1", "NAT64"},

		// The bypasses that matter: an IPv4 address wearing an IPv6 costume.
		{"::ffff:127.0.0.1", "IPv4-mapped loopback"},
		{"::ffff:10.0.0.1", "IPv4-mapped RFC 1918"},
		{"::ffff:169.254.169.254", "IPv4-mapped metadata endpoint"},
	}

	for _, tc := range blocked {
		addr, err := netip.ParseAddr(tc.addr)
		if err != nil {
			t.Fatalf("test data is wrong: cannot parse %q: %v", tc.addr, err)
		}
		if err := CheckAddr(addr); err == nil {
			t.Errorf("CheckAddr(%s) allowed the connection; expected it blocked (%s)", tc.addr, tc.why)
		} else if !errors.Is(err, ErrBlocked) {
			t.Errorf("CheckAddr(%s) returned %v; expected it to wrap ErrBlocked", tc.addr, err)
		}
	}
}

func TestCheckAddrAllows(t *testing.T) {
	allowed := []string{
		"1.1.1.1",
		"8.8.8.8",
		"93.184.216.34",
		"167.233.210.46",
		"2606:4700:4700::1111",
		"2001:4860:4860::8888",
	}

	for _, s := range allowed {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("test data is wrong: cannot parse %q: %v", s, err)
		}
		if err := CheckAddr(addr); err != nil {
			t.Errorf("CheckAddr(%s) blocked a public address: %v", s, err)
		}
	}
}

func TestCheckHost(t *testing.T) {
	bad := []string{
		"",
		"exa mple.com",
		"example.com\n",
		"example.com\x00.evil.test",
	}
	for _, host := range bad {
		if err := checkHost(host); err == nil {
			t.Errorf("checkHost(%q) accepted malformed input", host)
		}
	}

	if err := checkHost("example.com"); err != nil {
		t.Errorf("checkHost rejected a normal hostname: %v", err)
	}
}

func TestPortAllowList(t *testing.T) {
	d := &Dialer{AllowedPorts: []string{"443"}}

	if err := d.checkPort("443"); err != nil {
		t.Errorf("checkPort(443) rejected an allowed port: %v", err)
	}
	if err := d.checkPort("22"); err == nil {
		t.Error("checkPort(22) accepted a port outside the allow list")
	}

	open := &Dialer{}
	if err := open.checkPort("9999"); err != nil {
		t.Errorf("empty allow list should permit any port, got: %v", err)
	}
}
