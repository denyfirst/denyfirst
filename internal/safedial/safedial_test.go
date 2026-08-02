package safedial

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
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

func TestDefaults(t *testing.T) {
	zero := &Dialer{}

	if got := zero.perAttemptTimeout(); got != defaultTimeout {
		t.Errorf("perAttemptTimeout() = %v, want %v", got, defaultTimeout)
	}
	if got := zero.totalTimeout(); got != defaultTotalTimeout {
		t.Errorf("totalTimeout() = %v, want %v", got, defaultTotalTimeout)
	}
	if got := zero.maxAddrs(); got != defaultMaxAddrs {
		t.Errorf("maxAddrs() = %v, want %v", got, defaultMaxAddrs)
	}

	set := &Dialer{Timeout: time.Second, TotalTimeout: 2 * time.Second, MaxAddrs: 3}

	if got := set.perAttemptTimeout(); got != time.Second {
		t.Errorf("perAttemptTimeout() = %v, want 1s", got)
	}
	if got := set.totalTimeout(); got != 2*time.Second {
		t.Errorf("totalTimeout() = %v, want 2s", got)
	}
	if got := set.maxAddrs(); got != 3 {
		t.Errorf("maxAddrs() = %v, want 3", got)
	}
}

// blockingResolver never answers, so a lookup through it can only end when a
// deadline fires. Timing tests that rely on a real lookup being slow are not
// tests: a warm CI runner resolves and connects in twenty milliseconds, and
// the assertion silently inverts.
func blockingResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
}

// A caller with a tighter deadline than TotalTimeout must not have it
// extended. This is the property that lets an HTTP handler bound the whole
// request regardless of how the dialer is configured.
//
// If TotalTimeout won, this test would hang for an hour and the Go test
// timeout would kill the run, which is a failure either way.
func TestCallerDeadlineWins(t *testing.T) {
	d := &Dialer{TotalTimeout: time.Hour, Resolver: blockingResolver()}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := d.DialContext(ctx, "tcp", "unreachable.test:443")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("dial succeeded against a resolver that never answers")
	}
	if elapsed > 5*time.Second {
		t.Errorf("dial took %v; the caller's 100ms deadline was not honoured", elapsed)
	}
}

// TotalTimeout must bound the operation when the caller sets no deadline of
// its own. Without it, a per-attempt timeout multiplies by the number of
// addresses tried.
func TestTotalTimeoutBoundsTheOperation(t *testing.T) {
	d := &Dialer{
		Timeout:      time.Hour, // deliberately useless as a bound
		TotalTimeout: 150 * time.Millisecond,
		Resolver:     blockingResolver(),
	}

	start := time.Now()
	_, err := d.DialContext(context.Background(), "tcp", "unreachable.test:443")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("dial succeeded against a resolver that never answers")
	}
	if elapsed > 5*time.Second {
		t.Errorf("dial took %v; TotalTimeout of 150ms did not bound it", elapsed)
	}
}

// An already-expired context must be refused before any network activity.
func TestExpiredContextIsRefused(t *testing.T) {
	d := &Dialer{}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	if _, err := d.DialContext(ctx, "tcp", "example.com:443"); err == nil {
		t.Error("DialContext succeeded with a context whose deadline had already passed")
	}
}

func TestRejectsNonTCP(t *testing.T) {
	d := &Dialer{}
	if _, err := d.DialContext(context.Background(), "udp", "example.com:53"); err == nil {
		t.Error("DialContext accepted a udp network")
	} else if !errors.Is(err, ErrBlocked) {
		t.Errorf("got %v; expected it to wrap ErrBlocked", err)
	}
}

func TestTruncNote(t *testing.T) {
	if got := truncNote(false, 8); got != "" {
		t.Errorf("truncNote(false, 8) = %q, want empty", got)
	}
	if got := truncNote(true, 8); got == "" {
		t.Error("truncNote(true, 8) returned nothing; a partial result must be explained")
	}
}
