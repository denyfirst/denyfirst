package tlsprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/safedial"
)

// Go writes network errors for an operator reading a terminal, so they name
// whatever helps there: the resolver this machine uses, the address that was
// dialled, sometimes a socket path. None of that belongs in a reply to a
// stranger, and the way it used to arrive was by being passed through
// unexamined in the default branch.
//
// The rule is that every branch returns a phrase written here. This checks the
// consequence rather than the rule: whatever goes in, nothing recognisable
// comes out.
func TestHandshakeErrorsCarryNoInfrastructure(t *testing.T) {
	// Shapes taken from real failures, with the details that must not survive.
	cases := []error{
		errors.New(`safedial: resolve "example.test": lookup example.test on 185.12.64.2:53: no such host`),
		errors.New(`safedial: connect "example.test:443": dial tcp 203.0.113.7:443: i/o timeout`),
		errors.New(`dial tcp 198.51.100.9:443: connect: connection refused`),
		errors.New(`dial tcp [2001:db8::1]:443: connect: network is unreachable`),
		errors.New(`lookup example.test on 127.0.0.53:53: server misbehaving`),
		errors.New(`read tcp 10.0.0.4:51234->203.0.113.7:443: read: connection reset by peer`),
		errors.New(`open /etc/letsencrypt/live/example/privkey.pem: permission denied`),
		fmt.Errorf("%w: 10.0.0.1 is private", safedial.ErrBlocked),
		context.DeadlineExceeded,
		context.Canceled,
		errors.New("some failure nobody has seen before"),
	}

	// Anything that describes this machine, the network path, or the
	// filesystem. A port number on its own is harmless; an address is not.
	forbidden := []string{
		"185.12.64.2", "127.0.0.53", "203.0.113.7", "198.51.100.9",
		"10.0.0.1", "10.0.0.4", "2001:db8",
		":53", "->", "/etc/", "privkey",
		"lookup", "dial tcp", "read tcp", "connect:", "safedial",
	}

	for _, err := range cases {
		got := classifyHandshakeError(err, 0x0304)

		if got == "" {
			t.Errorf("classifyHandshakeError(%v) returned nothing; a reader is left with a silent gap", err)
			continue
		}
		for _, leak := range forbidden {
			if strings.Contains(got, leak) {
				t.Errorf("classifyHandshakeError(%v)\n  = %q\n  contains %q, which describes this machine rather than the target",
					err, got, leak)
			}
		}
	}
}

// The distinction that matters most in a report: our own client declining to
// offer a version is not the server refusing it, and conflating the two turns
// a limitation of this tool into a claim about somebody else's server.
func TestClientRefusalIsNotServerRefusal(t *testing.T) {
	ours := classifyHandshakeError(
		errors.New("tls: no supported versions satisfy MinVersion and MaxVersion"), 0x0301)
	if !strings.Contains(ours, "not tested") {
		t.Errorf("a refusal by our own client reads as %q; it must say the version was not tested", ours)
	}

	theirs := classifyHandshakeError(
		errors.New("remote error: tls: protocol version not supported"), 0x0301)
	if !strings.Contains(theirs, "server refused") {
		t.Errorf("a refusal by the server reads as %q", theirs)
	}
}

// Each shape gets its own phrase. A reader who sees "could not be
// established" for a timeout and for a refusal learns nothing from either.
func TestCommonFailuresAreDistinguished(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"timeout":      {errors.New("dial tcp 203.0.113.7:443: i/o timeout"), "timed out"},
		"refused":      {errors.New("dial tcp 203.0.113.7:443: connect: connection refused"), "refused"},
		"no such host": {errors.New(`lookup nowhere.test on 1.1.1.1:53: no such host`), "did not resolve"},
		"unreachable":  {errors.New("dial tcp 203.0.113.7:443: connect: network is unreachable"), "could not be reached"},
		"reset":        {errors.New("read tcp: connection reset by peer"), "closed during the handshake"},
		"not tls":      {errors.New("tls: first record does not look like a TLS handshake"), "not TLS"},
		"blocked":      {fmt.Errorf("%w: 127.0.0.1 is loopback", safedial.ErrBlocked), "not scanned"},
	}

	for name, tc := range cases {
		got := classifyHandshakeError(tc.err, 0x0303)
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: got %q, want it to mention %q", name, got, tc.want)
		}
	}
}

// End to end: a probe of a name that does not resolve must produce a report
// whose every field is safe to publish. This is the path the endpoint returns
// verbatim, so it is the one worth checking against the real thing rather
// than against a constructed error.
func TestReportFromAFailedProbeNamesNoAddress(t *testing.T) {
	p := &Prober{
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, errors.New(
				`safedial: resolve "nowhere.test": lookup nowhere.test on 185.12.64.2:53: no such host`)
		},
	}

	report, err := p.Probe(context.Background(), "nowhere.test", "443")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	for _, v := range report.Versions {
		if v.Error == "" {
			t.Errorf("%s failed without saying why", v.Name)
		}
		for _, leak := range []string{"185.12.64.2", ":53", "lookup", "safedial"} {
			if strings.Contains(v.Error, leak) {
				t.Errorf("%s error %q contains %q", v.Name, v.Error, leak)
			}
		}
	}
}
