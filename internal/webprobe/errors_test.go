package webprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	neturl "net/url"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/safedial"
)

// A published error names the shape of a failure and nothing else (I6).
//
// The leak arrives from the standard library rather than from any formatting
// here, which is why it was open on this probe long after the TLS one closed
// it: Go writes network errors for an operator reading a terminal, so a DNS
// failure names the resolver it asked, and that resolver belongs to whoever
// runs this machine. safedial's refusals name the address they rejected.
// Both were reaching Hop.Err, which is serialised into a report — read by an
// operator on the command line, and by a stranger the day this check has an
// address on the service.
func TestAFailedHopNamesNoInfrastructure(t *testing.T) {
	// Each of these is a real failure this probe can meet, written the way
	// the library writes it.
	for _, tc := range []struct {
		name string
		err  error
	}{
		{
			"a resolver naming itself",
			&net.DNSError{Err: "no such host", Name: "example.com", Server: "10.0.0.1:53", IsNotFound: true},
		},
		{
			"safedial naming the address it refused",
			fmt.Errorf("%w: 127.0.0.1 is loopback", safedial.ErrBlocked),
		},
		{
			"safedial naming a reserved range",
			fmt.Errorf("%w: 169.254.169.254 is inside reserved range 169.254.0.0/16", safedial.ErrBlocked),
		},
		{
			"a dial naming the address and the port",
			errors.New("dial tcp 192.0.2.7:443: connect: connection refused"),
		},
		{
			// The branch that matters most, because it is the one nobody has
			// reviewed: a failure worded in a way none of the tests below
			// anticipated still must not be passed through.
			"a failure nothing here recognises",
			errors.New("dial tcp 192.0.2.7:443: lookup failed reading /etc/resolv.conf"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Wrapped the way http.Client wraps everything, so the test reads
			// what a hop actually receives.
			wrapped := &neturl.Error{Op: "Get", URL: "https://example.com:443/", Err: tc.err}

			text, _ := classifyProbeError(wrapped)

			if text == "" {
				t.Fatal("a failed hop with no reason is a hop a reader cannot interpret")
			}
			for _, leak := range []string{
				"10.0.0.1", "127.0.0.1", "169.254", "192.0.2.7", "resolv.conf", "/etc/",
			} {
				if strings.Contains(text, leak) {
					t.Errorf("the phrase carries %q, which describes this machine rather than the failure: %s",
						leak, text)
				}
			}
			// Nothing is passed through, so the library's own wording cannot
			// appear even where it happens to be harmless. A pass-through
			// that is safe today is one nobody re-reads when the library
			// changes its mind.
			if strings.Contains(text, tc.err.Error()) {
				t.Errorf("the underlying error was passed through: %s", text)
			}
		})
	}
}

// A destination this service refuses is a fact a caller can count, not a
// phrase to be matched (A7).
//
// blocked_destination was declared, documented as the signal that somebody is
// aiming this service at the network it runs in, and permanently zero on the
// TLS check until the field existed. Adding an entry point for the web check
// without it would be that defect rebuilt on a new endpoint.
func TestANameThatResolvesOnlyWhereWeWillNotGoIsRecordedAsBlocked(t *testing.T) {
	p := &Prober{
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, fmt.Errorf("%w: 127.0.0.1 is loopback", safedial.ErrBlocked)
		},
		RequestTimeout: 2 * time.Second,
		TotalTimeout:   8 * time.Second,
	}

	report, err := p.Probe(context.Background(), "internal.example", nil)
	if err != nil {
		t.Fatalf("Probe returned %v; a refused destination is a finding, not an error", err)
	}
	if !report.BlockedDestination {
		t.Error("every attempt was refused by safedial and the report does not say so; " +
			"the reason would be in the prose and never in the numbers")
	}
	for _, c := range []*Chain{report.Secure, report.Plain} {
		if got := c.Final().Err; strings.Contains(got, "127.0.0.1") {
			t.Errorf("the recorded reason repeats the address that was refused: %s", got)
		}
	}
}

// The other direction, and the one that would turn a measurement into a
// refusal: a name reached on one port has been reached.
//
// Written because "every hop was blocked" and "some hop was blocked" pass the
// test above identically, and only the first is true of a destination this
// service will not go to. A host answering on 443 with nothing on 80 is an
// ordinary and correct arrangement.
func TestANameReachedOnOnePortIsNotABlockedDestination(t *testing.T) {
	p := &Prober{
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			if strings.HasSuffix(address, ":80") {
				return nil, fmt.Errorf("%w: 127.0.0.1 is loopback", safedial.ErrBlocked)
			}
			return nil, errors.New("connect: connection refused")
		},
		RequestTimeout: 2 * time.Second,
		TotalTimeout:   8 * time.Second,
	}

	report, err := p.Probe(context.Background(), "half.example", nil)
	if err != nil {
		t.Fatalf("Probe returned %v", err)
	}
	if report.BlockedDestination {
		t.Error("one port refused and the other reached was reported as a destination this service " +
			"will not connect to, which would answer a caller with a refusal instead of a measurement")
	}
}

// A report with no hops at all has established nothing, and nothing is not
// the same as a refusal (R4). Reached through the helper rather than through
// Probe, which always attempts two chains.
func TestNoHopsIsNotABlockedDestination(t *testing.T) {
	if blockedDestination() {
		t.Error("a report with no chains was called a blocked destination")
	}
	if blockedDestination(nil, nil) {
		t.Error("two absent chains were called a blocked destination")
	}
	if blockedDestination(&Chain{}) {
		t.Error("a chain with no hops was called a blocked destination")
	}
}

// A hop that was refused by policy is not a hop that failed on the network,
// and the two are counted differently. This is the pair of facts the flag
// carries, checked at the point it is decided.
func TestOnlyAPolicyRefusalSetsTheBlockedFlag(t *testing.T) {
	if _, blocked := classifyProbeError(fmt.Errorf("%w: 127.0.0.1 is loopback", safedial.ErrBlocked)); !blocked {
		t.Error("safedial's refusal was not recorded as one")
	}
	for _, err := range []error{
		errors.New("connect: connection refused"),
		errors.New("i/o timeout"),
		context.DeadlineExceeded,
	} {
		if _, blocked := classifyProbeError(err); blocked {
			t.Errorf("%v was recorded as a policy refusal; a server that is simply down would then be "+
				"answered as a destination this service will not connect to", err)
		}
	}
}

// A refusal by policy is recognised by what it is, not by how it reads.
//
// Written because a sabotage escaped: moving the safedial branch below the
// message tests changed nothing, so nothing held it in place. Investigation
// says the ordering is not load-bearing today — no message ErrBlocked carries
// contains a phrase an earlier branch matches, and safedial builds
// SingleFamilyError only on the dial-error path, so a blocked error is never
// also a single-family one. That is a fact about safedial's current wording
// rather than a property of this function, and it is exactly the kind of fact
// that changes without anyone noticing it was being relied on.
//
// So the ordering is pinned here instead. Each of these carries a message that
// would match a later branch if it were reached first; all of them are
// refusals, and all of them must be answered as refusals.
func TestAPolicyRefusalIsRecognisedWhateverItSays(t *testing.T) {
	for _, msg := range []string{
		"127.0.0.1 is loopback",
		`"internal.example" has no usable public address`,
		"port \"22\" is not in the allow list",

		// Deliberately worded like the failures the other branches catch. A
		// refusal that reads like a timeout is still a refusal, and answering
		// it as a timeout would tell an operator the network was slow when
		// what happened is that this service declined to go there.
		"no such host",
		"i/o timeout",
		"connection refused",
		"network is unreachable",
		"EOF",
		"tls: handshake failure",
	} {
		err := fmt.Errorf("%w: %s", safedial.ErrBlocked, msg)

		text, blocked := classifyProbeError(err)
		if !blocked {
			t.Errorf("a refusal reading %q was not recorded as one; the count that tells an operator "+
				"somebody is aiming this service at its own network would miss it", msg)
		}
		if !strings.Contains(text, "not a destination the service will connect to") {
			t.Errorf("a refusal reading %q was answered with %q", msg, text)
		}
	}
}
