package tlsprobe

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/policy"
)

const multiHost = "multi.example.test"

// listener is a local TLS server, optionally limited to one version.
func listener(t *testing.T, maxVersion uint16) (addr string, stop func()) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = &tls.Config{MaxVersion: maxVersion}
	srv.StartTLS()
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		srv.Close()
		t.Fatalf("parsing the test server URL: %v", err)
	}
	return parsed.Host, srv.Close
}

// pinned is a prober for a name on the given addresses, each routed to the
// listener beside it. The name itself goes to the first listener, as a
// resolver that always answered with the first address would send it.
type pinned struct {
	mu     sync.Mutex
	dialed []string
}

func (p *pinned) prober(t *testing.T, routes map[string]string, first string, addrs ...string) *Prober {
	t.Helper()
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &Prober{
		HandshakeTimeout: 5 * time.Second,
		TotalTimeout:     30 * time.Second,
		LookupAddrs: func(context.Context, string) ([]netip.Addr, error) {
			var out []netip.Addr
			for _, a := range addrs {
				out = append(out, netip.MustParseAddr(a))
			}
			return out, nil
		},
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			p.mu.Lock()
			p.dialed = append(p.dialed, address)
			p.mu.Unlock()
			host, _, _ := net.SplitHostPort(address)
			target, ok := routes[host]
			if !ok {
				target = first
			}
			if target == "" {
				return nil, errors.New("connect: connection refused")
			}
			return d.DialContext(ctx, network, target)
		},
	}
}

func notesWith(r *Report, fragment string) []string {
	var out []string
	for _, n := range r.Notes {
		if strings.Contains(n.Text, fragment) {
			out = append(out, n.Text)
		}
	}
	return out
}

// A name on two machines that answer differently is said to, with what each
// answered — the machine the resolver did not hand the scan is not missed.
func TestAddressesThatAnswerDifferentlyAreSaidToWithWhatEachAnswered(t *testing.T) {
	modern, stopModern := listener(t, 0)
	defer stopModern()
	older, stopOlder := listener(t, tls.VersionTLS12)
	defer stopOlder()

	p := &pinned{}
	prober := p.prober(t, map[string]string{"192.0.2.1": modern, "192.0.2.2": older}, modern, "192.0.2.1", "192.0.2.2")

	report, err := prober.Probe(context.Background(), multiHost, "443")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(report.Addresses) != 2 {
		t.Fatalf("addresses %+v; the name resolves to two", report.Addresses)
	}
	byAddr := map[string]AddressAnswer{}
	for _, a := range report.Addresses {
		byAddr[a.Address] = a
	}
	if a := byAddr["192.0.2.1:443"]; !a.Answered || a.Version != "TLS 1.3" || a.Certificate == "" {
		t.Errorf("192.0.2.1: %+v", a)
	}
	if a := byAddr["192.0.2.2:443"]; !a.Answered || a.Version != "TLS 1.2" {
		t.Errorf("192.0.2.2: %+v; that machine stops at TLS 1.2", a)
	}

	notes := notesWith(report, "do not answer alike")
	if len(notes) != 1 || !strings.Contains(notes[0], "192.0.2.2:443: TLS 1.2") || !strings.Contains(notes[0], "192.0.2.1:443: TLS 1.3") {
		t.Errorf("the report does not say the machines differ and how: %v", notes)
	}
	for _, n := range report.Notes {
		if strings.Contains(n.Text, "do not answer alike") && n.Kind != policy.KindObserved {
			t.Errorf("a difference established by asking each machine is not an observation: %s", n.Kind)
		}
	}
}

// Every pinned handshake is dialled at its address, through the prober's dialler
// — the guard where the connection is made (N1) — rather than at the name.
func TestEachAddressIsDialledAsItselfThroughTheDialler(t *testing.T) {
	server, stop := listener(t, 0)
	defer stop()

	p := &pinned{}
	prober := p.prober(t, map[string]string{"192.0.2.1": server, "192.0.2.2": server}, server, "192.0.2.1", "192.0.2.2")
	if _, err := prober.Probe(context.Background(), multiHost, "443"); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, want := range []string{"192.0.2.1:443", "192.0.2.2:443"} {
		found := false
		for _, got := range p.dialed {
			found = found || got == want
		}
		if !found {
			t.Errorf("%s was never dialled; dialled %v", want, p.dialed)
		}
	}
}

// Machines that answer alike are said to, and nothing suggests otherwise.
func TestAddressesThatAnswerAlikeAreSaidToAnswerAlike(t *testing.T) {
	server, stop := listener(t, 0)
	defer stop()

	p := &pinned{}
	prober := p.prober(t, map[string]string{"192.0.2.1": server, "192.0.2.2": server}, server, "192.0.2.1", "192.0.2.2")
	report, err := prober.Probe(context.Background(), multiHost, "443")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(notesWith(report, "gave the same version, suite and certificate")) != 1 {
		t.Errorf("two machines answering alike are not said to:\n%v", report.Notes)
	}
	if len(notesWith(report, "do not answer alike")) != 0 {
		t.Error("two machines answering alike are said to differ")
	}
}

// An address that does not answer is not a machine answering differently, and
// is not established either way.
func TestAnAddressThatDoesNotAnswerIsNotEstablished(t *testing.T) {
	server, stop := listener(t, 0)
	defer stop()

	p := &pinned{}
	prober := p.prober(t, map[string]string{"192.0.2.1": server, "192.0.2.2": ""}, server, "192.0.2.1", "192.0.2.2")
	report, err := prober.Probe(context.Background(), multiHost, "443")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	notes := notesWith(report, "did not answer")
	if len(notes) != 1 || !strings.Contains(notes[0], "192.0.2.2:443 (no connection opened)") {
		t.Errorf("the silent address is not named with its reason: %v", notes)
	}
	if len(notesWith(report, "do not answer alike")) != 0 {
		t.Error("an address that did not answer is reported as answering differently")
	}
	for _, n := range report.Notes {
		if !strings.Contains(n.Text, "did not answer") {
			continue
		}
		if n.Kind != policy.KindUnsettled {
			t.Errorf("a silent address is reported as %s; nothing about that machine was established", n.Kind)
		}
		// The dialler's own words say "connection refused"; the report says a
		// fixed phrase naming nothing about this machine's network (I6).
		if strings.Contains(n.Text, "connection refused") {
			t.Errorf("the error text reached the report: %s", n.Text)
		}
	}
	for _, a := range report.Addresses {
		if strings.Contains(a.Reason, "connection refused") {
			t.Errorf("the error text reached the answer for %s: %q", a.Address, a.Reason)
		}
	}
}

// The addresses asked are the dialler's candidates, capped as it caps them, and
// the report says when there were more.
func TestTheAddressesAskedAreCappedAndTheReportSaysSo(t *testing.T) {
	server, stop := listener(t, 0)
	defer stop()

	var many []string
	for i := 1; i <= 12; i++ {
		many = append(many, netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}).String())
	}
	p := &pinned{}
	prober := p.prober(t, nil, server, many...)
	report, err := prober.Probe(context.Background(), multiHost, "443")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(report.Addresses) != 8 || !report.AddressesTruncated {
		t.Errorf("%d addresses asked (truncated %v); the dialler tries eight", len(report.Addresses), report.AddressesTruncated)
	}
	if len(notesWith(report, "only the first 8 were compared")) != 1 {
		t.Errorf("the report does not say only some addresses were compared:\n%v", report.Notes)
	}
}

// Nothing more is asked of a name with one address, or of an address given as
// the target: there is nothing to compare.
func TestOneAddressAsksNothingMore(t *testing.T) {
	server, stop := listener(t, 0)
	defer stop()

	p := &pinned{}
	prober := p.prober(t, nil, server, "192.0.2.1")
	report, err := prober.Probe(context.Background(), multiHost, "443")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(report.Addresses) != 0 {
		t.Errorf("a name with one address was asked about %v", report.Addresses)
	}

	var looked atomic.Bool
	literal := loopbackProber()
	literal.LookupAddrs = func(context.Context, string) ([]netip.Addr, error) {
		looked.Store(true)
		return nil, nil
	}
	host, port, stopLiteral := localTLSServer(t)
	defer stopLiteral()
	if _, err := literal.Probe(context.Background(), host, port); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if looked.Load() {
		t.Error("an address given as the target was looked up as a name")
	}
}

// The same address twice in an answer is one machine.
func TestAnAddressListedTwiceIsAskedOnce(t *testing.T) {
	server, stop := listener(t, 0)
	defer stop()

	p := &pinned{}
	prober := p.prober(t, nil, server, "192.0.2.1", "192.0.2.1", "::ffff:192.0.2.1")
	report, err := prober.Probe(context.Background(), multiHost, "443")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(report.Addresses) != 0 {
		t.Errorf("one address listed three ways was compared with itself: %v", report.Addresses)
	}
}

// A difference in version alone is a difference.
//
// TLS 1.0 and TLS 1.2 share suites, so two machines can give the same suite and
// the same certificate at different versions — one of them still speaking a
// version the other retired. A sabotage leaving the version out of the
// comparison escaped on 2026-09-14, because the test above differs in suite as
// well: TLS 1.3 and TLS 1.2 share none.
func TestAVersionAloneIsADifference(t *testing.T) {
	report := &Report{Addresses: []AddressAnswer{
		{Address: "192.0.2.1:443", Answered: true, Version: "TLS 1.2", Suite: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", Certificate: "ab"},
		{Address: "192.0.2.2:443", Answered: true, Version: "TLS 1.0", Suite: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", Certificate: "ab"},
	}}
	describeAddresses(report)
	if len(notesWith(report, "do not answer alike")) != 1 {
		t.Errorf("two machines at different versions are not said to differ:\n%v", report.Notes)
	}
}
