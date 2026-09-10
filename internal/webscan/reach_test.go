package webscan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/verify"
	"github.com/denyfirst/denyfirst/internal/webprobe"
)

// A redirect is a host the server chose, and Scan's three guards authorised
// the host the operator chose. These are the tests that the second host is put
// to the same three questions as the first.

// redirector answers the name it was built to redirect and 200 for anything
// else, sending every connection to one listener whatever name was dialled.
//
// Two httptest servers are two ports on one host, so a name-shaped boundary
// cannot be measured against them. The names below never resolve.
type redirector struct {
	from, to string

	mu     sync.Mutex
	dialed []string
}

func (d *redirector) start(t *testing.T) *webprobe.Prober {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Probe builds its starting addresses with an explicit port, and Go
		// sends the Host header the URL carries, port and all.
		if nameOf(r.Host) == d.from {
			w.Header().Set("Location", d.to)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	addr := srv.Listener.Addr().String()
	return &webprobe.Prober{
		Dial: func(ctx context.Context, network, asked string) (net.Conn, error) {
			d.mu.Lock()
			d.dialed = append(d.dialed, asked)
			d.mu.Unlock()

			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
		RequestTimeout: 5 * time.Second,
		TotalTimeout:   15 * time.Second,
	}
}

func (d *redirector) reached(host string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, addr := range d.dialed {
		if h, _, err := net.SplitHostPort(addr); err == nil && h == host {
			return true
		}
	}
	return false
}

// nameOf drops a port from a Host header, if one is there.
func nameOf(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// stopped is every reason a chain in this result gave for not going on.
func stopped(r *Result) []string {
	var out []string
	for _, c := range []*webprobe.Chain{r.Observed.Secure, r.Observed.Plain} {
		if c != nil && c.Stopped != "" {
			out = append(out, c.Stopped)
		}
	}
	return out
}

// The exclusion list holds at a redirect, not only at the front door.
func TestARedirectToAnExcludedDomainIsNotFollowed(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build refuses the starting name before any of this")
	}

	// army.mil is on the list. Typed, it is refused; until the boundary was
	// asked at the hop, a Location header reached it.
	d := &redirector{from: "example.test", to: "http://army.mil/"}
	s := &Scanner{Prober: d.start(t)}

	result, err := s.Scan(context.Background(), "example.test")
	if err != nil {
		t.Fatalf("Scan returned %v", err)
	}

	if d.reached("army.mil") {
		t.Error("a redirect carried this scanner to a name on the exclusion list. The list " +
			"says what this project will not touch whoever asks (N8), and a server that " +
			"answers a redirect is somebody asking")
	}
	if len(stopped(result)) == 0 {
		t.Error("the chain declined to follow and recorded no reason")
	}
}

// The verified zone holds at a redirect.
func TestARedirectOutOfTheVerifiedZoneIsNotFollowed(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build refuses these names before the scope is reached")
	}

	secret := []byte("a deployment secret")
	d := &redirector{from: "proven.test", to: "http://somewhere-else.test/"}

	s := &Scanner{
		Prober: d.start(t),
		Verify: &verify.Scope{Secret: secret, Resolver: oneDomain{secret: secret, name: "proven.test"}},
	}

	result, err := s.Scan(context.Background(), "proven.test")
	if err != nil {
		t.Fatalf("Scan returned %v", err)
	}

	if d.reached("somewhere-else.test") {
		t.Error("one Location header on a site this deployment does own walked it out of " +
			"its own estate. Proof of control is proof about a zone, and the host a " +
			"redirect names is outside it until the same question is asked again")
	}
	if len(stopped(result)) == 0 {
		t.Error("the chain declined to follow and recorded no reason")
	}
}

// And inside the zone it is followed, or the boundary is a wall.
func TestARedirectInsideTheVerifiedZoneIsFollowed(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build refuses these names before the scope is reached")
	}

	secret := []byte("a deployment secret")
	d := &redirector{from: "proven.test", to: "http://www.proven.test/"}

	s := &Scanner{
		Prober: d.start(t),
		Verify: &verify.Scope{Secret: secret, Resolver: oneDomain{secret: secret, name: "proven.test"}},
	}

	if _, err := s.Scan(context.Background(), "proven.test"); err != nil {
		t.Fatalf("Scan returned %v", err)
	}

	if !d.reached("www.proven.test") {
		t.Error("a redirect within a zone this deployment proved control of was not " +
			"followed. A record at proven.test covers www.proven.test, and an operator " +
			"who published it and still gets half a report reads it as a fault in their DNS")
	}
}

// A boundary that cannot be asked stops the chain rather than opening it.
func TestARedirectIsNotFollowedWhenTheBoundaryCannotBeAsked(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build refuses these names before the scope is reached")
	}

	secret := []byte("a deployment secret")
	d := &redirector{from: "proven.test", to: "http://somewhere-else.test/"}

	s := &Scanner{
		Prober: d.start(t),
		Verify: &verify.Scope{
			Secret:   secret,
			Resolver: provenThenSilent{secret: secret, name: "proven.test"},
		},
	}

	if _, err := s.Scan(context.Background(), "proven.test"); err != nil {
		t.Fatalf("Scan returned %v", err)
	}

	if d.reached("somewhere-else.test") {
		t.Error("a resolver that would not answer opened the boundary. A guard that gives " +
			"way whenever a lookup is slow is a guard somebody can arrange to be slow")
	}
}

// The reason is a sentence about the rule, and the address is in the header.
func TestTheRedirectRefusalNamesNoHost(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build refuses these names before the scope is reached")
	}

	secret := []byte("a deployment secret")
	d := &redirector{from: "proven.test", to: "http://somewhere-else.test/"}

	s := &Scanner{
		Prober: d.start(t),
		Verify: &verify.Scope{Secret: secret, Resolver: oneDomain{secret: secret, name: "proven.test"}},
	}

	result, err := s.Scan(context.Background(), "proven.test")
	if err != nil {
		t.Fatalf("Scan returned %v", err)
	}

	reasons := stopped(result)
	if len(reasons) == 0 {
		t.Fatal("nothing was recorded about why the chain stopped")
	}
	for _, why := range reasons {
		if strings.Contains(why, "somewhere-else") {
			t.Errorf("the reason repeats the address back into the report (I3): %q", why)
		}
	}
}

// provenThenSilent proves one domain and refuses to answer about any other, so
// a test can drive the difference between "not verified" and "not asked".
type provenThenSilent struct {
	secret []byte
	name   string
}

func (p provenThenSilent) LookupChallenge(_ context.Context, name string) ([]string, bool, error) {
	if name == verify.Label+"."+p.name {
		return []string{verify.Token(p.secret, p.name)}, true, nil
	}
	return nil, false, errSilentResolver
}

var errSilentResolver = errResolver("the resolver did not answer")

type errResolver string

func (e errResolver) Error() string { return string(e) }
