package webprobe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The first address in a chain is the operator's. Every one after it belongs
// to whoever answered, and these are the tests that the difference is honoured.

// dialLog sends every connection to one address and remembers what it was
// asked for, so a test can say what was dialled rather than what was intended.
//
// It exists because two httptest servers are two ports on 127.0.0.1, which is
// one host — and a boundary about hosts cannot be measured against that. The
// names below are fictional and never resolved; the dialler substitutes the
// server for whatever was asked.
type dialLog struct {
	to string

	mu    sync.Mutex
	asked []string
}

func (d *dialLog) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.asked = append(d.asked, addr)
	d.mu.Unlock()

	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, d.to)
}

func (d *dialLog) reached(host string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	return slices.ContainsFunc(d.asked, func(addr string) bool {
		h, _, err := net.SplitHostPort(addr)
		return err == nil && h == host
	})
}

// reachLog is a caller's boundary: it remembers what it was asked about and
// refuses whatever it was told to.
type reachLog struct {
	refuse map[string]string

	mu    sync.Mutex
	asked []string
}

func (r *reachLog) reach(_ context.Context, host string) string {
	r.mu.Lock()
	r.asked = append(r.asked, host)
	r.mu.Unlock()

	return r.refuse[host]
}

func (r *reachLog) questions(host string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := 0
	for _, h := range r.asked {
		if h == host {
			n++
		}
	}
	return n
}

// redirectingTo answers every request for from with a redirect to to, and
// everything else with 200.
func redirectingTo(from, to string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The port has to come off first. Probe builds its starting addresses
		// with an explicit one and Go sends the Host header the URL carries,
		// so a handler comparing the whole thing matches nothing and answers
		// 200 — which is a test that redirects nowhere and asserts happily
		// that nothing was refused. A sabotage found this one.
		if nameOf(r.Host) == from {
			w.Header().Set("Location", to)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
}

// nameOf drops a port from a Host header, if one is there.
func nameOf(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func proberVia(d *dialLog) *Prober {
	return &Prober{Dial: d.dial, RequestTimeout: 5 * time.Second}
}

// A redirect to a host the caller will not reach is not followed.
func TestARedirectIsNotFollowedToAHostTheCallerRefuses(t *testing.T) {
	srv := redirectingTo("start.example", "http://elsewhere.example/")
	defer srv.Close()

	d := &dialLog{to: srv.Listener.Addr().String()}
	r := &reachLog{refuse: map[string]string{
		"elsewhere.example": "the Location header named a domain this deployment does not reach",
	}}

	p := proberVia(d)
	c := p.chain(context.Background(), p.client(), "http://start.example/",
		&walk{reach: r.reach, decided: map[string]string{"start.example": ""}})

	if d.reached("elsewhere.example") {
		t.Error("the probe connected to a host the caller refused: the refusal has to come " +
			"before the connection, or this deployment's address is already in the logs of " +
			"a server nobody authorised it to touch")
	}
	if c.Stopped == "" {
		t.Error("the chain stopped and said nothing; a reader who cannot tell 'it ended here' " +
			"from 'it was not followed' cannot interpret the chain at all")
	}
	if len(c.Hops) != 1 {
		t.Errorf("recorded %d hops, want the one that produced the Location", len(c.Hops))
	}

	// The reason must not repeat the name (I3), and the reader does not need
	// it to: the Location header is one of the headers this probe keeps.
	if strings.Contains(c.Stopped, "elsewhere.example") {
		t.Errorf("the reason repeats the redirect target: %q", c.Stopped)
	}
	if got := c.Hops[0].Headers["Location"]; len(got) == 0 {
		t.Error("the Location header was not recorded, so nothing in the report says where " +
			"the chain was pointed")
	}
}

// A redirect to a host the caller allows is followed, as a browser would.
func TestARedirectIsFollowedToAHostTheCallerAllows(t *testing.T) {
	srv := redirectingTo("start.example", "http://elsewhere.example/")
	defer srv.Close()

	d := &dialLog{to: srv.Listener.Addr().String()}
	r := &reachLog{}

	p := proberVia(d)
	c := p.chain(context.Background(), p.client(), "http://start.example/",
		&walk{reach: r.reach, decided: map[string]string{"start.example": ""}})

	if !d.reached("elsewhere.example") {
		t.Error("a redirect the caller allowed was not followed; a boundary that refuses " +
			"everything is not a boundary, it is a broken check")
	}
	if c.Stopped != "" {
		t.Errorf("the chain stopped with %q", c.Stopped)
	}
	if len(c.Hops) != 2 {
		t.Errorf("recorded %d hops, want 2", len(c.Hops))
	}
}

// A nil boundary follows anything the other limits allow.
func TestANilReachFollowsAnyHost(t *testing.T) {
	srv := redirectingTo("start.example", "http://elsewhere.example/")
	defer srv.Close()

	d := &dialLog{to: srv.Listener.Addr().String()}

	p := proberVia(d)
	c := p.chain(context.Background(), p.client(), "http://start.example/", anywhere())

	if !d.reached("elsewhere.example") {
		t.Error("a probe with no boundary did not follow a redirect; that is the command " +
			"line, where the scan leaves from the operator's own machine and a browser " +
			"would have followed the same one")
	}
	if c.Stopped != "" {
		t.Errorf("the chain stopped with %q", c.Stopped)
	}
}

// The host the caller asked about is not asked about again.
func TestTheHostAskedAboutIsNotAskedAgain(t *testing.T) {
	// The commonest redirect there is: the same name, the other scheme.
	srv := redirectingTo("example.test", "https://example.test/")
	defer srv.Close()

	d := &dialLog{to: srv.Listener.Addr().String()}
	r := &reachLog{}

	p := proberVia(d)
	if _, err := p.Probe(context.Background(), "example.test", r.reach); err != nil {
		t.Fatalf("Probe returned %v", err)
	}

	if n := r.questions("example.test"); n != 0 {
		t.Errorf("the boundary was asked %d times about the host it was handed; the caller "+
			"authorised that name by asking, and asking again is a DNS lookup per scan for "+
			"an answer already given", n)
	}
}

// One question per distinct name, however many hops name it.
func TestOneQuestionPerDistinctHost(t *testing.T) {
	// elsewhere.example redirects to itself once, so the same name is the
	// target of two hops.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Host == "start.example":
			w.Header().Set("Location", "http://elsewhere.example/")
			w.WriteHeader(http.StatusFound)
		case r.Host == "elsewhere.example" && r.URL.Path == "/":
			w.Header().Set("Location", "http://elsewhere.example/second")
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	d := &dialLog{to: srv.Listener.Addr().String()}
	r := &reachLog{}

	p := proberVia(d)
	p.chain(context.Background(), p.client(), "http://start.example/",
		&walk{reach: r.reach, decided: map[string]string{"start.example": ""}})

	if n := r.questions("elsewhere.example"); n != 1 {
		t.Errorf("the boundary was asked %d times about one name; each question can be a "+
			"DNS lookup somebody else's resolver serves, and a chain of five hops on one "+
			"host would be five of them", n)
	}
}

// The name is folded before it is asked about or remembered.
func TestTheHostIsFoldedBeforeTheBoundaryIsAsked(t *testing.T) {
	srv := redirectingTo("start.example", "http://ELSEWHERE.example./")
	defer srv.Close()

	d := &dialLog{to: srv.Listener.Addr().String()}
	r := &reachLog{refuse: map[string]string{"elsewhere.example": "not reachable"}}

	p := proberVia(d)
	c := p.chain(context.Background(), p.client(), "http://start.example/",
		&walk{reach: r.reach, decided: map[string]string{"start.example": ""}})

	if c.Stopped == "" {
		t.Error("a redirect to the same name in another spelling was followed; DNS is " +
			"case-insensitive and a trailing dot names the same zone, so a boundary that " +
			"compares the spelling a server chose is a boundary that server chooses (N8)")
	}
	if d.reached("ELSEWHERE.example") {
		t.Error("the probe connected to a host the caller refused, spelled differently")
	}
}

// A chain stopped at the boundary is stopped, not truncated.
func TestARefusedRedirectIsNotReportedAsTheRedirectLimit(t *testing.T) {
	srv := redirectingTo("start.example", "http://elsewhere.example/")
	defer srv.Close()

	d := &dialLog{to: srv.Listener.Addr().String()}
	r := &reachLog{refuse: map[string]string{"elsewhere.example": "not reachable"}}

	p := proberVia(d)
	c := p.chain(context.Background(), p.client(), "http://start.example/",
		&walk{reach: r.reach, decided: map[string]string{"start.example": ""}})

	if c.Truncated {
		t.Error("a chain this deployment declined to follow was marked truncated; the two " +
			"say different things to a reader — one is a limit of the method, the other is " +
			"a decision, and only one of them changes if the site is scanned from elsewhere")
	}
}
