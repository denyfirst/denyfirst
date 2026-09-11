package httpapi

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/scan"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
	"github.com/denyfirst/denyfirst/internal/verify"
	"github.com/denyfirst/denyfirst/internal/webprobe"
	"github.com/denyfirst/denyfirst/internal/webscan"
)

// This file tests the composition rather than the components.
//
// Both scanners asked verify.Scope, both had tests proving they asked it, and
// the service built one of them without a scope — so /api/v1/tls/scan refused
// an unproven host and /api/v1/web/scan measured it. Every unit test passed
// while half the deployment had no boundary at all. What was missing was a
// test that builds the service the way the service is built and then drives
// the addresses a stranger can reach.
//
// So nothing here reaches inside a scanner. It configures a boundary the way
// cmd/denyfirstd does, posts to the paths the mux actually registers, and asks
// whether anything opened a connection.

// verificationSecret is a deployment secret of the length the service
// requires. Its value is irrelevant; that it is the same one the tokens are
// derived from is the whole of it.
var verificationSecret = []byte("thirty-two bytes of test secret.")

// challengeStub answers the verification lookup without a network, and
// remembers that it was asked.
//
// Being asked is half of what these tests assert. A refusal that arrives
// without a lookup is not this boundary refusing — it is something earlier in
// the chain, and a test that accepted it would go on passing after the
// boundary was removed.
type challengeStub struct {
	published map[string]string
	asked     atomic.Int32
}

func (c *challengeStub) LookupChallenge(_ context.Context, name string) ([]string, bool, error) {
	c.asked.Add(1)
	value, ok := c.published[strings.ToLower(name)]
	if !ok {
		return nil, false, nil
	}
	return []string{value}, true, nil
}

// scopeProving builds the boundary a service configures, with a record
// published for each domain named and for nothing else.
func scopeProving(domains ...string) (*verify.Scope, *challengeStub) {
	stub := &challengeStub{published: map[string]string{}}
	for _, d := range domains {
		stub.published[verify.Label+"."+d] = verify.Token(verificationSecret, d)
	}
	return &verify.Scope{Secret: verificationSecret, Resolver: stub}, stub
}

// recordingDial refuses every connection and remembers that one was tried.
//
// Refusing rather than answering, because these tests are about what does not
// happen. The flag is what they read: a boundary that held is a boundary
// nothing dialled through, and that is a stronger statement than a status
// code, which a handler could produce while a connection was already open.
func recordingDial(reached *atomic.Bool) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		reached.Store(true)
		return nil, errors.New("no network in tests")
	}
}

// verifyingService builds the server the way cmd/denyfirstd builds it: the
// scope goes on the scanner handed to New, and nothing else is configured with
// it.
//
// The web prober is then reached into and replaced, rather than the whole web
// scanner being handed in through UseWebScanner. That is deliberate and it is
// the point of the file. UseWebScanner now carries the boundary over, so a
// server built through it would have a scope whatever New did — and a
// constructor that stopped passing one would go unnoticed here, which is the
// exact shape of the defect these tests exist for. Replacing only the prober
// leaves whatever New decided in place and still lets nothing reach the
// network.
func verifyingService(scope *verify.Scope, tlsReached, webReached *atomic.Bool) *Server {
	s := New(&scan.Scanner{
		Prober: &tlsprobe.Prober{Dial: recordingDial(tlsReached)},
		Verify: scope,
	}, Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	s.web.Prober = &webprobe.Prober{
		Dial:           recordingDial(webReached),
		RequestTimeout: 200 * time.Millisecond,
		TotalTimeout:   time.Second,
	}

	return s
}

func postTo(t *testing.T, s *Server, path, body, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()

	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = remoteAddr

	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

var postRoute = regexp.MustCompile(`mux\.HandleFunc\("POST ([^"]+)"`)

// scanningRoutes are the addresses a stranger can post a target to, read from
// the source rather than listed here.
//
// Listed here, this test would say what somebody remembered to add to it. The
// defect it exists to catch was a check wired up without a boundary, and a
// hand-written list is the same kind of omission one file further along. So
// the routes come from the registrations themselves: add an endpoint, and it
// is tested by existing.
//
// Every POST on this service is a scan today. If one that is not is ever
// added, this stops being a true statement and the person adding it has to say
// which kind it is — which is the conversation worth having.
func scanningRoutes(t *testing.T) []string {
	t.Helper()

	source, err := os.ReadFile("httpapi.go")
	if err != nil {
		t.Fatalf("reading the routes: %v", err)
	}

	var routes []string
	for _, m := range postRoute.FindAllStringSubmatch(string(source), -1) {
		routes = append(routes, m[1])
	}
	if len(routes) < 2 {
		t.Fatalf("found %d POST routes in httpapi.go, expected the scan endpoints; the "+
			"registration was rewritten and this test is now reading nothing", len(routes))
	}
	return routes
}

// Every address that scans asks the same boundary.
func TestEveryScanningEndpointRequiresProofOfControl(t *testing.T) {
	scope, dns := scopeProving()

	var tlsReached, webReached atomic.Bool
	s := verifyingService(scope, &tlsReached, &webReached)

	for i, route := range scanningRoutes(t) {
		// A host of its own per route, so that nothing here is answered by
		// the per-target budget instead of by the boundary.
		host := fmt.Sprintf("unproven%d.test", i)
		w := postTo(t, s, route, `{"target":"`+host+`"}`, fmt.Sprintf("203.0.113.%d:5000", 200+i))

		if w.Code != http.StatusForbidden {
			t.Errorf("%s answered %d for a domain this deployment has not been shown control "+
				"of, want 403", route, w.Code)
			continue
		}
		if got := errorCode(t, w); got != "not_verified" {
			t.Errorf("%s refused with %q, want %q", route, got, "not_verified")
		}
	}

	if tlsReached.Load() || webReached.Load() {
		t.Errorf("a connection was opened for a domain this deployment has not been shown "+
			"control of (tls=%v web=%v): the refusal has to come before the network, or the "+
			"operator's address is already in a stranger's logs",
			tlsReached.Load(), webReached.Load())
	}
	if dns.asked.Load() == 0 {
		t.Error("nothing asked for a challenge record: these requests were refused by something " +
			"other than the boundary, and this test would keep passing without it")
	}
}

// A domain that has published its record is scanned.
func TestAProvenDomainReachesTheProbe(t *testing.T) {
	scope, _ := scopeProving("proven.test")

	var tlsReached, webReached atomic.Bool
	s := verifyingService(scope, &tlsReached, &webReached)

	// Both checks, because a boundary that let one through and stopped the
	// other is the defect this file was written for, in the other direction.
	postTo(t, s, "/api/v1/tls/scan", `{"target":"proven.test"}`, "203.0.113.40:5000")
	postTo(t, s, "/api/v1/web/scan", `{"target":"proven.test"}`, "203.0.113.41:5000")

	if !tlsReached.Load() {
		t.Error("the TLS check did not reach the network for a domain that published its record")
	}
	if !webReached.Load() {
		t.Error("the web check did not reach the network for a domain that published its record")
	}
}

// The constructor hands every check the boundary it was given.
func TestTheConstructorGivesEveryCheckTheSameBoundary(t *testing.T) {
	scope, _ := scopeProving()

	s := New(&scan.Scanner{Verify: scope}, Limits{}, nil)
	if s.web.Verify != s.scanner.Verify {
		t.Error("the web check was built with a different boundary from the one the caller " +
			"configured; a service that sets one on the scanner it passes in has to get it " +
			"on every check, or it has a boundary on part of its surface and none on the rest")
	}

	// The other direction. A caller that configured nothing gets nothing,
	// which is what the command line and every other test in this package is.
	plain := New(&scan.Scanner{}, Limits{}, nil)
	if plain.web.Verify != nil {
		t.Error("a caller that asked for no proof of control got one anyway")
	}
}

// The door tests use cannot take the boundary away.
func TestReplacingTheWebScannerCannotDropTheBoundary(t *testing.T) {
	scope, dns := scopeProving()

	s := New(&scan.Scanner{
		Prober: &tlsprobe.Prober{Dial: recordingDial(new(atomic.Bool))},
		Verify: scope,
	}, Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	// A replacement carrying a prober and no scope, which is what every test
	// that needs a reachable server hands in, and what a service growing a
	// configurable prober would hand in by accident.
	var reached atomic.Bool
	replacement := &webscan.Scanner{Prober: &webprobe.Prober{
		Dial:           recordingDial(&reached),
		RequestTimeout: 200 * time.Millisecond,
		TotalTimeout:   time.Second,
	}}
	s.UseWebScanner(replacement)

	if replacement.Verify != scope {
		t.Fatal("replacing the web scanner dropped the boundary the server was built with")
	}

	w := postTo(t, s, "/api/v1/web/scan", `{"target":"unproven.test"}`, "203.0.113.50:5000")
	if w.Code != http.StatusForbidden || errorCode(t, w) != "not_verified" {
		t.Errorf("after the web scanner was replaced the check answered %d/%q, want 403/%q",
			w.Code, errorCode(t, w), "not_verified")
	}
	if reached.Load() {
		t.Error("the replaced prober opened a connection for an unproven domain")
	}
	if dns.asked.Load() == 0 {
		t.Error("the replaced check asked for no challenge record")
	}

	// And it carries over rather than overriding. A caller that hands in a
	// narrower scope than the server was built with has said something, and a
	// constructor that quietly replaced it would widen a boundary while
	// looking like it was enforcing one.
	own, _ := scopeProving("its-own.test")
	carrying := &webscan.Scanner{Verify: own}
	s.UseWebScanner(carrying)
	if carrying.Verify != own {
		t.Error("a replacement that carried its own boundary had it overwritten")
	}
}

// A lookup that failed is not a domain that is unverified (N9).
func TestALookupFailureIsNotAnsweredAsUnproven(t *testing.T) {
	scope := &verify.Scope{Secret: verificationSecret, Resolver: failingResolver{}}

	var tlsReached, webReached atomic.Bool
	s := verifyingService(scope, &tlsReached, &webReached)

	w := postTo(t, s, "/api/v1/web/scan", `{"target":"example.test"}`, "203.0.113.70:5000")
	if got := errorCode(t, w); got != "scan_failed" {
		t.Errorf("a challenge lookup that could not be answered was refused as %q, want "+
			"%q: telling an operator their domain is unproven sends them to publish a "+
			"record they have already published, rather than to the resolver that would "+
			"not answer", got, "scan_failed")
	}
	if tlsReached.Load() || webReached.Load() {
		t.Error("a connection was opened after the challenge lookup failed")
	}
}

// failingResolver stands in for a resolver that will not answer.
type failingResolver struct{}

func (failingResolver) LookupChallenge(context.Context, string) ([]string, bool, error) {
	return nil, false, errors.New("the resolver did not answer")
}

// The refusal says which decision was made, and names no host.
func TestTheVerificationRefusalStatesTheRuleWithoutRepeatingTheTarget(t *testing.T) {
	scope, _ := scopeProving()

	var tlsReached, webReached atomic.Bool
	s := verifyingService(scope, &tlsReached, &webReached)

	const host = "secret-internal-name.test"
	w := postTo(t, s, "/api/v1/web/scan", `{"target":"`+host+`"}`, "203.0.113.60:5000")

	body := w.Body.String()
	if strings.Contains(body, "secret-internal-name") {
		t.Errorf("the refusal repeats the target back to the caller (I3): %s", body)
	}
	if !strings.Contains(body, verify.Label) {
		t.Errorf("the refusal does not say what to publish, so a reader is told they are "+
			"refused and not what to do about it: %s", body)
	}
	if strings.Contains(strings.ToLower(body), "could not be reached") {
		t.Errorf("the refusal describes a network fault for a decision made here: %s", body)
	}
}

// The trust store travels with the boundary, and for the same reason.
//
// A service that read its own store, checked it was not empty and refused to
// start without one handed it to the TLS scanner; the web check was built
// without it and judged its chains against whatever the platform picks (R7).
// One kind of omission, a second field.
func TestTheConstructorGivesEveryCheckTheSameTrustStore(t *testing.T) {
	pool := x509.NewCertPool()

	s := New(&scan.Scanner{Roots: pool}, Limits{}, nil)
	if s.web.Roots != pool {
		t.Error("the web check was built without the trust store the caller configured, so a " +
			"service that resolved one judges half its chains against something else")
	}

	// And a caller that configured none gets none, so nil still means "load the
	// system store explicitly" rather than a pool this constructor invented.
	if plain := New(&scan.Scanner{}, Limits{}, nil); plain.web.Roots != nil {
		t.Error("a caller that configured no trust store got one anyway")
	}
}

// And the door tests use cannot take it away either.
func TestReplacingTheWebScannerCannotDropTheTrustStore(t *testing.T) {
	pool := x509.NewCertPool()
	s := New(&scan.Scanner{Roots: pool}, Limits{}, nil)

	// What every test that needs a reachable server hands in: a prober, and no
	// store.
	replacement := &webscan.Scanner{Prober: &webprobe.Prober{}}
	s.UseWebScanner(replacement)

	if replacement.Roots != pool {
		t.Error("replacing the web scanner dropped the trust store the server was built with")
	}

	// A replacement that brought its own keeps it: the caller said something.
	own := x509.NewCertPool()
	carrying := &webscan.Scanner{Roots: own}
	s.UseWebScanner(carrying)
	if carrying.Roots != own {
		t.Error("a replacement that carried its own trust store had it overwritten")
	}
}

// The service reads pages only where it required proof of control.
//
// The composition, not the component. Every guard in webscan can be correct
// while this constructor hands it the wrong switch, and that exact shape was a
// real hole here once: denyfirstd passed a verification scope to the TLS
// scanner and never touched the web one, so the same service refused an
// unproven host on one path and scanned it on another. A sabotage turning this
// on unconditionally escaped every test in this package on 2026-09-11.
func TestTheServiceReadsPagesOnlyWhereItRequiredProof(t *testing.T) {
	scope := &verify.Scope{Secret: []byte("a deployment secret")}

	withProof := New(&scan.Scanner{Verify: scope}, Limits{}, nil)
	if !withProof.web.ReadMarkup {
		t.Error("a service that requires proof of control does not read the page. The page " +
			"belongs to whoever asked about it, and a meta Content-Security-Policy is invisible " +
			"without reading it.")
	}
	if withProof.web.Verify != scope {
		t.Error("the boundary did not reach the web check, which is the hole this constructor " +
			"exists to close")
	}

	withoutProof := New(&scan.Scanner{}, Limits{}, nil)
	if withoutProof.web.ReadMarkup {
		t.Error("a service configured with no scope reads the pages of names nobody proved " +
			"anything about. N9 says a service must not scan those at all; until somebody fixes " +
			"that, it does not also read their pages.")
	}
}
