package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/safedial"
	"github.com/denyfirst/denyfirst/internal/webprobe"
	"github.com/denyfirst/denyfirst/internal/webscan"
)

const webScanPath = "/api/v1/web/scan"

// errBlockedForTest is shaped like safedial's refusal, including the address
// in its text, so that a test can check the address does not come back out.
var errBlockedForTest = fmt.Errorf("%w: 127.0.0.1 is loopback", safedial.ErrBlocked)

// postWebFrom sends a web scan the way a client would.
func postWebFrom(t *testing.T, s *Server, body, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()

	r := httptest.NewRequest(http.MethodPost, webScanPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = remoteAddr

	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func postWeb(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	return postWebFrom(t, s, body, "203.0.113.7:5000")
}

// offlineWebScanner answers nothing, so a test needs no network and cannot be
// turned green or red by whatever a resolver on the machine decides to answer.
func offlineWebScanner() *webscan.Scanner {
	return &webscan.Scanner{Prober: &webprobe.Prober{
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("nothing is listening")
		},
		RequestTimeout: 200 * time.Millisecond,
		TotalTimeout:   time.Second,
	}}
}

// blockedWebScanner stands in for a name that resolves only to addresses
// safedial refuses.
func blockedWebScanner() *webscan.Scanner {
	return &webscan.Scanner{Prober: &webprobe.Prober{
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errBlockedForTest
		},
		RequestTimeout: 200 * time.Millisecond,
		TotalTimeout:   time.Second,
	}}
}

// webServer returns a server with the web check wired to an offline scanner.
func webServer(t *testing.T, w *webscan.Scanner) *Server {
	t.Helper()
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	s.UseWebScanner(w)
	return s
}

// The web check has an address, and it answers a report.
func TestTheWebEndpointAnswersAReport(t *testing.T) {
	s := webServer(t, offlineWebScanner())

	w := postWeb(t, s, `{"target":"example.test"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}

	var got struct {
		Host    string `json:"host"`
		Policy  string `json:"policy"`
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if got.Host != "example.test" {
		t.Errorf("the report names host %q", got.Host)
	}
	if got.Policy != policy.WebVersion {
		t.Errorf("the report names rule set %q, want %q: a verdict that does not say which rules "+
			"produced it cannot be reproduced", got.Policy, policy.WebVersion)
	}
}

// A GET is not a scan, on this path either.
//
// The target travels in the body so that it stays out of browser history, out
// of a Referer header and out of every proxy log on the way (P2).
func TestTheWebEndpointDoesNotAnswerAGet(t *testing.T) {
	s := webServer(t, offlineWebScanner())

	r := httptest.NewRequest(http.MethodGet, webScanPath+"?target=example.test", nil)
	r.RemoteAddr = "203.0.113.7:5000"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	// 405 rather than "not 200", because those are different facts and only
	// one of them is the property. A GET route that existed would refuse this
	// request anyway — for having no body — and "not 200" would be satisfied
	// by that while the route sat there inviting callers to put a target in a
	// URL. A sabotage that added the route escaped exactly that way. 405 is
	// the answer only a path with no GET on it gives.
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("a GET was answered with %d, want 405: the path must carry no GET at all, because "+
			"a target in a URL is a target in browser history, in a Referer header, and in the log "+
			"of every proxy on the way", w.Code)
	}
}

// The web check takes a bare hostname, and a port is refused rather than
// dropped.
//
// Ignoring it would be the failure target parsing already refuses for a path:
// discarding part of what somebody typed without saying so, leaving a report
// that names the right host while the person is still surprised.
func TestTheWebEndpointRefusesAPortRatherThanDroppingIt(t *testing.T) {
	s := webServer(t, offlineWebScanner())

	for _, target := range []string{"example.test:443", "example.test:80", "example.test:8443"} {
		w := postWeb(t, s, `{"target":"`+target+`"}`)
		if got := errorCode(t, w); got != "port_not_accepted" {
			t.Errorf("%q was refused as %q, want port_not_accepted", target, got)
		}
		if body := w.Body.String(); strings.Contains(body, "example.test") {
			t.Errorf("the refusal repeats the target back: %s", body)
		}
	}
}

// A scheme is stripped, exactly as it is for the other check, because a pasted
// address is a likely mistake rather than something worth refusing.
func TestTheWebEndpointAcceptsAPastedAddress(t *testing.T) {
	s := webServer(t, offlineWebScanner())

	for _, target := range []string{"https://example.test", "https://example.test/", "example.test."} {
		w := postWeb(t, s, `{"target":"`+target+`"}`)
		if w.Code != http.StatusOK {
			t.Errorf("%q was refused as %q", target, errorCode(t, w))
		}
	}
}

// A name with no domain is refused, and the message states the rule.
//
// This is the rule the web probe defines rather than one the handler invented:
// a single label is not a name a certificate or a cookie can be scoped to.
func TestTheWebEndpointRefusesANameWithNoDomain(t *testing.T) {
	s := webServer(t, offlineWebScanner())

	w := postWeb(t, s, `{"target":"localhost"}`)
	if got := errorCode(t, w); got != "invalid_target" {
		t.Errorf("refused as %q, want invalid_target", got)
	}
	if body := w.Body.String(); strings.Contains(body, "localhost") {
		t.Errorf("the refusal repeats the target back: %s", body)
	}
}

// An address is refused under the same code on both endpoints.
//
// One code means one thing, so an operator reading the figure is reading one
// kind of event rather than a sum of two.
func TestAnAddressIsRefusedTheSameWayOnBothEndpoints(t *testing.T) {
	s := webServer(t, offlineWebScanner())

	web := errorCode(t, postWebFrom(t, s, `{"target":"93.184.216.34"}`, "203.0.113.20:5000"))
	tls := errorCode(t, postFrom(t, s, `{"target":"93.184.216.34"}`, "203.0.113.21:5000"))

	if web != "hostname_required" || tls != web {
		t.Errorf("the web endpoint refused an address as %q and the TLS one as %q; "+
			"both are the same event and belong in one figure", web, tls)
	}
}

// Every guard the TLS endpoint has, the web endpoint has.
//
// Written as a list rather than as separate tests because the property is that
// the two are the same, and a list makes a guard that stops applying to one of
// them visible as a difference rather than as a missing file.
func TestTheWebEndpointWalksTheSameChainOfGuards(t *testing.T) {
	for _, tc := range []struct {
		name string
		send func(*testing.T, *Server) *httptest.ResponseRecorder
		want string
	}{
		{
			"a body that is not JSON",
			func(t *testing.T, s *Server) *httptest.ResponseRecorder {
				return postWebFrom(t, s, `not json`, "203.0.113.30:5000")
			},
			"bad_request",
		},
		{
			"a body over the cap",
			func(t *testing.T, s *Server) *httptest.ResponseRecorder {
				return postWebFrom(t, s, `{"target":"`+strings.Repeat("a", 9000)+`.test"}`, "203.0.113.31:5000")
			},
			"payload_too_large",
		},
		{
			"an excluded name",
			func(t *testing.T, s *Server) *httptest.ResponseRecorder {
				return postWebFrom(t, s, `{"target":"army.mil"}`, "203.0.113.32:5000")
			},
			"excluded",
		},
		{
			"a target with a control character",
			func(t *testing.T, s *Server) *httptest.ResponseRecorder {
				return postWebFrom(t, s, `{"target":"exam ple.test"}`, "203.0.113.33:5000")
			},
			"invalid_target",
		},
		{
			"an unknown JSON field",
			func(t *testing.T, s *Server) *httptest.ResponseRecorder {
				return postWebFrom(t, s, `{"target":"example.test","depth":3}`, "203.0.113.34:5000")
			},
			"bad_request",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := webServer(t, offlineWebScanner())
			if got := errorCode(t, tc.send(t, s)); got != tc.want {
				t.Errorf("refused as %q, want %q", got, tc.want)
			}
		})
	}
}

// A cross-site request cannot reach the web endpoint either.
func TestTheWebEndpointRefusesACrossSiteRequest(t *testing.T) {
	s := webServer(t, offlineWebScanner())

	r := httptest.NewRequest(http.MethodPost, webScanPath, strings.NewReader(`{"target":"example.test"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.RemoteAddr = "203.0.113.40:5000"

	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	if got := errorCode(t, w); got != "cross_site" {
		t.Errorf("refused as %q, want cross_site", got)
	}
}

// One scan allowance covers both checks.
//
// Two endpoints each with a full allowance would silently double what one
// client can spend, which is the kind of change that arrives as a side effect
// of adding a route rather than as a decision.
func TestOneScanAllowanceCoversBothChecks(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 2, Refill: time.Hour}, nil)
	s.UseWebScanner(offlineWebScanner())

	const from = "203.0.113.50:5000"
	if w := postFrom(t, s, `{"target":"one.test"}`, from); w.Code != http.StatusOK {
		t.Fatalf("the first scan was refused as %q", errorCode(t, w))
	}
	if w := postWebFrom(t, s, `{"target":"two.test"}`, from); w.Code != http.StatusOK {
		t.Fatalf("the second scan was refused as %q", errorCode(t, w))
	}

	if got := errorCode(t, postWebFrom(t, s, `{"target":"three.test"}`, from)); got != "rate_limited" {
		t.Errorf("a third scan was refused as %q, want rate_limited: the web endpoint is spending "+
			"an allowance of its own", got)
	}
}

// One host has one budget, whichever check is asked.
//
// This is the only limit here that protects the server being measured rather
// than this service, and that server had no say in being measured at all. A
// budget of its own for each check would let one host be made to absorb twice
// the peak, and would hand a prober two independent questions about it instead
// of one.
func TestTheTargetBudgetIsSharedBetweenTheChecks(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	s.UseWebScanner(offlineWebScanner())

	// Spend the host's budget through one endpoint, from many addresses so
	// that no client limit fires first.
	exhaustTarget(t, s, `{"target":"busy.test"}`, "203.0.113.")

	if got := errorCode(t, postWebFrom(t, s, `{"target":"busy.test"}`, "198.51.100.9:5000")); got != "target_busy" {
		t.Errorf("the web endpoint scanned a host whose budget the TLS endpoint had spent, and was "+
			"refused as %q; the budget belongs to the host rather than to the check", got)
	}
}

// A name that resolves only where this service will not go is refused and
// counted, on this endpoint too.
//
// Without the field the web report carries, the reason would sit in prose
// inside a successful report and the figure would be permanently zero — the
// defect A7 is written about, rebuilt on a new endpoint.
func TestTheWebEndpointCountsABlockedDestination(t *testing.T) {
	s := webServer(t, blockedWebScanner())

	w := postWeb(t, s, `{"target":"internal.test"}`)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if got := errorCode(t, w); got != "blocked_destination" {
		t.Errorf("refused as %q, want blocked_destination", got)
	}
	if got := s.Stats().Refused["blocked_destination"]; got != 1 {
		t.Errorf("counted %d times, want 1: this figure is the only sign an operator gets that "+
			"somebody is aiming this service at the network it runs in", got)
	}
	if body := w.Body.String(); strings.Contains(body, "127.0.0.1") {
		t.Errorf("the refusal repeats an address back to the caller: %s", body)
	}
}

// A web scan is counted against the web check.
func TestAWebScanIsCountedAgainstItsOwnCheck(t *testing.T) {
	s := webServer(t, offlineWebScanner())

	postWeb(t, s, `{"target":"example.test"}`)

	snap := s.Stats()
	if got := snap.Checks[checkWeb].Total; got != 1 {
		t.Errorf("the web block counted %d scans, want 1", got)
	}
	if got := snap.Total; got != 0 {
		t.Errorf("the TLS figures moved to %d; a verdict from one rule set is not comparable with "+
			"a verdict from another", got)
	}
	if got := snap.Checks[checkWeb].Policy; got != policy.WebVersion {
		t.Errorf("the web block names %q, want %q", got, policy.WebVersion)
	}
}

// What the handler accepts, the probe accepts.
//
// The handler asks webprobe.CheckHostname because the probe is what defines a
// target for this check (N6). Today that call refuses nothing target parsing
// has not already refused — scan.checkHostSyntax requires a domain for the
// same reason the probe does — so a sabotage that disabled it changed no
// answer and escaped every test.
//
// That is a fact about two definitions currently agreeing rather than a
// property of either, and it is the kind of fact that stops being true
// quietly: loosen the parser, and the handler starts handing the probe
// something it will refuse, which comes back to a caller as scan_failed with
// a 502 rather than as the rule they broke.
//
// So the agreement is what is pinned. Everything the handler is willing to
// scan has to be something the probe would scan.
func TestTheHandlerNeverAcceptsATargetTheProbeWouldRefuse(t *testing.T) {
	for _, raw := range []string{
		"example.test",
		"EXAMPLE.TEST",
		"example.test.",
		"https://example.test",
		"https://example.test/",
		"sub.example.test",
		"a-b.example.test",
		"xn--80ak6aa92e.test",
		strings.Repeat("a", 60) + ".example.test",
	} {
		t.Run(raw, func(t *testing.T) {
			parsed, refused := parseWebTarget(raw)
			if refused != nil {
				// Refused is a fine answer; the property is about what is
				// accepted.
				return
			}
			if err := webprobe.CheckHostname(parsed.host); err != nil {
				t.Errorf("the handler accepted %q as host %q, which the probe refuses: %v. "+
					"A caller would be told scan_failed rather than the rule they broke",
					raw, parsed.host, err)
			}
		})
	}
}

// And the target the probe is handed is the folded one (I7).
//
// Something downstream compares hostnames for a living: the per-target budget
// hashes the name to recognise a repeat, and a hash is exact where DNS is not.
// One spelling has to reach the limiter, the lists and the scanner alike.
func TestTheWebTargetIsFoldedBeforeAnythingSeesIt(t *testing.T) {
	for _, raw := range []string{"EXAMPLE.TEST", "Example.Test.", "example.test."} {
		parsed, refused := parseWebTarget(raw)
		if refused != nil {
			t.Fatalf("%q was refused", raw)
		}
		if parsed.host != "example.test" {
			t.Errorf("%q parsed to %q, want example.test: a spelling that reaches the limiter "+
				"unfolded buys a fresh budget for a host that already has one", raw, parsed.host)
		}
	}
}
