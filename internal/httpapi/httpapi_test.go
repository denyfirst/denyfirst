package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/scan"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

// offlineScanner never reaches the network, so the tests describe the HTTP
// layer rather than the state of the internet.
func offlineScanner() *scan.Scanner {
	return &scan.Scanner{
		Prober: &tlsprobe.Prober{
			Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
				return nil, errors.New("no network in tests")
			},
		},
	}
}

// blockingScanner holds every scan until released, so concurrency limits can
// be observed rather than raced against.
func blockingScanner(release <-chan struct{}) *scan.Scanner {
	return &scan.Scanner{
		Prober: &tlsprobe.Prober{
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				select {
				case <-release:
					return nil, errors.New("released")
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			},
		},
	}
}

func post(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	return postFrom(t, s, body, "203.0.113.7:5000")
}

func postFrom(t *testing.T, s *Server, body, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()

	r := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = remoteAddr

	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()

	var resp errorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not a JSON error object: %v (body %q)", err, w.Body.String())
	}
	return resp.Error.Code
}

// Every response carries the headers, including error responses. A policy
// applied only on the happy path is not a policy.
func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	s := New(offlineScanner(), Limits{}, nil)

	responses := []*httptest.ResponseRecorder{
		post(t, s, `{"target":"example.test"}`),
		post(t, s, `not json`),
	}

	required := map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cache-Control":                "no-store",
	}

	for i, w := range responses {
		for header, want := range required {
			if got := w.Header().Get(header); got != want {
				t.Errorf("response %d: %s = %q, want %q", i, header, got, want)
			}
		}
		csp := w.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'none'") {
			t.Errorf("response %d: CSP = %q, want it to deny by default", i, csp)
		}
		if !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("response %d: CSP = %q, want framing denied", i, csp)
		}
	}
}

// HSTS over plaintext tells a browser nothing it can act on, and asserting it
// there suggests the header is decoration rather than policy.
func TestHSTSOnlyOverTLS(t *testing.T) {
	s := New(offlineScanner(), Limits{}, nil)

	plain := post(t, s, `{"target":"example.test"}`)
	if got := plain.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS sent over plaintext: %q", got)
	}

	r := httptest.NewRequest(http.MethodPost, "https://denyfirst.test/api/v1/scan",
		strings.NewReader(`{"target":"example.test"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "203.0.113.7:5000"
	r.TLS = &tls.ConnectionState{}

	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	if got := w.Header().Get("Strict-Transport-Security"); got == "" {
		t.Error("HSTS missing over TLS")
	}
}

func TestRejectsMalformedBodies(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000}, nil)

	cases := map[string]string{
		`not json`:                            "bad_request",
		`{"target":"example.test"} {"x":1}`:   "bad_request",
		`{"target":"example.test","extra":1}`: "bad_request",
		`{"target":"exam ple.test"}`:          "invalid_target",
		`{"target":"exam\nple.test"}`:         "invalid_target",
		`{"target":""}`:                       "invalid_target",
		`{"target":"example.test:22"}`:        "port_not_allowed",
		`{"target":"example.test:3389"}`:      "port_not_allowed",
		`{"target":"93.184.216.34"}`:          "hostname_required",
	}

	for body, wantCode := range cases {
		w := post(t, s, body)
		if got := errorCode(t, w); got != wantCode {
			t.Errorf("body %q: code = %q, want %q (status %d)", body, got, wantCode, w.Code)
		}
	}
}

// The error text must describe the rule rather than repeat what was sent.
// Reflecting input is how a JSON endpoint becomes an XSS vector the moment
// something renders it.
func TestErrorsDoNotEchoInput(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000}, nil)

	const marker = "<script>alert(1)</script>"

	// The host path.
	w := post(t, s, `{"target":"exam `+marker+` ple"}`)
	if strings.Contains(w.Body.String(), "script") {
		t.Errorf("the host was repeated back: %s", w.Body.String())
	}

	// The port path is separate and has its own message. SplitHostPort does
	// not require a port to be numeric, so anything after the colon reaches
	// the port check unaltered.
	w = post(t, s, `{"target":"example.test:`+marker+`"}`)
	if strings.Contains(w.Body.String(), "script") {
		t.Errorf("the port was repeated back: %s", w.Body.String())
	}
}

func TestBodySizeLimit(t *testing.T) {
	s := New(offlineScanner(), Limits{MaxRequestBytes: 64, Burst: 1000}, nil)

	oversized := `{"target":"` + strings.Repeat("a", 500) + `"}`
	w := post(t, s, oversized)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
	if got := errorCode(t, w); got != "payload_too_large" {
		t.Errorf("code = %q, want payload_too_large", got)
	}
}

func TestRateLimit(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 3, Refill: time.Hour}, nil)

	// A different target each time, so only the per-client budget can refuse
	// these. The per-target limit is a separate mechanism with its own tests;
	// reusing one hostname here would let it fire and make this test report
	// the wrong thing.
	for i := range 3 {
		body := `{"target":"client-limit-` + strconv.Itoa(i) + `.test"}`
		if w := post(t, s, body); w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d was limited while tokens remained", i+1)
		}
	}

	w := post(t, s, `{"target":"client-limit-final.test"}`)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d once the burst is spent", w.Code, http.StatusTooManyRequests)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("Retry-After missing from a rate limited response")
	}
}

// One client must not spend another client's allowance.
func TestRateLimitIsPerClient(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1, Refill: time.Hour}, nil)

	if w := postFrom(t, s, `{"target":"example.test"}`, "198.51.100.1:1000"); w.Code == http.StatusTooManyRequests {
		t.Fatal("the first request from a new client was limited")
	}
	if w := postFrom(t, s, `{"target":"example.test"}`, "198.51.100.1:1000"); w.Code != http.StatusTooManyRequests {
		t.Error("the second request from the same client was not limited")
	}
	if w := postFrom(t, s, `{"target":"example.test"}`, "198.51.100.2:1000"); w.Code == http.StatusTooManyRequests {
		t.Error("a different client was refused because of someone else's usage")
	}
}

// A subscriber holds a whole /64 and can present a new address per request.
// Keying on the full address would make the limiter decorative.
func TestIPv6IsLimitedPerPrefix(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1, Refill: time.Hour}, nil)

	if w := postFrom(t, s, `{"target":"example.test"}`, "[2001:db8:1:2::1]:1000"); w.Code == http.StatusTooManyRequests {
		t.Fatal("the first request was limited")
	}

	// A different address, the same /64.
	if w := postFrom(t, s, `{"target":"example.test"}`, "[2001:db8:1:2::dead:beef]:1000"); w.Code != http.StatusTooManyRequests {
		t.Error("rotating the host part of an IPv6 address escaped the limiter")
	}

	// A genuinely different /64 is a different client.
	if w := postFrom(t, s, `{"target":"example.test"}`, "[2001:db8:1:3::1]:1000"); w.Code == http.StatusTooManyRequests {
		t.Error("a separate /64 was refused because of another prefix's usage")
	}
}

// Without a declared proxy, X-Forwarded-For is whatever the client typed.
// Honouring it would let anyone mint a fresh rate limit key per request.
func TestForwardedHeaderIgnoredWithoutTrustedProxy(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1, Refill: time.Hour}, nil)

	send := func(spoof string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/scan",
			strings.NewReader(`{"target":"example.test"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-For", spoof)
		r.RemoteAddr = "203.0.113.9:1000"

		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}

	if code := send("1.1.1.1"); code == http.StatusTooManyRequests {
		t.Fatal("the first request was limited")
	}
	if code := send("2.2.2.2"); code != http.StatusTooManyRequests {
		t.Error("changing X-Forwarded-For escaped the limiter although no proxy was declared")
	}
}

// A hop count says a proxy exists. It does not say the request in hand came
// through one.
//
// A reverse proxy hides an origin server but rarely removes it: the address
// turns up in certificate transparency logs, in old DNS records, or in a
// scanning service. A client reaching it directly writes whatever
// X-Forwarded-For it likes, and a service that trusts the header on the
// strength of a flag alone gives that client a fresh rate limit key for every
// request, which is the same as having no limit at all.
func TestForwardedHeaderIsIgnoredFromUndeclaredNetworks(t *testing.T) {
	s := New(offlineScanner(), Limits{
		Burst:            1,
		Refill:           time.Hour,
		TrustedProxies:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		TrustedProxyHops: 1,
	}, nil)

	// Straight to the origin, pretending to be a proxy.
	send := func(claim string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/scan",
			strings.NewReader(`{"target":"example.test"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-For", claim)
		r.RemoteAddr = "203.0.113.50:1000" // outside the declared network
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}

	if code := send("1.1.1.1"); code == http.StatusTooManyRequests {
		t.Fatal("the first request was limited")
	}
	if code := send("2.2.2.2"); code != http.StatusTooManyRequests {
		t.Error("a client reaching the origin directly minted a new key by changing the header")
	}
}

// Through a declared proxy, the header is what identifies the client, and the
// entry that counts is the one the proxy appended.
func TestForwardedHeaderIsReadFromDeclaredNetworks(t *testing.T) {
	s := New(offlineScanner(), Limits{
		Burst:            1,
		Refill:           time.Hour,
		TrustedProxies:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		TrustedProxyHops: 1,
	}, nil)

	send := func(xff string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/scan",
			strings.NewReader(`{"target":"example.test"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-For", xff)
		r.RemoteAddr = "10.0.0.7:1000" // the proxy
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}

	// Two different real clients: each has its own budget.
	if code := send("1.1.1.1, 198.51.100.5"); code == http.StatusTooManyRequests {
		t.Fatal("the first client was limited")
	}
	if code := send("1.1.1.1, 198.51.100.6"); code == http.StatusTooManyRequests {
		t.Error("a second client was refused because of the first")
	}

	// The same real client again, whatever it claims to the left. Taking the
	// leftmost entry — the usual mistake — would let it choose its own key.
	if code := send("9.9.9.9, 198.51.100.5"); code != http.StatusTooManyRequests {
		t.Error("the leftmost entry was trusted")
	}
}

// A hop count with no network to check against would mean reading a header
// any client can write. An incomplete configuration has to fail closed.
func TestHopCountWithoutNetworksIsIgnored(t *testing.T) {
	s := New(offlineScanner(), Limits{
		Burst:            1,
		Refill:           time.Hour,
		TrustedProxyHops: 1, // no TrustedProxies
	}, nil)

	send := func(claim string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/scan",
			strings.NewReader(`{"target":"example.test"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-For", claim)
		r.RemoteAddr = "203.0.113.60:1000"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}

	if code := send("1.1.1.1"); code == http.StatusTooManyRequests {
		t.Fatal("the first request was limited")
	}
	if code := send("2.2.2.2"); code != http.StatusTooManyRequests {
		t.Error("a hop count without a network list was honoured, so the header was trusted")
	}
}

func TestConcurrencyLimit(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	s := New(blockingScanner(release), Limits{
		MaxConcurrent:  1,
		Burst:          100,
		RequestTimeout: 3 * time.Second,
	}, nil)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		post(t, s, `{"target":"slow.test"}`)
	}()

	// Give the first request time to take the only slot.
	time.Sleep(150 * time.Millisecond)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/scan",
		strings.NewReader(`{"target":"other.test"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "198.51.100.20:1000"

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	w := httptest.NewRecorder()
	s.ServeHTTP(w, r.WithContext(ctx))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d while the only slot was held", w.Code, http.StatusServiceUnavailable)
	}
	if got := errorCode(t, w); got != "too_busy" {
		t.Errorf("code = %q, want too_busy", got)
	}

	wg.Wait()
}

// The switch that lets the command line reach private addresses has no
// counterpart here. Addresses are refused before the dialler is reached,
// which is a second layer rather than a replacement: if the hostname rule
// were ever relaxed, safedial would still refuse these.
func TestPrivateTargetsAreRefused(t *testing.T) {
	s := New(nil, Limits{Burst: 1000, RequestTimeout: 5 * time.Second}, nil)

	for _, target := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "[::1]"} {
		w := post(t, s, `{"target":"`+target+`"}`)

		if w.Code != http.StatusOK {
			continue // refused outright is also correct
		}

		var resp scanResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decoding the response for %s: %v", target, err)
		}
		if resp.Certificate != nil {
			t.Errorf("%s returned a certificate", target)
		}
		for _, v := range resp.TLS.Versions {
			if v.Supported {
				t.Errorf("%s completed a handshake", target)
			}
		}
	}
}

func TestMethodAndPathRouting(t *testing.T) {
	s := New(offlineScanner(), Limits{}, nil)

	cases := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/api/v1/scan", http.StatusMethodNotAllowed},
		{http.MethodPut, "/api/v1/scan", http.StatusMethodNotAllowed},
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodGet, "/", http.StatusNotFound},
		{http.MethodGet, "/api/v1/nothing", http.StatusNotFound},
	}

	for _, tc := range cases {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.RemoteAddr = "203.0.113.30:1000"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)

		if w.Code != tc.want {
			t.Errorf("%s %s: status = %d, want %d", tc.method, tc.path, w.Code, tc.want)
		}
	}
}

func TestUnsupportedContentType(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000}, nil)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/scan",
		strings.NewReader(`{"target":"example.test"}`))
	r.Header.Set("Content-Type", "text/plain")
	r.RemoteAddr = "203.0.113.31:1000"

	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnsupportedMediaType)
	}
}

// An unbounded map turns a rate limiter into a memory exhaustion primitive,
// since an attacker rotating source addresses adds an entry per request.
func TestLimiterMemoryIsBounded(t *testing.T) {
	const maxKeys = 50
	l := newLimiter(5, time.Hour, maxKeys, nil)

	for i := range 500 {
		l.allow("v4:198.51.100." + strconv.Itoa(i%256) + "." + strconv.Itoa(i))
	}

	if got := l.size(); got > maxKeys {
		t.Errorf("the limiter tracks %d clients, above its cap of %d", got, maxKeys)
	}
}

// Idle buckets are dropped, so a busy day does not leave the map full for
// ever. This is also how long an address is held, which the privacy page
// states as a number.
func TestLimiterSweepsIdleClients(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	l := newLimiter(2, time.Second, 1000, clock)
	for i := range 10 {
		l.allow("client-" + strconv.Itoa(i))
	}
	if l.size() != 10 {
		t.Fatalf("size = %d, want 10", l.size())
	}

	// Past the point where a bucket has refilled completely, its state is
	// indistinguishable from a fresh one.
	now = now.Add(time.Hour)
	l.allow("someone-new")

	if got := l.size(); got > 2 {
		t.Errorf("size = %d after an hour of idleness, want the old entries gone", got)
	}
}

// The privacy page states how long an address is held. That figure has to
// come from the same arithmetic the sweep uses, or the page and the code
// drift apart and the page is the one people read.
func TestRetentionPeriodIsBounded(t *testing.T) {
	l := newLimiter(DefaultBurst, DefaultRefill, DefaultMaxTrackedIPs, nil)

	got := l.RetentionPeriod()
	if got <= 0 {
		t.Fatalf("RetentionPeriod() = %v", got)
	}
	if got > 5*time.Minute {
		t.Errorf("RetentionPeriod() = %v; an address held longer than a few minutes needs a reason", got)
	}
}

func TestHealthReportsThePolicy(t *testing.T) {
	s := New(offlineScanner(), Limits{}, nil)

	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	r.RemoteAddr = "203.0.113.40:1000"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if body["policy"] == "" {
		t.Error("the health response does not name the policy version")
	}
}

// The two limits answer different questions and must not be mistaken for one
// another. One client scanning many hosts is ordinary use; many clients
// scanning one host is what the target limit exists for. A test that reuses a
// hostname while measuring the client limit reports whichever fires first,
// which is how this pair got tangled once already.
func TestTheTwoLimitsAreIndependent(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 2, Refill: time.Hour}, nil)

	// One client, many targets: the client budget is what runs out.
	for i := range 2 {
		if w := post(t, s, `{"target":"independent-`+strconv.Itoa(i)+`.test"}`); w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d was refused while the client still had tokens", i+1)
		}
	}
	w := post(t, s, `{"target":"independent-final.test"}`)
	if errorCode(t, w) != "rate_limited" {
		t.Errorf("code = %q, want rate_limited: this client had spent its own budget", errorCode(t, w))
	}

	// Many clients, one target: the target budget is what runs out, and the
	// message must say so rather than blaming the caller.
	fresh := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	for i := range targetBurst {
		postFrom(t, fresh, `{"target":"shared.test"}`, "203.0.113."+strconv.Itoa(i+1)+":5000")
	}
	w = postFrom(t, fresh, `{"target":"shared.test"}`, "203.0.113.200:5000")
	if errorCode(t, w) != "target_busy" {
		t.Errorf("code = %q, want target_busy: this client had done nothing", errorCode(t, w))
	}
}

// The service refuses addresses; the command line accepts them. This is where
// that difference is enforced for anyone reaching it over HTTP.
func TestServiceRequiresAHostname(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	for _, target := range []string{
		"93.184.216.34",
		"93.184.216.34:8443",
		"2606:4700:4700::1111",
		"[2606:4700:4700::1111]:443",
	} {
		w := post(t, s, `{"target":"`+target+`"}`)

		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", target, w.Code)
			continue
		}
		if got := errorCode(t, w); got != "hostname_required" {
			t.Errorf("%s: code = %q, want hostname_required", target, got)
		}
		// The message explains the rule; it must not repeat the address.
		if strings.Contains(w.Body.String(), target) {
			t.Errorf("%s: the response repeated the target", target)
		}
	}
}

// A hostname that merely resembles an address must still be accepted, or the
// check is matching strings rather than parsing. Services such as nip.io
// resolve ordinary-looking names to addresses, and refusing those would be
// wrong without stopping anybody determined.
func TestNamesThatResembleAddressesAreAccepted(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	for _, target := range []string{
		"93.184.216.34.example.com",
		"1.2.3.4.nip.io",
		"v6.example.com",
	} {
		w := post(t, s, `{"target":"`+target+`"}`)
		if w.Code == http.StatusBadRequest && errorCode(t, w) == "hostname_required" {
			t.Errorf("%s was refused as an address although it is a name", target)
		}
	}
}
