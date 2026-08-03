package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
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

	for i := range 3 {
		if w := post(t, s, `{"target":"example.test"}`); w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d was limited while tokens remained", i+1)
		}
	}

	w := post(t, s, `{"target":"example.test"}`)
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

// With one trusted proxy, the address it appended is the rightmost entry.
// Taking the leftmost — the usual mistake — reads whatever the client sent.
func TestForwardedHeaderReadFromTheRight(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1, Refill: time.Hour, TrustedProxyHops: 1}, nil)

	send := func(xff string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/scan",
			strings.NewReader(`{"target":"example.test"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-For", xff)
		r.RemoteAddr = "10.0.0.1:1000" // the proxy
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}

	// The client claims to be 1.1.1.1; the proxy says it came from 198.51.100.5.
	if code := send("1.1.1.1, 198.51.100.5"); code == http.StatusTooManyRequests {
		t.Fatal("the first request was limited")
	}
	// Same real client, different claim. It must still be limited.
	if code := send("9.9.9.9, 198.51.100.5"); code != http.StatusTooManyRequests {
		t.Error("the leftmost entry was trusted, so a client could choose its own key")
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
// counterpart here. If this ever returns a completed handshake, the service
// has become an open proxy into whatever network it runs in.
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
// ever.
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
