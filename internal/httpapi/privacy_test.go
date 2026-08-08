package httpapi

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Invariant P1 says nothing about a request is recorded: not the target, not
// the client address, not the result. Until now that was enforced by review,
// which is the weakest form of enforcement the invariants document itself
// argues against.
//
// A test cannot prove that no future line will ever be written, but it can
// fail the moment one is, which is the difference between a promise and a
// habit.
func TestNothingIsLogged(t *testing.T) {
	var captured bytes.Buffer

	// The standard logger is global, so this is restored before returning.
	// Nothing in this package runs in parallel, so the swap is safe.
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	previousPrefix := log.Prefix()

	log.SetOutput(&captured)
	log.SetFlags(0)
	log.SetPrefix("")

	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
		log.SetPrefix(previousPrefix)
	})

	s := New(offlineScanner(), Limits{
		Burst:          10_000,
		Refill:         time.Nanosecond,
		RequestTimeout: 2 * time.Second,
	}, nil)

	// Every path a request can take, because a line is usually added on the
	// unhappy ones. The addresses and hostnames below are the sort of thing
	// that would show up in a log if any existed.
	requests := []struct {
		method, path, body, remoteAddr string
	}{
		{http.MethodPost, "/api/v1/scan", `{"target":"secret-internal-name.test"}`, "198.51.100.77:5000"},
		{http.MethodPost, "/api/v1/scan", `{"target":"example.test:22"}`, "198.51.100.78:5000"},
		{http.MethodPost, "/api/v1/scan", `{"target":"exam ple.test"}`, "198.51.100.79:5000"},
		{http.MethodPost, "/api/v1/scan", `not json at all`, "198.51.100.80:5000"},
		{http.MethodPost, "/api/v1/scan", ``, "198.51.100.81:5000"},
		{http.MethodPost, "/api/v1/scan", `{"target":"` + strings.Repeat("a", 9000) + `"}`, "198.51.100.82:5000"},
		{http.MethodGet, "/api/v1/scan", ``, "198.51.100.83:5000"},
		{http.MethodGet, "/healthz", ``, "198.51.100.84:5000"},
		{http.MethodGet, "/does-not-exist", ``, "198.51.100.85:5000"},
	}

	for _, req := range requests {
		r := httptest.NewRequest(req.method, req.path, strings.NewReader(req.body))
		if req.body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		r.RemoteAddr = req.remoteAddr
		r.Header.Set("X-Forwarded-For", "203.0.113.99")
		r.Header.Set("User-Agent", "identifying-agent/1.0")

		s.ServeHTTP(httptest.NewRecorder(), r)
	}

	if captured.Len() != 0 {
		t.Errorf("the service wrote to the log while serving requests:\n%s", captured.String())
	}
}

// The rate limiter holds client addresses in memory, which is the one place
// they legitimately exist. They must not outlive their usefulness there.
func TestClientAddressesAreForgotten(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	l := newLimiter(3, time.Second, 1000, clock)

	for _, addr := range []string{"v4:198.51.100.1", "v4:198.51.100.2", "v6:2001:db8::/64"} {
		l.allow(addr)
	}
	if l.size() != 3 {
		t.Fatalf("the limiter tracks %d clients, want 3", l.size())
	}

	// Past the point where a bucket has refilled completely, keeping the
	// address changes nothing about rate limiting and everything about what
	// this process knows.
	now = now.Add(time.Hour)
	l.allow("v4:203.0.113.1")

	if got := l.size(); got > 2 {
		t.Errorf("the limiter still holds %d clients an hour later; addresses must not be kept once they serve no purpose", got)
	}
}
