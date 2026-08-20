package httpapi

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
)

// Counting by reason is safe to publish; counting by requester is not. A key
// outside the known list would mean somebody started counting something that
// describes a request rather than a category of them.
func TestOnlyKnownRefusalCodesAreCounted(t *testing.T) {
	c := newCounters(nil)

	for _, code := range refusalCodes {
		c.refuse(code)
	}

	// The shapes somebody would reach for if they wanted detail.
	for _, rejected := range []string{
		"bank.example.com",
		"203.0.113.7",
		"rate_limited:203.0.113.7",
		"",
		"unknown_reason",
	} {
		c.refuse(rejected)
	}

	got := c.snapshot().Refused
	if len(got) != len(refusalCodes) {
		t.Errorf("the counter holds %d keys, want %d", len(got), len(refusalCodes))
	}
	for key := range got {
		if !slices.Contains(refusalCodes, key) {
			t.Errorf("the counter holds %q, which is not a known refusal code", key)
		}
	}
}

// A file written by hand, or by an older version, must not be able to
// introduce a key this version would never produce.
func TestRestoreFiltersUnknownCodes(t *testing.T) {
	c := newCounters(nil)
	c.restore(Snapshot{
		Total: 10,
		Refused: map[string]uint64{
			"rate_limited":     5,
			"bank.example.com": 99,
			"made_up":          3,
		},
	})

	got := c.snapshot().Refused
	if got["rate_limited"] != 5 {
		t.Errorf("a known code was not restored: %v", got)
	}
	for key := range got {
		if !slices.Contains(refusalCodes, key) {
			t.Errorf("restore accepted %q from the file", key)
		}
	}
}

// Every refusal the handler can produce has to be counted, or the numbers
// describe a subset of what happened and the operator draws conclusions from
// a partial picture.
func TestHandlerCountsItsRefusals(t *testing.T) {
	cases := []struct {
		body string
		code string
	}{
		{`not json`, "bad_request"},
		{`{"target":"exam ple.test"}`, "invalid_target"},
		{`{"target":"example.test:22"}`, "port_not_allowed"},
		{`{"target":"93.184.216.34"}`, "hostname_required"},
	}

	for _, tc := range cases {
		s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
		post(t, s, tc.body)

		if got := s.Stats().Refused[tc.code]; got != 1 {
			t.Errorf("body %q: %s counted %d times, want 1", tc.body, tc.code, got)
		}
	}
}

func TestRateLimitIsCounted(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1, Refill: time.Hour}, nil)

	post(t, s, `{"target":"counted-one.test"}`)
	post(t, s, `{"target":"counted-two.test"}`)

	if got := s.Stats().Refused["rate_limited"]; got != 1 {
		t.Errorf("rate_limited counted %d times, want 1", got)
	}
}

func TestTargetBusyIsCounted(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	exhaustTarget(t, s, `{"target":"counted-busy.test"}`, "198.51.100.")

	if got := s.Stats().Refused["target_busy"]; got != 1 {
		t.Errorf("target_busy counted %d times, want 1", got)
	}
}

// The published figures must not describe a request, however they are
// aggregated.
func TestStatsResponseNamesNobody(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	post(t, s, `{"target":"private-name.test"}`)
	postFrom(t, s, `{"target":"another-private-name.test"}`, "198.51.100.55:5000")

	r := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	r.RemoteAddr = "203.0.113.99:5000"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	body := w.Body.String()
	for _, leak := range []string{"private-name", "198.51.100", "203.0.113"} {
		if strings.Contains(body, leak) {
			t.Errorf("the stats response contains %q: %s", leak, body)
		}
	}

	var decoded map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if _, found := decoded["scansTotal"]; !found {
		t.Error("the response reports no total")
	}
}

// Snapshot holds a map and cannot be compared with ==. The caller that
// persists these needs to know whether anything changed, and getting it wrong
// means either writing every minute for ever or never writing at all.
func TestSnapshotEquality(t *testing.T) {
	a := Snapshot{Total: 5, Refused: map[string]uint64{"rate_limited": 2}}
	b := Snapshot{Total: 5, Refused: map[string]uint64{"rate_limited": 2}}

	if !a.Equal(b) {
		t.Error("two identical snapshots compared unequal")
	}

	b.Refused["rate_limited"] = 3
	if a.Equal(b) {
		t.Error("a changed refusal count compared equal")
	}

	c := Snapshot{Total: 5}
	if c.Equal(a) {
		t.Error("a snapshot with no refusals compared equal to one with some")
	}
}

// ── The connection limiter ───────────────────────────────────────────────

// A TLS handshake costs an elliptic curve operation before any HTTP arrives,
// so a client that connects and then does nothing never reaches a single
// request-level guard.
func TestListenerCapsConcurrentConnections(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer inner.Close()

	const limit = 3
	listener := LimitListener(inner, limit)

	accepted := make(chan net.Conn, limit*4)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	// Open more than the cap and keep them open.
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()

	for range limit * 3 {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			continue
		}
		held = append(held, c)
	}

	// Give the accept loop time to work through them.
	time.Sleep(200 * time.Millisecond)

	if got := len(accepted); got > limit {
		t.Errorf("%d connections were admitted, above the cap of %d", got, limit)
	}
	if len(accepted) == 0 {
		t.Error("no connection was admitted, so the cap refuses everything")
	}
}

// A slot must come back when a connection closes, or the server stops
// accepting after the first burst of ordinary traffic.
func TestClosingAConnectionReturnsItsSlot(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer inner.Close()

	listener := LimitListener(inner, 1)

	served := make(chan struct{}, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			served <- struct{}{}
			conn.Close()
		}
	}()

	// One at a time, several times over. Without the slot returning, only the
	// first would be admitted.
	for i := range 5 {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatalf("connection %d: %v", i+1, err)
		}
		select {
		case <-served:
		case <-time.After(2 * time.Second):
			t.Fatalf("connection %d was never admitted; a slot did not come back", i+1)
		}
		c.Close()
	}
}

// http.Server closes a connection more than once in some paths. Releasing the
// slot each time would let the cap drift upwards over the life of a process.
func TestDoubleCloseDoesNotLeakSlots(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer inner.Close()

	const limit = 2
	l := LimitListener(inner, limit).(*limitListener)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range limit {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Close()
			conn.Close()
			conn.Close()
		}
	}()

	for range limit {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatalf("dialling: %v", err)
		}
		c.Close()
	}
	wg.Wait()

	if got := len(l.slots); got != 0 {
		t.Errorf("%d slots are still held after every connection closed", got)
	}
	if cap(l.slots) != limit {
		t.Errorf("the cap changed to %d", cap(l.slots))
	}
}

// ── The published figures ────────────────────────────────────────────────

// The counters hold no timestamps, but a counter that can be polled is a
// clock. Reading the endpoint once a second would turn "5 scans" into "a scan
// happened at 14:32:08", which anyone holding the other end of that
// connection can compare against their own logs.
func TestPublishedFiguresStandStill(t *testing.T) {
	now := time.Now()
	c := newCounters(func() time.Time { return now })

	if got := c.publicSnapshot().Total; got != 0 {
		t.Fatalf("Total = %d, want 0", got)
	}

	for range 5 {
		c.record(policy.Strong)
	}
	now = now.Add(20 * time.Second)

	if got := c.publicSnapshot().Total; got != 0 {
		t.Errorf("the published total moved to %d within the minute; polling would time each scan", got)
	}

	// The live figure, which only this process reads, is current.
	if got := c.snapshot().Total; got != 5 {
		t.Errorf("the live total is %d, want 5: persistence must not be delayed", got)
	}

	now = now.Add(publishInterval)
	if got := c.publicSnapshot().Total; got != 5 {
		t.Errorf("the published total is %d after the interval, want 5", got)
	}
}

// ── Cross-site requests ──────────────────────────────────────────────────

// A page on another site can tell a browser to send this request, and it
// arrives carrying the visitor's address rather than the attacker's. The
// victim's allowance is spent on a scan they never asked for.
func TestCrossSiteRequestsAreRefused(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	send := func(site string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/scan",
			strings.NewReader(`{"target":"example.test"}`))
		r.Header.Set("Content-Type", "application/json")
		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}
		r.RemoteAddr = "203.0.113.77:5000"

		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}

	w := send("cross-site")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a cross-site request", w.Code)
	}
	if got := errorCode(t, w); got != "cross_site" {
		t.Errorf("code = %q, want cross_site", got)
	}
	if got := s.Stats().Refused["cross_site"]; got != 1 {
		t.Errorf("cross_site counted %d times, want 1", got)
	}

	// The page itself, and clients that are not browsers, must still work.
	// An absent header is a client that is not subject to this at all.
	for _, site := range []string{"same-origin", "same-site", "none", ""} {
		if w := send(site); w.Code == http.StatusForbidden {
			t.Errorf("Sec-Fetch-Site %q was refused; only cross-site should be", site)
		}
	}
}

// The scan endpoint was limited from the first day; these two were not. That
// was an omission: /api/v1/stats clones a map on every call, so a client
// asking a few thousand times a second turns a health check into a way of
// spending this machine's processor.
func TestReadEndpointsAreLimited(t *testing.T) {
	for _, path := range []string{"/healthz", "/api/v1/stats"} {
		s := New(offlineScanner(), Limits{}, nil)

		var limited bool
		for range readBurst + 10 {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.RemoteAddr = "203.0.113.90:5000"
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)

			if w.Code == http.StatusTooManyRequests {
				limited = true
				break
			}
		}
		if !limited {
			t.Errorf("%s served %d requests without a limit", path, readBurst+10)
		}
	}
}

// A client that has spent its scan allowance must not be able to refill it by
// asking for statistics, and a monitor polling a health check must not lose
// the ability to scan.
func TestReadAndScanBudgetsAreSeparate(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1, Refill: time.Hour}, nil)

	// Spend the scan allowance.
	post(t, s, `{"target":"first.test"}`)
	if w := post(t, s, `{"target":"second.test"}`); w.Code != http.StatusTooManyRequests {
		t.Fatal("the scan allowance was not spent")
	}

	// The read endpoints still answer.
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	r.RemoteAddr = "203.0.113.7:5000"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("healthz returned %d after the scan allowance was spent; the budgets are shared", w.Code)
	}
}
