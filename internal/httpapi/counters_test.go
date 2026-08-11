package httpapi

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
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

	for i := range targetBurst + 1 {
		postFrom(t, s, `{"target":"counted-busy.test"}`, "198.51.100."+strconv.Itoa(i+1)+":5000")
	}

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
