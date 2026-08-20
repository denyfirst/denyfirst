package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/safedial"
	"github.com/denyfirst/denyfirst/internal/scan"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

// blockedScanner stands in for a name that resolves only to an address
// safedial refuses: private, loopback, link-local or reserved.
func blockedScanner() *scan.Scanner {
	return &scan.Scanner{
		Prober: &tlsprobe.Prober{
			Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
				return nil, fmt.Errorf("%w: 127.0.0.1 is loopback", safedial.ErrBlocked)
			},
		},
	}
}

// holdingScanner keeps a scan slot until it is released, whatever the request
// deadline says. blockingScanner gives the slot back when the context ends,
// which is right for measuring a timeout and wrong for measuring what happens
// when every slot is taken.
func holdingScanner(release <-chan struct{}) *scan.Scanner {
	return &scan.Scanner{
		Prober: &tlsprobe.Prober{
			Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
				<-release
				return nil, errors.New("released")
			},
		},
	}
}

// The whole point of counting refusals is that a change in the shape of them
// means something. A code that no request can produce is a figure that reads
// as "this never happens" when what happened is that nobody wired it up.
//
// blocked_destination was exactly that: declared, documented as the signal
// for somebody using this service as a way into the network it runs in, and
// permanently zero, because safedial's refusal became a note inside a
// successful report instead of a refusal.
func TestEveryRefusalCodeCanBeProduced(t *testing.T) {
	produced := map[string]bool{}

	note := func(w *httptest.ResponseRecorder, want string) {
		t.Helper()
		got := errorCode(t, w)
		if got != want {
			t.Errorf("got code %q, want %q (status %d)", got, want, w.Code)
			return
		}
		produced[got] = true
	}

	// ── the cheap refusals, one server each so the limits stay separate ──
	{
		s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
		note(postFrom(t, s, `not json`, "203.0.113.2:5000"), "bad_request")
		note(postFrom(t, s, `{"target":"exam ple.test"}`, "203.0.113.3:5000"), "invalid_target")
		note(postFrom(t, s, `{"target":"example.test:22"}`, "203.0.113.4:5000"), "port_not_allowed")
		note(postFrom(t, s, `{"target":"93.184.216.34"}`, "203.0.113.5:5000"), "hostname_required")
		note(postFrom(t, s, `{"target":"army.mil"}`, "203.0.113.6:5000"), "excluded")
		note(postFrom(t, s, `{"target":"`+strings.Repeat("a", 9000)+`.test"}`, "203.0.113.8:5000"), "payload_too_large")
	}

	// ── the header checks ──
	{
		s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(`{"target":"example.test"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		r.RemoteAddr = "203.0.113.9:5000"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		note(w, "cross_site")

		r = httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(`{"target":"example.test"}`))
		r.Header.Set("Content-Type", "text/plain")
		r.RemoteAddr = "203.0.113.10:5000"
		w = httptest.NewRecorder()
		s.ServeHTTP(w, r)
		note(w, "unsupported_media")
	}

	// ── one client spending its own allowance ──
	{
		s := New(offlineScanner(), Limits{Burst: 1, Refill: time.Hour}, nil)
		postFrom(t, s, `{"target":"first.test"}`, "203.0.113.11:5000")
		note(postFrom(t, s, `{"target":"second.test"}`, "203.0.113.11:5000"), "rate_limited")
	}

	// ── many clients spending one host's allowance ──
	{
		s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
		for i := range targetBurst {
			postFrom(t, s, `{"target":"busy.test"}`, "203.0.113."+strconv.Itoa(100+i)+":5000")
		}
		note(postFrom(t, s, `{"target":"busy.test"}`, "203.0.113.150:5000"), "target_busy")
	}

	// ── every scan slot in use ──
	//
	// The holder ignores the request deadline, so it keeps the only slot for
	// as long as this block needs it. blockingScanner respects the deadline
	// and would hand the slot back before the second request gave up, which
	// measures the timeout rather than the semaphore.
	{
		release := make(chan struct{})
		var holding sync.WaitGroup

		s := New(holdingScanner(release), Limits{
			Burst: 1000, Refill: time.Nanosecond,
			MaxConcurrent:  1,
			RequestTimeout: 200 * time.Millisecond,
		}, nil)

		holding.Add(1)
		go func() {
			defer holding.Done()
			postFrom(t, s, `{"target":"holding.test"}`, "203.0.113.60:5000")
		}()
		waitForScanSlot(t, s)

		note(postFrom(t, s, `{"target":"waiting.test"}`, "203.0.113.61:5000"), "too_busy")

		close(release)
		holding.Wait()
	}

	// ── the scan outlasting its budget ──
	{
		release := make(chan struct{})
		defer close(release)

		s := New(blockingScanner(release), Limits{
			Burst: 1000, Refill: time.Nanosecond,
			RequestTimeout: 30 * time.Millisecond,
		}, nil)
		note(postFrom(t, s, `{"target":"slow.test"}`, "203.0.113.70:5000"), "timeout")
	}

	// ── a name that resolves only where this service will not go ──
	{
		s := New(blockedScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
		w := postFrom(t, s, `{"target":"internal.test"}`, "203.0.113.80:5000")
		if w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 for a destination the service refuses", w.Code)
		}
		note(w, "blocked_destination")

		if got := s.Stats().Refused["blocked_destination"]; got != 1 {
			t.Errorf("blocked_destination counted %d times, want 1: this figure is the only sign an "+
				"operator gets that somebody is aiming this service at the network it runs in", got)
		}
		if body := w.Body.String(); strings.Contains(body, "127.0.0.1") {
			t.Errorf("the refusal repeats an address back to the caller: %s", body)
		}
	}

	// Named so that silence is not mistaken for an oversight, which is the
	// same reason the threat model has a section for what it does not cover.
	//
	// scan.Scan reports an error only if it could not begin, and by the time
	// the handler calls it every reason it could refuse has already been
	// checked. So the branch is unreachable from outside — and it is written
	// as a counted refusal anyway, because the signature permits an error and
	// an uncounted one would be exactly the hole this test exists to find.
	//
	// If this list ever grows, the entry needs a sentence here saying why. If
	// scan_failed becomes reachable, drive it above and take it out.
	defensive := map[string]string{
		"scan_failed": "scan.Scan cannot fail once the handler has validated the target",
	}

	for _, code := range refusalCodes {
		if produced[code] {
			if why, ok := defensive[code]; ok {
				t.Errorf("%q is listed as unreachable (%s) but this test produced it; drive it "+
					"deliberately and remove it from the list", code, why)
			}
			continue
		}
		if _, ok := defensive[code]; ok {
			continue
		}
		t.Errorf("no request in this test produces %q. Either a handler stopped emitting it, or it "+
			"was never wired up and the published figure for it is permanently zero.", code)
	}
	for code := range produced {
		if !slices.Contains(refusalCodes, code) {
			t.Errorf("a request produced code %q, which is not in refusalCodes and is therefore not counted", code)
		}
	}
}

// waitForScanSlot blocks until the semaphore is occupied, so a test measuring
// what happens when it is full is not racing the goroutine that fills it.
func waitForScanSlot(t *testing.T, s *Server) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(s.sem) > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no scan ever took a slot")
}

// A refusal is cheap, not free: it takes the counter lock and it moves a
// figure this service publishes.
//
// The two header checks used to sit in front of the rate limiter so that a
// cross-site request could not spend the victim's scan allowance on their
// behalf. That reasoning is kept — the allowance spent is the read one — but
// the conclusion that an early refusal needs no limit at all was wrong: it
// left an unauthenticated client able to drive any of these counters to any
// value, and the counters are the only thing an operator has to watch.
func TestRefusalsBeforeTheScanAreLimited(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header [2]string
		want   int
	}{
		{"cross-site", [2]string{"Sec-Fetch-Site", "cross-site"}, http.StatusForbidden},
		{"wrong content type", [2]string{"Content-Type", "text/plain"}, http.StatusUnsupportedMediaType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New(offlineScanner(), Limits{Burst: 1, Refill: time.Hour}, nil)

			limited := 0
			for i := 0; i < readBurst*10; i++ {
				r := httptest.NewRequest(http.MethodPost, "/api/v1/scan",
					strings.NewReader(`{"target":"example.test"}`))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set(tc.header[0], tc.header[1])
				r.RemoteAddr = "203.0.113.90:5000"

				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)

				switch w.Code {
				case tc.want:
				case http.StatusTooManyRequests:
					limited++
				default:
					t.Fatalf("request %d: status %d", i, w.Code)
				}
			}

			if limited == 0 {
				t.Errorf("%d refusals from one address and none was rate limited; an unlimited refusal "+
					"path is a way to spend this machine's processor and a way to write into the "+
					"published counters", readBurst*10)
			}
		})
	}
}

// TestReadAndScanBudgetsAreSeparate covers one direction: a client that has
// spent its scan allowance can still poll. This is the other direction, and
// it is the one the read gate at the top of handleScan could break — the
// scan path now spends a read token, so a busy monitor must not be able to
// starve the scan it is monitoring.
func TestPollingReadsDoesNotSpendTheScanAllowance(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1, Refill: time.Hour}, nil)

	for i := 0; i < readBurst-2; i++ {
		r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		r.RemoteAddr = "203.0.113.95:5000"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("health check %d: status %d", i, w.Code)
		}
	}

	if w := postFrom(t, s, `{"target":"example.test"}`, "203.0.113.95:5000"); w.Code == http.StatusTooManyRequests {
		t.Error("polling the health check spent this client's scan allowance")
	}
}
