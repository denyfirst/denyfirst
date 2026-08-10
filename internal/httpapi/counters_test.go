package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
)

// The whole argument for publishing these numbers is that they identify
// nobody. A field carrying a hostname, an address, or a per-request timestamp
// would break that, and it would break it quietly, because the numbers would
// still look like numbers.
func TestSnapshotHoldsNothingIdentifying(t *testing.T) {
	allowed := map[string]bool{
		"Total": true, "Strong": true, "Weak": true, "Insecure": true,
		"Ungraded": true, "Today": true, "TodayDate": true, "Since": true,
	}

	fields := reflect.TypeOf(Snapshot{})
	for i := range fields.NumField() {
		name := fields.Field(i).Name
		if !allowed[name] {
			t.Errorf("Snapshot has a field %q that nobody reviewed. Aggregate counts may be published; anything that describes a single request may not.", name)
		}
	}
}

func TestCountersRecordVerdicts(t *testing.T) {
	c := newCounters(nil)

	c.record(policy.Strong)
	c.record(policy.Weak)
	c.record(policy.Weak)
	c.record(policy.Insecure)
	c.record(policy.Ungraded)

	got := c.snapshot()

	if got.Total != 5 {
		t.Errorf("Total = %d, want 5", got.Total)
	}
	if got.Strong != 1 || got.Weak != 2 || got.Insecure != 1 || got.Ungraded != 1 {
		t.Errorf("verdict breakdown = %+v", got)
	}
	if got.Today != 5 {
		t.Errorf("Today = %d, want 5", got.Today)
	}
}

func TestTodayResetsAtMidnight(t *testing.T) {
	now := time.Date(2026, 8, 10, 23, 0, 0, 0, time.UTC)
	c := newCounters(func() time.Time { return now })

	c.record(policy.Strong)
	c.record(policy.Weak)
	if got := c.snapshot().Today; got != 2 {
		t.Fatalf("Today = %d, want 2", got)
	}

	now = now.Add(2 * time.Hour) // past midnight

	if got := c.snapshot().Today; got != 0 {
		t.Errorf("Today = %d after the day ended, want 0", got)
	}
	if got := c.snapshot().Total; got != 2 {
		t.Errorf("Total = %d, want it unaffected by the day changing", got)
	}

	c.record(policy.Strong)
	if got := c.snapshot().Today; got != 1 {
		t.Errorf("Today = %d on the new day, want 1", got)
	}
}

// A deploy must not zero the number on the site.
func TestRestoreCarriesTotalsAcrossRestart(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	first := newCounters(clock)
	for range 100 {
		first.record(policy.Insecure)
	}
	saved := first.snapshot()

	second := newCounters(clock)
	second.restore(saved)
	second.record(policy.Strong)

	got := second.snapshot()
	if got.Total != 101 {
		t.Errorf("Total = %d after restore, want 101", got.Total)
	}
	if got.Insecure != 100 {
		t.Errorf("Insecure = %d, want 100", got.Insecure)
	}
	if got.Since != saved.Since {
		t.Errorf("Since = %q, want the original %q: it is the date counting began, not the date this process started", got.Since, saved.Since)
	}
}

// A figure from an earlier day must not be presented as today's.
func TestRestoreDropsAStaleDailyFigure(t *testing.T) {
	yesterday := Snapshot{Total: 500, Today: 42, TodayDate: "2026-08-09", Since: "2026-01-01"}

	now := time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)
	c := newCounters(func() time.Time { return now })
	c.restore(yesterday)

	got := c.snapshot()
	if got.Today != 0 {
		t.Errorf("Today = %d, want 0: the stored figure belonged to a day that has ended", got.Today)
	}
	if got.Total != 500 {
		t.Errorf("Total = %d, want 500", got.Total)
	}
}

func TestCountersAreSafeUnderConcurrency(t *testing.T) {
	c := newCounters(nil)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				c.record(policy.Weak)
			}
		}()
	}
	wg.Wait()

	if got := c.snapshot().Total; got != 5000 {
		t.Errorf("Total = %d, want 5000", got)
	}
}

func TestStatsEndpoint(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000}, nil)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	r.RemoteAddr = "203.0.113.60:1000"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if _, found := body["scansTotal"]; !found {
		t.Error("the response does not report a total")
	}
	if body["policy"] == "" {
		t.Error("the response does not name the policy")
	}

	// The response is published on a public page, so it must not have picked
	// up anything from the request that produced it.
	for _, leak := range []string{"203.0.113", "RemoteAddr", "userAgent"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Errorf("the stats response contains %q", leak)
		}
	}
}

func TestStatsRejectsWrite(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000}, nil)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/stats", strings.NewReader("{}"))
	r.RemoteAddr = "203.0.113.61:1000"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}
