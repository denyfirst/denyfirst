package httpapi

import (
	"net/http"
	"sync"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
)

// Snapshot is everything this service counts.
//
// It is worth reading the list for what is absent. There is no hostname, no
// client address, no timestamp beyond a date, and no ordering. Two scans a
// second apart and two scans a month apart leave the same trace, which is
// none: only a number goes up.
//
// That is what makes it publishable. A reader can see the tool is used, and
// nobody — including whoever seizes the machine — can learn who used it or
// what they looked at.
type Snapshot struct {
	Total    uint64 `json:"scansTotal"`
	Strong   uint64 `json:"strong"`
	Weak     uint64 `json:"weak"`
	Insecure uint64 `json:"insecure"`
	Ungraded uint64 `json:"ungraded"`

	// Today resets at midnight UTC. TodayDate exists only so a restart can
	// tell whether the figure still belongs to the current day.
	Today     uint64 `json:"scansToday"`
	TodayDate string `json:"todayDate,omitempty"`

	// Since is the date counting began, so a total can be read as a rate.
	Since string `json:"since,omitempty"`
}

// counters accumulates the numbers above.
//
// Nothing here writes to disk. The package that handles untrusted input
// touches no files at all, which removes an entire class of question from the
// request path. Persistence belongs to the caller, through Stats and
// RestoreStats.
type counters struct {
	now func() time.Time

	mu   sync.Mutex
	data Snapshot
}

func newCounters(now func() time.Time) *counters {
	if now == nil {
		now = time.Now
	}
	c := &counters{now: now}
	c.data.Since = now().UTC().Format(time.DateOnly)
	c.data.TodayDate = c.data.Since
	return c
}

// record adds one completed scan.
func (c *counters) record(verdict policy.Verdict) {
	today := c.now().UTC().Format(time.DateOnly)

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.data.TodayDate != today {
		c.data.TodayDate = today
		c.data.Today = 0
	}

	c.data.Total++
	c.data.Today++

	switch verdict {
	case policy.Strong:
		c.data.Strong++
	case policy.Weak:
		c.data.Weak++
	case policy.Insecure:
		c.data.Insecure++
	default:
		c.data.Ungraded++
	}
}

func (c *counters) snapshot() Snapshot {
	today := c.now().UTC().Format(time.DateOnly)

	c.mu.Lock()
	defer c.mu.Unlock()

	out := c.data
	if out.TodayDate != today {
		// The stored figure belongs to a day that has ended.
		out.Today = 0
		out.TodayDate = today
	}
	return out
}

func (c *counters) restore(s Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Only the accumulated figures are taken. A restored Since is kept if it
	// is present, because it is the date counting began rather than the date
	// this process started.
	c.data.Total = s.Total
	c.data.Strong = s.Strong
	c.data.Weak = s.Weak
	c.data.Insecure = s.Insecure
	c.data.Ungraded = s.Ungraded

	if s.Since != "" {
		c.data.Since = s.Since
	}

	today := c.now().UTC().Format(time.DateOnly)
	if s.TodayDate == today {
		c.data.Today = s.Today
		c.data.TodayDate = s.TodayDate
	}
}

// Stats returns the current figures, for a caller that wants to persist them.
func (s *Server) Stats() Snapshot {
	return s.counts.snapshot()
}

// RestoreStats seeds the counters from a previous run. Call it before serving.
func (s *Server) RestoreStats(snapshot Snapshot) {
	s.counts.restore(snapshot)
}

type statsResponse struct {
	Snapshot
	Policy string `json:"policy"`
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, statsResponse{
		Snapshot: s.counts.snapshot(),
		Policy:   policy.Version,
	})
}
