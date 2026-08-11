package httpapi

import (
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
)

// refusalCodes are the reasons a request can be turned away, and the complete
// set of keys that may appear in Snapshot.Refused.
//
// Counting by reason rather than by requester is the whole design. "Blocked
// destinations rose from two a day to eight thousand" is the sentence an
// operator needs, and it can be said without knowing who asked or what they
// asked about. A service that could not see that at all would be asking its
// users to trust an operator who is not watching.
//
// A test asserts that nothing outside this list is ever counted. Without it,
// somebody adding a reason keyed on a hostname would produce a file that
// still looks like a list of numbers.
var refusalCodes = []string{
	"rate_limited",        // one client asking too often
	"target_busy",         // one host being scanned too often, whoever asks
	"too_busy",            // every scan slot in use
	"blocked_destination", // safedial refused: private, loopback, reserved
	"invalid_target",      // malformed hostname
	"hostname_required",   // an address where a name is needed
	"port_not_allowed",    // outside the implicit-TLS list
	"bad_request",         // the body was not one JSON object
	"payload_too_large",   // over the body limit
	"unsupported_media",   // not application/json
	"cross_site",          // a browser request originating on another site
	"timeout",             // the scan outlasted its budget
	"scan_failed",         // the target could not be reached
}

// Snapshot is everything this service counts.
//
// It is worth reading for what is absent. There is no hostname, no client
// address, no timestamp beyond a date, and no ordering. Two scans a second
// apart and two a month apart leave the same trace, which is none: some
// numbers go up.
//
// That is what makes it publishable. A reader can see the tool is used and
// that its guards fire, and nobody — including whoever seizes the machine —
// can learn who used it or what they looked at.
type Snapshot struct {
	Total    uint64 `json:"scansTotal"`
	Strong   uint64 `json:"strong"`
	Weak     uint64 `json:"weak"`
	Insecure uint64 `json:"insecure"`
	Ungraded uint64 `json:"ungraded"`

	// Refused counts requests turned away, by reason. Keys come from
	// refusalCodes and nowhere else.
	Refused map[string]uint64 `json:"refused,omitempty"`

	// Today resets at midnight UTC. TodayDate exists only so a restart can
	// tell whether the figure still belongs to the current day.
	Today     uint64 `json:"scansToday"`
	TodayDate string `json:"todayDate,omitempty"`

	// Since is the date counting began, so a total can be read as a rate.
	Since string `json:"since,omitempty"`
}

// Equal compares two snapshots.
//
// Snapshot holds a map, so it cannot be compared with ==. The caller that
// persists these needs to know whether anything changed since the last write,
// and getting that wrong means either writing every minute for ever or never
// writing at all.
func (s Snapshot) Equal(other Snapshot) bool {
	return s.Total == other.Total &&
		s.Strong == other.Strong &&
		s.Weak == other.Weak &&
		s.Insecure == other.Insecure &&
		s.Ungraded == other.Ungraded &&
		s.Today == other.Today &&
		s.TodayDate == other.TodayDate &&
		s.Since == other.Since &&
		maps.Equal(s.Refused, other.Refused)
}

// counters accumulates the numbers above.
//
// Nothing here writes to disk. The package that handles untrusted input
// touches no files at all, which removes an entire class of question from the
// request path. Persistence belongs to the caller, through Stats and
// RestoreStats.
// publishInterval is how long the figures served over HTTP stand still.
//
// The counters hold no timestamps, but a counter that can be polled is a
// clock. Reading the endpoint once a second turns "5 scans" into "a scan
// happened at 14:32:08", which is material anyone holding the other end of
// that connection can correlate against their own logs.
//
// Freezing the published figures to a whole minute widens that window from a
// second to sixty, which is enough to make the comparison useless. The
// figures written to disk stay live, because nobody is watching them.
const publishInterval = time.Minute

type counters struct {
	now func() time.Time

	mu   sync.Mutex
	data Snapshot

	// published is what the endpoint serves, refreshed at most once per
	// publishInterval.
	published   Snapshot
	publishedAt time.Time
}

func newCounters(now func() time.Time) *counters {
	if now == nil {
		now = time.Now
	}
	c := &counters{now: now}
	c.data.Since = now().UTC().Format(time.DateOnly)
	c.data.TodayDate = c.data.Since
	c.data.Refused = map[string]uint64{}
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

// refuse adds one turned-away request.
//
// An unknown code is dropped rather than counted. The alternative is a map
// that grows with whatever string a future caller passes, which is how a
// bounded counter becomes an unbounded one, and how something identifying
// eventually ends up in a file that is published.
func (c *counters) refuse(code string) {
	if !slices.Contains(refusalCodes, code) {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.data.Refused == nil {
		c.data.Refused = map[string]uint64{}
	}
	c.data.Refused[code]++
}

// snapshot returns the live figures. Used for persistence, where the only
// reader is the process itself.
func (c *counters) snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshotLocked()
}

func (c *counters) snapshotLocked() Snapshot {
	today := c.now().UTC().Format(time.DateOnly)

	out := c.data
	out.Refused = maps.Clone(c.data.Refused)

	if out.TodayDate != today {
		// The stored figure belongs to a day that has ended.
		out.Today = 0
		out.TodayDate = today
	}
	return out
}

// publicSnapshot returns figures that stand still for a minute at a time.
//
// This is what the endpoint serves. See publishInterval for why it is not the
// live figure: a counter anyone can poll is a clock, and this project already
// promises there is no time in what it keeps.
func (c *counters) publicSnapshot() Snapshot {
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.publishedAt.IsZero() || now.Sub(c.publishedAt) >= publishInterval {
		c.published = c.snapshotLocked()
		c.publishedAt = now
	}
	return c.published
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

	// Restored keys are filtered too. A file edited by hand, or written by an
	// older version, must not be able to introduce a key this version would
	// never produce.
	c.data.Refused = map[string]uint64{}
	for code, count := range s.Refused {
		if slices.Contains(refusalCodes, code) {
			c.data.Refused[code] = count
		}
	}

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
		Snapshot: s.counts.publicSnapshot(),
		Policy:   policy.Version,
	})
}
