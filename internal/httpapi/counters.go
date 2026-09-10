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
	"port_not_accepted",   // a port given to a check that takes none
	"bad_request",         // the body was not one JSON object
	"payload_too_large",   // over the body limit
	"unsupported_media",   // not application/json
	"cross_site",          // a browser request originating on another site
	"excluded",            // a name this service will not scan
	"timeout",             // the scan outlasted its budget
	"scan_failed",         // the target could not be reached

	// Only a demonstration build can produce this one: the ordinary build has
	// no list to be outside of. It is counted rather than left silent because
	// a figure that rises here says visitors are asking for something this
	// deployment does not do, which is the sentence that would tell us the
	// page is not explaining itself.
	"not_demonstrated", // a host outside what this deployment demonstrates

	// Only a deployment that requires proof of control can produce this one,
	// and it is the figure that says whether the requirement is understood.
	// A number rising here is not an attack: it is people asking about
	// domains they have not published a record for, which is either a
	// procedure nobody was told about or a record that stopped resolving.
	// Both are things an operator wants to see, and neither can be seen from
	// a scan count.
	"not_verified", // a domain this deployment has not been shown control of
}

// checkNames are the checks this service counts, and the complete set of keys
// that may appear in Snapshot.Checks.
//
// Named for the check rather than for its rule set, and the difference is what
// keeps a figure readable across a rule set moving. "denyfirst-tls-v6" as a key
// would become "denyfirst-tls-v7" one day, and the counter for a check would
// then restart under a new name while the old one sat in the file for ever. A
// scan is a scan of the TLS check whichever version of the rules graded it, so
// the key is the check and the version is a field inside.
//
// The names are the ones that already exist in three places: the two paths on
// this service, and the -check flag on the command line. A fourth spelling
// would be a fourth thing to keep in step.
var checkNames = []string{"tls", "web"}

// CheckCounts is one check's figures.
//
// It exists because a verdict stopped meaning one thing the moment a second
// check did. denyfirst-tls-v6 grades a handshake and a certificate;
// denyfirst-web-v2 grades an HTTP response, which most of the ports this
// project dials do not have. A "strong" adding the two together describes
// nothing that can be checked, which is R22 read as arithmetic.
type CheckCounts struct {
	// Policy names the rule set that graded these scans. Stamped from the
	// current version when the figures are read rather than taken from a
	// restored file, so a published block cannot claim a version this build
	// does not grade by.
	Policy string `json:"policy,omitempty"`

	Total    uint64 `json:"scansTotal"`
	Strong   uint64 `json:"strong"`
	Weak     uint64 `json:"weak"`
	Insecure uint64 `json:"insecure"`
	Ungraded uint64 `json:"ungraded"`
	Today    uint64 `json:"scansToday"`
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
	//
	// Not split by check. A refusal is a property of this service's guards
	// rather than of a rule set: a rate_limited is the same event whichever
	// endpoint it arrived at, and the figure an operator watches is how much
	// of that is arriving at all.
	Refused map[string]uint64 `json:"refused,omitempty"`

	// Checks carries one block per check, each naming its own rule set.
	//
	// The fields above are the TLS check's, unchanged and meaning exactly
	// what they meant before this field existed, and "tls" here repeats them.
	// That duplication is deliberate. /api/v1/stats is published, this
	// project's own page reads it, and so does whatever anybody else has
	// written against it; a field that keeps its name and changes its meaning
	// is the kind of change nobody notices until a graph has been wrong for a
	// month. So nothing moves, and the second check arrives beside the first
	// rather than inside it.
	//
	// It also survives a rollback. cmd/denyfirstd reads this file with a
	// plain json.Unmarshal, so an older binary ignores this field and reads
	// the figures above — which still describe the TLS check, and not a total
	// with somebody else's scans folded into it.
	//
	// Keys come from checkNames and nowhere else, and a key appears only once
	// a scan of that check has been counted: a block of zeros for a check
	// this build cannot run would be a figure that reads as "this never
	// happens" when what happened is that nobody wired it up.
	Checks map[string]CheckCounts `json:"checks,omitempty"`

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
		maps.Equal(s.Refused, other.Refused) &&
		maps.Equal(s.Checks, other.Checks)
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

// record adds one completed scan of one check.
//
// An unknown check is dropped rather than counted, for the reason refuse()
// drops an unknown code: the alternative is a map that grows with whatever
// string a future caller passes, which is how a bounded counter becomes an
// unbounded one and how something identifying ends up in a file that is
// published.
func (c *counters) record(check string, verdict policy.Verdict) {
	if !slices.Contains(checkNames, check) {
		return
	}

	today := c.now().UTC().Format(time.DateOnly)

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.data.TodayDate != today {
		c.data.TodayDate = today
		c.data.Today = 0
		for name, counts := range c.data.Checks {
			counts.Today = 0
			c.data.Checks[name] = counts
		}
	}

	if c.data.Checks == nil {
		c.data.Checks = map[string]CheckCounts{}
	}
	counts := c.data.Checks[check]
	counts.Total++
	counts.Today++
	switch verdict {
	case policy.Strong:
		counts.Strong++
	case policy.Weak:
		counts.Weak++
	case policy.Insecure:
		counts.Insecure++
	default:
		// R4: an empty verdict means nothing was established, which is not
		// passing and not failing. It has its own column.
		counts.Ungraded++
	}
	c.data.Checks[check] = counts
}

// checkTLS and checkWeb are the keys in Snapshot.Checks. Spelled once.
const (
	checkTLS = "tls"
	checkWeb = "web"
)

// project copies the TLS check's figures into the fields at the top of a
// Snapshot.
//
// Those fields are the TLS check's and have been since before there was a
// second check to confuse them with. They are derived here rather than
// maintained alongside, because two counters incremented in two places is two
// places for one number to drift, and the one that drifts is the one nobody
// reads until it is published.
func (s *Snapshot) project() {
	tls := s.Checks[checkTLS]
	s.Total = tls.Total
	s.Strong = tls.Strong
	s.Weak = tls.Weak
	s.Insecure = tls.Insecure
	s.Ungraded = tls.Ungraded
	s.Today = tls.Today
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
	out.Checks = maps.Clone(c.data.Checks)

	if out.TodayDate != today {
		// The stored figures belong to a day that has ended.
		out.TodayDate = today
		for name, counts := range out.Checks {
			counts.Today = 0
			out.Checks[name] = counts
		}
	}

	// The rule set is stamped on the way out rather than carried in the
	// counters. A restored file was written by some earlier build, and a
	// block that named that build's rules while this one graded the scans
	// would be a version claim nothing behind it supports.
	for name, counts := range out.Checks {
		switch name {
		case checkTLS:
			counts.Policy = policy.TLSVersion
		case checkWeb:
			counts.Policy = policy.WebVersion
		}
		out.Checks[name] = counts
	}

	out.project()
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
	//
	// Keys are filtered exactly as the refusal codes are: a file edited by
	// hand, or written by a version that counted something this one does not,
	// must not introduce a key this build would never produce.
	c.data.Checks = map[string]CheckCounts{}
	for name, counts := range s.Checks {
		if slices.Contains(checkNames, name) {
			// The version is dropped rather than restored. What actually
			// holds is the stamp in snapshotLocked, which every read goes
			// through — clearing it here changes nothing a caller can
			// observe, and a sabotage that removed this line escaped every
			// test. It stays so that the field is empty in memory too: a
			// future reader of c.data that skipped the stamp would otherwise
			// pick up a version some earlier build wrote.
			counts.Policy = ""
			c.data.Checks[name] = counts
		}
	}

	// A file written before Checks existed carries the TLS figures at the top
	// and nothing else, so they are read from there.
	//
	// Only when there is no block already, and only when something was
	// counted. Preferring the top-level fields over a block that is present
	// would undo a day's counting every time an older file was read back, and
	// seeding an empty block from an empty file would create a key for a
	// check nobody has run.
	if _, found := c.data.Checks[checkTLS]; !found && s.Total > 0 {
		c.data.Checks[checkTLS] = CheckCounts{
			Total:    s.Total,
			Strong:   s.Strong,
			Weak:     s.Weak,
			Insecure: s.Insecure,
			Ungraded: s.Ungraded,
			Today:    s.Today,
		}
	}

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

	// The daily figures are kept only if the file belongs to the current day.
	//
	// Every check's, not only the one at the top. A restart the morning after
	// a busy night would otherwise report yesterday's web scans as today's,
	// which is the one thing a figure named "today" must not do.
	today := c.now().UTC().Format(time.DateOnly)
	if s.TodayDate == today {
		c.data.TodayDate = s.TodayDate
		return
	}
	for name, counts := range c.data.Checks {
		counts.Today = 0
		c.data.Checks[name] = counts
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
		Policy:   policy.TLSVersion,
	})
}
