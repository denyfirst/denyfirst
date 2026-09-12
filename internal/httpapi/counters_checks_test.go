package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/policy"
)

// statsBody returns what a client reading /api/v1/stats actually receives.
func statsBody(t *testing.T, s *Server) map[string]any {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, "/api/v1/stats", nil)
	r.RemoteAddr = "203.0.113.201:5000"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding the stats response: %v", err)
	}
	return out
}

// The published shape does not change.
//
// /api/v1/stats is public, this project's page reads it, and so does whatever
// anybody else has written against it. Every field that was there is still
// there, still spelled the same way, and still counting the same thing — the
// TLS check, which is what it counted before there was a second check to
// confuse it with. A field that keeps its name and changes its meaning is the
// change nobody notices until a graph has been wrong for a month.
func TestThePublishedFieldsKeepTheirNamesAndTheirMeaning(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	for _, target := range []string{"one.test", "two.test", "three.test"} {
		post(t, s, `{"target":"`+target+`"}`)
	}

	body := statsBody(t, s)
	for _, field := range []string{
		"scansTotal", "strong", "weak", "insecure", "ungraded",
		"scansToday", "todayDate", "since", "policy",
	} {
		if _, found := body[field]; !found {
			t.Errorf("the response no longer carries %q; something already reads it", field)
		}
	}
	if got := body["policy"]; got != policy.TLSVersion {
		t.Errorf("the top-level policy is %v, want %s: it names the rule set the figures beside it "+
			"were graded by", got, policy.TLSVersion)
	}
	if got := body["scansTotal"]; got != float64(3) {
		t.Errorf("scansTotal = %v, want 3", got)
	}
}

// The TLS block repeats the figures at the top, exactly.
//
// The duplication is the whole design: nothing moves, and the second check
// arrives beside the first rather than inside it. A reader who wants one
// check's figures reads Checks and never has to know that one of them is also
// spelled out above.
func TestTheTopLevelFiguresAreTheTLSCheck(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	post(t, s, `{"target":"one.test"}`)
	post(t, s, `{"target":"two.test"}`)

	snap := s.Stats()
	tls, found := snap.Checks[checkTLS]
	if !found {
		t.Fatal("a TLS scan was counted and there is no tls block")
	}

	if tls.Total != snap.Total || tls.Strong != snap.Strong || tls.Weak != snap.Weak ||
		tls.Insecure != snap.Insecure || tls.Ungraded != snap.Ungraded || tls.Today != snap.Today {
		t.Errorf("the tls block and the figures at the top disagree:\n  top   %+v\n  block %+v", snap, tls)
	}
}

// Every block names the rule set that graded it (R22).
//
// A verdict stopped meaning one thing the moment a second check existed.
// denyfirst-tls-v6 grades a handshake and a certificate; denyfirst-web-v2
// grades an HTTP response, which most of the ports this project dials do not
// have. A number that does not say which of those it came from says nothing.
func TestEveryCheckBlockNamesItsOwnRuleSet(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	post(t, s, `{"target":"one.test"}`)
	s.counts.record(checkWeb, policy.Strong)

	want := map[string]string{checkTLS: policy.TLSVersion, checkWeb: policy.WebVersion}
	for name, counts := range s.Stats().Checks {
		if counts.Policy != want[name] {
			t.Errorf("the %q block names %q, want %q", name, counts.Policy, want[name])
		}
	}
	if policy.TLSVersion == policy.WebVersion {
		t.Error("the two rule sets share a name, so naming them proves nothing")
	}
}

// A second check does not move the first one's figures.
//
// This is R22 as arithmetic and it is the reason the split exists: a "strong"
// adding a handshake to an HTTP response describes nothing anybody can check.
func TestAWebScanDoesNotMoveTheTLSFigures(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	post(t, s, `{"target":"one.test"}`)

	before := s.Stats()
	s.counts.record(checkWeb, policy.Strong)
	s.counts.record(checkWeb, policy.Insecure)
	after := s.Stats()

	if after.Total != before.Total || after.Strong != before.Strong ||
		after.Insecure != before.Insecure || after.Today != before.Today {
		t.Errorf("web scans moved the TLS figures:\n  before %+v\n  after  %+v", before, after)
	}
	if got := after.Checks[checkWeb].Total; got != 2 {
		t.Errorf("the web block counted %d scans, want 2", got)
	}
}

// A key appears only once a scan of that check has been counted.
//
// A block of zeros for a check this build cannot run is a figure that reads as
// "this never happens" when what happened is that nobody wired it up, which is
// the mistake A7 is written about.
func TestACheckWithNoScansHasNoBlock(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	post(t, s, `{"target":"one.test"}`)

	if _, found := s.Stats().Checks[checkWeb]; found {
		t.Error("a web block exists before any web scan was counted")
	}
}

// An unknown check is dropped rather than counted.
//
// The same rule refuse() applies to an unknown code, for the same reason: a
// map that grows with whatever string a caller passes is how a bounded counter
// becomes an unbounded one, and how something identifying reaches a published
// file.
func TestOnlyKnownChecksAreCounted(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	s.counts.record("mail", policy.Strong)
	s.counts.record("192.0.2.7", policy.Strong)
	s.counts.record("", policy.Strong)

	for name := range s.Stats().Checks {
		if !slices.Contains(checkNames, name) {
			t.Errorf("the counters hold a block for %q, which is not a check this build runs", name)
		}
	}
}

// Every key that may appear is one a request can produce.
//
// The second half of A7, applied to this map. A counter that cannot move is
// not a low number; it is silence, and an operator reads silence as nothing
// happening. Both checks have an address now, so both are driven here; a check
// added later and left undriven fails this rather than shipping a figure that
// is permanently zero.
func TestEveryCountedCheckCanOccur(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	s.UseWebScanner(offlineWebScanner())

	post(t, s, `{"target":"one.test"}`)
	postWeb(t, s, `{"target":"two.test"}`)

	produced := s.Stats().Checks
	for _, name := range checkNames {
		if _, found := produced[name]; !found {
			t.Errorf("no request in this test produces a %q scan, so its published figures are "+
				"permanently zero", name)
		}
	}
}

// A file written before this field existed still restores correctly.
//
// The TLS figures were at the top and nowhere else, so that is where they are
// read from. Getting this wrong loses every scan ever counted, once, quietly,
// on the first restart after a deploy.
func TestAFileWithoutCheckBlocksRestoresIntoTheTLSBlock(t *testing.T) {
	today := time.Now().UTC().Format(time.DateOnly)
	old := Snapshot{
		Total: 5, Strong: 1, Insecure: 4,
		Today: 1, TodayDate: today, Since: "2026-08-10",
	}

	s := New(offlineScanner(), Limits{}, nil)
	s.RestoreStats(old)

	got := s.Stats()
	if got.Total != 5 || got.Strong != 1 || got.Insecure != 4 {
		t.Errorf("the figures at the top were lost: %+v", got)
	}
	if tls := got.Checks[checkTLS]; tls.Total != 5 || tls.Strong != 1 || tls.Insecure != 4 || tls.Today != 1 {
		t.Errorf("the tls block did not take the old figures: %+v", tls)
	}
	if got.Since != "2026-08-10" {
		t.Errorf("Since = %q; it is the date counting began, not the date this process started", got.Since)
	}
}

// An older build reading a file this one wrote keeps the right figures.
//
// cmd/porchd reads the file with a plain json.Unmarshal, so a field it
// does not know is ignored rather than refused. That is what makes a rollback
// safe — and it is only safe because the fields at the top still describe one
// check. Had scansTotal been widened to cover both, the older binary would
// have gone on counting somebody else's scans as TLS ones and nothing would
// have looked wrong.
func TestARollbackReadsTheTLSFiguresAndIgnoresTheRest(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	post(t, s, `{"target":"one.test"}`)
	post(t, s, `{"target":"two.test"}`)
	s.counts.record(checkWeb, policy.Strong)
	s.counts.record(checkWeb, policy.Strong)
	s.counts.record(checkWeb, policy.Strong)

	written, err := json.Marshal(s.Stats())
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	// The shape an older build declares: no Checks field at all.
	var old struct {
		Total    uint64 `json:"scansTotal"`
		Strong   uint64 `json:"strong"`
		Weak     uint64 `json:"weak"`
		Insecure uint64 `json:"insecure"`
		Ungraded uint64 `json:"ungraded"`
	}
	if err := json.Unmarshal(written, &old); err != nil {
		t.Fatalf("an older build could not read this file: %v", err)
	}

	if old.Total != 2 {
		t.Errorf("an older build reads scansTotal = %d, want 2: the three web scans must not be "+
			"folded into a figure that older build will report as TLS scans", old.Total)
	}
}

// Snapshot holds two maps now, and the caller that persists these needs to
// know whether anything changed. Getting it wrong means either writing every
// minute for ever or never writing at all.
func TestSnapshotEqualityCoversTheCheckBlocks(t *testing.T) {
	a := Snapshot{Checks: map[string]CheckCounts{checkTLS: {Total: 5}}}
	b := Snapshot{Checks: map[string]CheckCounts{checkTLS: {Total: 5}}}
	if !a.Equal(b) {
		t.Error("two identical snapshots compared unequal")
	}

	b.Checks[checkWeb] = CheckCounts{Total: 1}
	if a.Equal(b) {
		t.Error("a snapshot that gained a check block compared equal, so it would never be written")
	}

	c := Snapshot{Checks: map[string]CheckCounts{checkTLS: {Total: 6}}}
	if a.Equal(c) {
		t.Error("a changed count inside a block compared equal")
	}
}

// Midnight resets every check's daily figure, not only the one at the top.
//
// A restart the morning after a busy night would otherwise report yesterday's
// web scans as today's, which is the one thing a figure named "today" must not
// do.
func TestTheDailyFigureResetsForEveryCheck(t *testing.T) {
	now := time.Date(2026, 9, 10, 23, 59, 0, 0, time.UTC)
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, func() time.Time { return now })

	post(t, s, `{"target":"one.test"}`)
	s.counts.record(checkWeb, policy.Strong)

	if got := s.Stats().Checks[checkWeb].Today; got != 1 {
		t.Fatalf("the web block counted %d scans today, want 1", got)
	}

	now = now.Add(2 * time.Minute) // past midnight UTC

	got := s.Stats()
	if got.Today != 0 {
		t.Errorf("the figure at the top still reports %d scans today", got.Today)
	}
	for name, counts := range got.Checks {
		if counts.Today != 0 {
			t.Errorf("the %q block still reports %d scans today", name, counts.Today)
		}
		if counts.Total == 0 {
			t.Errorf("the %q block lost its total along with its daily figure", name)
		}
	}
}

// A restored file cannot introduce a key this build would never produce.
//
// The same filter the refusal codes have, and it was missing here until a
// sabotage walked through it. The counters are published, the file is on disk
// where an operator can edit it, and a version that counted something this one
// does not would otherwise have its keys carried forward for ever.
func TestRestoreFiltersUnknownChecks(t *testing.T) {
	s := New(offlineScanner(), Limits{}, nil)
	s.RestoreStats(Snapshot{
		Checks: map[string]CheckCounts{
			checkTLS:           {Total: 5, Strong: 5},
			"mail":             {Total: 9},
			"203.0.113.7":      {Total: 9},
			"../../etc/passwd": {Total: 9},
			"denyfirst-tls-v6": {Total: 9},
		},
		TodayDate: time.Now().UTC().Format(time.DateOnly),
	})

	got := s.Stats().Checks
	for name := range got {
		if !slices.Contains(checkNames, name) {
			t.Errorf("restore admitted %q, which is not a check this build runs", name)
		}
	}
	if got[checkTLS].Total != 5 {
		t.Errorf("the tls block was lost while the unknown ones were filtered: %+v", got[checkTLS])
	}
}

// The rule set a block names comes from this build, not from the file.
//
// A restored file was written by some earlier build. A block that carried that
// build's version while this one grades the scans would be a claim with
// nothing behind it — and the version is the whole reason the block names one
// at all (R22).
func TestARestoredBlockDoesNotCarryTheOldRuleSetName(t *testing.T) {
	s := New(offlineScanner(), Limits{}, nil)
	s.RestoreStats(Snapshot{
		Checks:    map[string]CheckCounts{checkTLS: {Total: 5, Policy: "denyfirst-tls-v1"}},
		TodayDate: time.Now().UTC().Format(time.DateOnly),
	})

	if got := s.Stats().Checks[checkTLS].Policy; got != policy.TLSVersion {
		t.Errorf("the restored block names %q, want %q: the version says which rules graded these "+
			"scans, and this build grades by its own", got, policy.TLSVersion)
	}
}

// The per-check figures stand still for a minute, exactly as the ones at the
// top do.
//
// publishInterval exists because a counter anyone can poll is a clock: read
// once a second, "5 scans" becomes "a scan happened at 14:32:08", which is
// material anybody holding the other end of that connection can line up
// against their own records. Freezing the published figures to a whole minute
// widens that window enough to make the comparison useless.
//
// The figures at the top are plain integers and are copied by assignment, so
// they were frozen for free. A map is not: handed out without being cloned it
// stays the live one, and the published block moves the instant the next scan
// is counted while everything beside it stands still. A sabotage that dropped
// the clone passed every test there was, including the one that checks the
// total stands still.
func TestThePublishedCheckFiguresStandStillToo(t *testing.T) {
	now := time.Now()
	c := newCounters(func() time.Time { return now })

	c.record(checkTLS, policy.Strong)
	c.record(checkWeb, policy.Strong)

	published := c.publicSnapshot()
	if got := published.Checks[checkWeb].Total; got != 1 {
		t.Fatalf("the web block published %d scans, want 1", got)
	}

	now = now.Add(20 * time.Second)
	for range 4 {
		c.record(checkWeb, policy.Insecure)
	}

	// The block handed out before those four is still the block it was.
	if got := published.Checks[checkWeb].Total; got != 1 {
		t.Errorf("a snapshot already handed to a caller changed underneath them to %d; "+
			"the map is the live one rather than a copy", got)
	}
	if got := c.publicSnapshot().Checks[checkWeb].Total; got != 1 {
		t.Errorf("the published web figure moved to %d within the minute; polling it would time "+
			"each scan to the second", got)
	}

	// The live figure, which only this process reads, is current.
	if got := c.snapshot().Checks[checkWeb].Total; got != 5 {
		t.Errorf("the live web total is %d, want 5: persistence must not be delayed", got)
	}

	now = now.Add(publishInterval)
	if got := c.publicSnapshot().Checks[checkWeb].Total; got != 5 {
		t.Errorf("the published web figure is %d after the interval, want 5", got)
	}
}
