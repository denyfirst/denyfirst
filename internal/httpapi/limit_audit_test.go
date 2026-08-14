package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

// A limiter that refuses every unknown client once its map is full turns a
// defence against one client into a denial of service against all of them:
// fill the map, and nobody the service has not already seen can get in.
//
// The map still has to stay bounded — that was the reason for the cap — so
// this checks both halves: the size holds, and a new client is still served.
func TestFullLimiterStillAdmitsNewClients(t *testing.T) {
	const cap = 50

	clock := time.Now()
	l := newLimiter(5, time.Minute, cap, func() time.Time { return clock })

	// Fill it well past the cap with clients that never return.
	for i := range cap * 4 {
		l.allow(fmt.Sprintf("v4:198.51.100.%d", i%256) + fmt.Sprint(i))
	}

	if size := l.size(); size > cap {
		t.Errorf("the map holds %d entries with a cap of %d", size, cap)
	}

	if !l.allow("v4:203.0.113.7") {
		t.Error("a client the service has not seen before was refused because the map was full")
	}
}

// The sweep runs at most once a minute, so a map that fills between sweeps
// used to refuse newcomers while being mostly stale. Making room has to look
// for expired entries before it evicts a live one.
func TestFullLimiterSweepsBeforeEvicting(t *testing.T) {
	const cap = 20

	clock := time.Now()
	l := newLimiter(1, time.Second, cap, func() time.Time { return clock })

	for i := range cap {
		l.allow(fmt.Sprintf("old:%d", i))
	}
	if l.size() != cap {
		t.Fatalf("setup left %d entries, want %d", l.size(), cap)
	}

	// Past the point where those buckets have refilled and mean nothing.
	clock = clock.Add(l.RetentionPeriod() + time.Second)

	if !l.allow("new:1") {
		t.Fatal("a new client was refused while every existing entry was stale")
	}
	if size := l.size(); size > 2 {
		t.Errorf("%d entries survived a sweep that should have cleared them", size)
	}
}

// X-Forwarded-For is written by the first client in the chain, and a client
// that writes a different piece of nonsense on every request would get a
// different rate limit key each time. Enough of them fill the map.
//
// An entry that is not an address is not an identity, so the connection's own
// address stands.
func TestForgedForwardedForCannotMakeNewKeys(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	keys := map[string]bool{}
	for _, forged := range []string{
		"not-an-address",
		"; drop table",
		"../../etc/passwd",
		"veryLongStringThatIsCertainlyNotAnAddress",
		"",
		"   ",
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/scan", nil)
		r.RemoteAddr = "10.0.0.5:4000"
		r.Header.Set("X-Forwarded-For", forged)

		keys[clientKey(r, trusted, 1)] = true
	}

	if len(keys) != 1 {
		t.Errorf("six forged headers produced %d distinct keys; each one is an entry in a bounded map", len(keys))
	}
	for key := range keys {
		if key != "v4:10.0.0.5" {
			t.Errorf("the key is %q; it should be the address the connection came from", key)
		}
	}
}

// The header is still read when it carries an address, which is the whole
// point of configuring a proxy in the first place.
func TestForwardedForIsUsedWhenItIsAnAddress(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	r := httptest.NewRequest(http.MethodPost, "/api/v1/scan", nil)
	r.RemoteAddr = "10.0.0.5:4000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")

	if got := clientKey(r, trusted, 1); got != "v4:203.0.113.7" {
		t.Errorf("clientKey = %q, want the forwarded address", got)
	}
}

// A mixture is the realistic case: a genuine proxy in front of a client that
// prepends rubbish of its own. The entry at the trusted position is the one
// that decides, and rubbish there falls back rather than becoming a key.
func TestForgedEntryAtTheTrustedPositionFallsBack(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	r := httptest.NewRequest(http.MethodPost, "/api/v1/scan", nil)
	r.RemoteAddr = "10.0.0.5:4000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7, rubbish")

	if got := clientKey(r, trusted, 1); got != "v4:10.0.0.5" {
		t.Errorf("clientKey = %q; a non-address at the trusted position must not become a key", got)
	}
}
