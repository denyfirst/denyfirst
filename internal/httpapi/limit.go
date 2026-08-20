package httpapi

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// ipv6PrefixBits is the width of the block a rate limit key covers for IPv6.
//
// A single subscriber is normally delegated a /64 and can move freely among
// the addresses inside it. Keying the limiter on a full IPv6 address would
// let one client present a new identity for every request, which is not an
// attack so much as the default behaviour of privacy extensions.
const ipv6PrefixBits = 64

// limiter is a token bucket per client, with a bounded map.
//
// The map is itself an attack surface: an unbounded one turns a rate limiter
// into a memory exhaustion primitive, since an attacker rotating source
// addresses adds an entry per request. Two defences apply. Idle entries are
// swept, and once the map reaches maxKeys new clients are refused rather than
// admitted, so the failure is a rejected request instead of a dead process.
type limiter struct {
	burst  float64
	refill time.Duration

	// maxKeys caps how many clients are tracked at once.
	maxKeys int

	// sweepEvery bounds how often the map is walked, so a burst of traffic
	// does not turn into a burst of sweeps.
	sweepEvery time.Duration

	now func() time.Time

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
	// lastForced is separate from lastSweep because the two are rate limited
	// for different reasons: one bounds routine housekeeping, the other
	// bounds work an attacker can ask for.
	lastForced time.Time
}

type bucket struct {
	tokens float64
	seen   time.Time
}

func newLimiter(burst int, refill time.Duration, maxKeys int, now func() time.Time) *limiter {
	if now == nil {
		now = time.Now
	}
	return &limiter{
		burst:      float64(burst),
		refill:     refill,
		maxKeys:    maxKeys,
		sweepEvery: time.Minute,
		now:        now,
		buckets:    make(map[string]*bucket),
		lastSweep:  now(),
	}
}

// allow reports whether the client may proceed and spends a token if so.
func (l *limiter) allow(key string) bool {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepLocked(now)

	b, found := l.buckets[key]
	if !found {
		if len(l.buckets) >= l.maxKeys {
			l.makeRoomLocked(now)
		}
		if len(l.buckets) >= l.maxKeys {
			// Nothing could be freed, which means the map is genuinely full
			// of active clients. Refusing is the last resort.
			return false
		}
		l.buckets[key] = &bucket{tokens: l.burst - 1, seen: now}
		return true
	}

	// Refill in proportion to the time since the bucket was last touched.
	if elapsed := now.Sub(b.seen); elapsed > 0 {
		b.tokens += float64(elapsed) / float64(l.refill)
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
	}
	b.seen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweepLocked drops buckets that have been full and idle long enough that
// forgetting them changes nothing.
//
// This is also how long an address is held. A bucket refills completely in
// burst × refill; twice that is the point past which its state is
// indistinguishable from a fresh one, and keeping it serves nothing.
func (l *limiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < l.sweepEvery {
		return
	}
	l.lastSweep = now

	idle := l.idlePeriod()

	for key, b := range l.buckets {
		if now.Sub(b.seen) > idle {
			delete(l.buckets, key)
		}
	}
}

// makeRoomLocked frees a slot when the map has reached its cap.
//
// Refusing outright was the original behaviour and it had a failure mode
// worth naming: one client able to produce many distinct keys fills the map,
// and from then on every client the service has not seen before is turned
// away. The limiter stops limiting anybody and starts excluding everybody,
// which is a denial of service built out of a defence against one.
//
// So: sweep first, since a full map is usually a stale one and the periodic
// sweep may not be due for another minute. If that frees nothing, drop a
// single entry. Which entry hardly matters — Go randomises map iteration, so
// this takes an arbitrary one, and losing a bucket costs its owner nothing
// worse than a fresh allowance. Finding the oldest instead would walk twenty
// thousand entries on every request during exactly the flood this exists to
// survive.
func (l *limiter) makeRoomLocked(now time.Time) {
	// A forced sweep, but not on every call.
	//
	// Walking the map is the expensive thing here and it happens under the
	// lock. During a flood the map is full continuously, so forcing a sweep
	// each time an entry is wanted would mean twenty thousand iterations per
	// request — a cheaper attack than the one this function was added to
	// prevent.
	//
	// Once a second is often enough to reclaim entries as they expire, and
	// rare enough that the flood pays for eviction alone, which is constant
	// time.
	const forcedSweepEvery = time.Second

	if now.Sub(l.lastForced) >= forcedSweepEvery {
		l.lastForced = now
		l.lastSweep = time.Time{}
		l.sweepLocked(now)
	}

	if len(l.buckets) < l.maxKeys {
		return
	}
	for key := range l.buckets {
		delete(l.buckets, key)
		return
	}
}

func (l *limiter) idlePeriod() time.Duration {
	return time.Duration(l.burst) * l.refill * 2
}

// RetentionPeriod is the longest an address can be held, so that the privacy
// page can state a number rather than a feeling.
//
// A bucket is dropped once it has been idle for burst × refill × 2, and the
// sweep runs at most once a minute, so the worst case is that plus one sweep
// interval.
func (l *limiter) RetentionPeriod() time.Duration {
	return l.idlePeriod() + l.sweepEvery
}

// DefaultRetentionPeriod is that figure for the settings this service ships
// with, exported so the privacy page can be checked against the code instead
// of against somebody's memory of it.
//
// The page states a number in words. Two sources that agree only because
// nobody compares them are one source written twice, which is the argument
// this project already makes about the PGP fingerprint, and the flags that
// change this number are on the same command line as everything else.
func DefaultRetentionPeriod() time.Duration {
	return newLimiter(DefaultBurst, DefaultRefill, DefaultMaxTrackedIPs, nil).RetentionPeriod()
}

func (l *limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// clientKey identifies the party a rate limit applies to.
//
// X-Forwarded-For is read only when the request arrived from a network named
// in trustedProxies, and then only as far back as trustedHops.
//
// Checking where the connection came from is the part that is easy to leave
// out, and leaving it out is worse than not reading the header at all. A
// reverse proxy hides the origin server but rarely removes it: an address
// found in certificate transparency logs, in old DNS records, or from a
// scanning service reaches it directly. A client connecting that way sets
// X-Forwarded-For to whatever it likes, and a service that trusts the header
// on the strength of a configuration flag alone hands every such client a
// fresh rate limit key per request.
//
// So the flag says a proxy exists; this says the request actually came
// through it.
func clientKey(r *http.Request, trustedProxies []netip.Prefix, trustedHops int) string {
	host := remoteHost(r.RemoteAddr)

	if trustedHops > 0 && len(trustedProxies) > 0 && fromTrustedProxy(host, trustedProxies) {
		// Values rather than Get, and the difference is a bypass rather than a
		// tidiness point. A proxy may extend the header the client sent or add
		// a line of its own; both are conforming, and the second is what
		// several load balancers do. Get returns the first line only, so
		// against such a proxy it returns whatever the client wrote — a fresh
		// key of the client's choosing on every request, which is the same as
		// having no limiter. Joining every line puts the proxy's entry back at
		// the end where the hop count expects it.
		if forwarded := strings.Join(r.Header.Values("X-Forwarded-For"), ","); forwarded != "" {
			parts := strings.Split(forwarded, ",")
			// Each proxy appends the address it received the request from, so
			// the entry nearest to us is the last one. Step back one position
			// per additional trusted hop. Taking the leftmost entry — the
			// usual mistake — reads whatever the client chose to send.
			idx := len(parts) - trustedHops
			if idx >= 0 && idx < len(parts) {
				candidate := strings.TrimSpace(parts[idx])
				// Only if it is an address. A proxy passes on what the
				// previous hop sent, and the first hop is a client that
				// writes whatever it likes — including a different piece of
				// nonsense on every request. Each one would become a key of
				// its own, and enough of them fill the map.
				//
				// Falling back to the connection's address keeps such a
				// client limited as the single client it is.
				if _, err := netip.ParseAddr(candidate); err == nil {
					host = candidate
				}
			}
		}
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Reached only when the connection's own address is unparseable,
		// which a working server does not produce. Keyed on the literal
		// string so the request is still limited rather than escaping
		// entirely, and constant so it cannot be used to make new keys.
		return "raw:" + host
	}

	if addr.Is4() || addr.Is4In6() {
		return "v4:" + addr.Unmap().String()
	}

	prefix, err := addr.Prefix(ipv6PrefixBits)
	if err != nil {
		return "v6:" + addr.String()
	}
	return "v6:" + prefix.String()
}

func fromTrustedProxy(host string, trusted []netip.Prefix) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()

	for _, prefix := range trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func remoteHost(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// semaphore bounds how many scans run at once.
//
// A scan holds a socket for up to the request timeout, and a slow target
// holds it for the whole of that. Without a cap, a handful of clients aimed
// at unresponsive hosts occupy every goroutine the process will ever have.
type semaphore chan struct{}

func newSemaphore(n int) semaphore {
	return make(semaphore, n)
}

// acquire waits for a slot or for the context to end, whichever comes first.
// A caller whose deadline expires while queued is released rather than run,
// because the answer would arrive after anyone stopped waiting for it.
func (s semaphore) acquire(ctx context.Context) error {
	select {
	case s <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s semaphore) release() {
	<-s
}
