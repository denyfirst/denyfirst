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
			// Refusing a new client is a worse outcome than serving it, and
			// a better one than running out of memory.
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
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			parts := strings.Split(forwarded, ",")
			// Each proxy appends the address it received the request from, so
			// the entry nearest to us is the last one. Step back one position
			// per additional trusted hop. Taking the leftmost entry — the
			// usual mistake — reads whatever the client chose to send.
			idx := len(parts) - trustedHops
			if idx >= 0 && idx < len(parts) {
				if candidate := strings.TrimSpace(parts[idx]); candidate != "" {
					host = candidate
				}
			}
		}
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Unparseable: key on the raw string so the request is still limited
		// rather than escaping the limiter entirely.
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
