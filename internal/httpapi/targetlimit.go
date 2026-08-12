package httpapi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

// One scan opens roughly thirty handshakes: four protocol versions in
// parallel, several rounds of cipher enumeration within each, and two more to
// settle the question of preference. That is the cost of measuring what a
// server will actually negotiate rather than what it advertises, and it is
// paid by the server being measured.
//
// A single request of a couple of hundred bytes therefore turns into a
// hundred and fifty times as much work at the other end. Every other limit in
// this package protects this service. This one protects the server on the
// other side, which is the party with no say in whether it is scanned.
//
// Without it, eight users aiming at one host produce a burst that a small
// server feels, and nothing stops that being deliberate.
const (
	// targetBurst is how many scans one host absorbs back to back, across all
	// clients. Two allows a person to retry once after a mistake.
	targetBurst = 2

	// targetRefill is how long one of those slots takes to return.
	targetRefill = 30 * time.Second

	// targetKeyBits is the width of the bucket identifier.
	//
	// The narrowness is the mechanism, not a shortcut. Two reviewers have now
	// read it as a defect and suggested widening it to sixty-four bits, so
	// the reasoning is set out here at length: widening it would destroy the
	// property this limiter exists to have.
	//
	// A rate limiter has to recognise a repeated target, which normally means
	// keeping the target. Keeping hostnames would break the one promise this
	// project is built on, so the key is an HMAC truncated to twelve bits:
	// 4096 buckets for every hostname that exists.
	//
	// Collisions are what protects the hostname. At twelve bits, a bucket
	// identifier is consistent with billions of names, so a memory dump
	// yields a number and nothing else. At sixty-four bits it is consistent
	// with roughly one, and since the key is in the same memory as the
	// buckets, whoever has both can hash a list of a million domains and read
	// off exactly what was scanned. The wider hash does not improve the
	// limiter; it undoes it.
	//
	// The cost is a false refusal when two unrelated hosts share a bucket,
	// and it is small: the chance is the number of hosts whose budget is
	// currently spent divided by 4096, so about half a percent with twenty in
	// flight. A person waits thirty seconds and tries again.
	//
	// If that ever becomes a real nuisance, the answer is fourteen bits —
	// 16384 buckets, a quarter of the collisions, and still billions of names
	// per bucket. Never sixty-four.
	targetKeyBits = 12
	targetBuckets = 1 << targetKeyBits

	// targetMaxTracked caps the map. Far above the number of buckets that can
	// exist, so this only ever guards against a bug.
	targetMaxTracked = targetBuckets
)

// targetLimiter bounds how often any one host is scanned, whoever asks.
type targetLimiter struct {
	// key is generated per process and never written down. It stops a bucket
	// identifier from being matched against a precomputed table of hostnames.
	// The truncation above is what protects against someone who has the key
	// as well.
	key []byte

	burst  float64
	refill time.Duration
	now    func() time.Time

	mu        sync.Mutex
	buckets   map[uint16]*bucket
	lastSweep time.Time
}

func newTargetLimiter(now func() time.Time) *targetLimiter {
	if now == nil {
		now = time.Now
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// crypto/rand failing means the system has no entropy, which is not a
		// state to carry on in. Every other guard in this package would be
		// making decisions on the same broken source.
		panic("httpapi: no entropy available for the target limiter key: " + err.Error())
	}

	return &targetLimiter{
		key:       key,
		burst:     targetBurst,
		refill:    targetRefill,
		now:       now,
		buckets:   make(map[uint16]*bucket),
		lastSweep: now(),
	}
}

// bucketFor maps a target to one of the buckets.
//
// The port is included so that scanning one host on two ports is two
// budgets, which is what a server experiences.
func (l *targetLimiter) bucketFor(host, port string) uint16 {
	mac := hmac.New(sha256.New, l.key)
	mac.Write([]byte(host))
	mac.Write([]byte{0})
	mac.Write([]byte(port))

	sum := mac.Sum(nil)
	return uint16(binary.BigEndian.Uint16(sum[:2]) & (targetBuckets - 1))
}

// allow reports whether this target may be scanned now, and spends a slot if
// so.
func (l *targetLimiter) allow(host, port string) bool {
	key := l.bucketFor(host, port)
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepLocked(now)

	b, found := l.buckets[key]
	if !found {
		if len(l.buckets) >= targetMaxTracked {
			return false
		}
		l.buckets[key] = &bucket{tokens: l.burst - 1, seen: now}
		return true
	}

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

// sweepLocked drops buckets that have refilled, so nothing lingers.
//
// The interval matters here beyond memory. A bucket that has refilled tells
// nobody anything, and an empty map is the state this service spends most of
// its time in.
func (l *targetLimiter) sweepLocked(now time.Time) {
	const sweepEvery = 30 * time.Second

	if now.Sub(l.lastSweep) < sweepEvery {
		return
	}
	l.lastSweep = now

	idle := time.Duration(l.burst) * l.refill

	for key, b := range l.buckets {
		if now.Sub(b.seen) > idle {
			delete(l.buckets, key)
		}
	}
}

func (l *targetLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
