package httpapi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"sync"
	"time"
)

// One scan opens up to fifty handshakes: four protocol versions in parallel,
// one round of cipher enumeration per suite the server turns out to accept —
// eleven at TLS 1.0 and 1.1, twenty-two at TLS 1.2, which is every suite Go
// can be told to offer — and two more to settle the question of preference. A
// modern server ends the enumeration early and costs under twenty; one that
// still accepts everything costs the lot. That is the price of measuring what
// a server will actually negotiate rather than what it advertises, and it is
// paid by the server being measured.
//
// A single request of a couple of hundred bytes therefore turns into a couple
// of hundred times as much work at the other end. Every other limit in this
// package protects this service. This one protects the server on the other
// side, which is the party with no say in whether it is scanned.
//
// Without it nothing bounds convergence: any number of callers aiming at one
// host produce as many scans as they care to ask for, and nothing stops that
// being deliberate. With it, that host sees one scan per refill interval for
// as long as the demand lasts, however many people are asking and however long
// they keep asking.
//
// The eight to ten it may absorb back to back is the peak, not the rate, and
// it sits deliberately above what ordinary use produces — for a reason that is
// about somebody else's privacy rather than about load. See targetBurstMin.
const (
	// targetBurstMin is the smallest allowance any host has, and eight rather
	// than two is the change that closes a leak rather than blurring it.
	//
	// A shared limit answers a question anybody outside can ask: scan a host,
	// be refused, and you have learnt that somebody else scanned it. At two
	// the threshold sat inside ordinary use — one person retrying after a typo
	// reached it — so the answer carried real information about a real user.
	// At eight it sits outside: this service has served single figures of
	// scans a day since it opened, so a probe is answered "yes, go ahead" and
	// tells the prober nothing. To make the limit speak, they have to push it
	// there themselves, which means eight scans of the victim from several
	// addresses, which is the thing they were trying to detect. The
	// measurement destroys what it measures.
	//
	// Raising it does not loosen what a scanned host carries, and that is the
	// part worth being precise about:
	//
	//   - Sustained load is set by targetRefill, not by the burst. A token
	//     bucket lets through one scan per refill interval for ever, whatever
	//     the bucket holds. That figure has not moved.
	//
	//   - One caller was never held by this limit anyway. The per-client
	//     limiter allows five scans a minute, so a single address could never
	//     do more than that to one host. This limit exists for the other
	//     case — many addresses converging on one host — and that case is
	//     still bounded by the same sustained rate.
	//
	// What does move is the peak: a host can now absorb eight to ten scans
	// back to back rather than two, which is a few hundred handshakes over a
	// few seconds instead of a hundred. It takes eight separate callers within
	// one window to produce, so it is either an incident somebody is looking
	// into or an attacker who owns eight addresses and could have opened those
	// connections directly. It also means eight people checking the same host
	// after an outage are no longer refused, which was a false refusal the old
	// figure produced regularly.
	targetBurstMin = 8

	// targetBurstSpread is how many distinct allowances exist: 8, 9 or 10.
	//
	// Insurance rather than the main defence. The paragraph above closes the
	// leak by putting the threshold beyond ordinary traffic; if this service
	// ever became busy enough that one host really did see eight scans in a
	// window, a fixed threshold would start answering again. A secret one does
	// not: a probe measures the allowance minus the prior scans and cannot
	// separate the two terms.
	//
	// What it buys is precise, and claiming more for it would be the kind of
	// security claim this project exists to argue against. It hides the count.
	// It does not hide the refusal: anybody who is refused knows that host has
	// had at least targetBurstMin scans inside one interval, and no arrangement
	// of secret thresholds takes that away, because the refusal is the limit
	// working. Removing that last fact means raising the minimum, and every
	// point of the minimum is peak load the scanned server absorbs — so it is
	// stated on the privacy page instead of being bought with somebody else's
	// bandwidth.
	targetBurstSpread = 3

	// targetRefill is how long one slot takes to return. This, not the burst,
	// is what bounds the load a scanned host carries: one scan per interval,
	// for ever. Unchanged, so that bound is unchanged.
	targetRefill = 30 * time.Second

	// targetKeyBits is the width of the bucket identifier.
	//
	// Two forces pull on this number in opposite directions, and the balance
	// moved once it was measured rather than guessed.
	//
	// Narrow protects a hostname. A bucket identifier has to be something no
	// name can be recovered from, so the HMAC is truncated and the key is
	// generated per process and never written down. At sixteen bits a bucket
	// fits roughly fifteen thousand of the names anybody would think to try.
	// (The earlier comment here said billions. Against a candidate list of a
	// billion names twelve bits gave two hundred thousand, not billions; the
	// claim was generous and is corrected rather than repeated. What the
	// truncation defends is enumeration — going from a number to a name. It
	// was never a defence against somebody testing one name they already
	// suspect, and saying so is cheaper than implying otherwise.)
	// Sixty-four bits would fit about one name and would turn this table into
	// the record the rest of the project exists to avoid keeping. That part
	// has not changed.
	//
	// Wide keeps the table out of reach. The whole table regenerates at
	// targetBuckets/targetRefill slots a second. If a caller can spend faster
	// than that, every bucket stays empty and every user is refused — and it
	// is worse for being quiet, because nothing looks overloaded. Measured on
	// the live service on 2026-08-20, a scan of a name that does not resolve
	// takes 16 to 19 ms, so eight concurrent scans is about 470 a second. At
	// twelve bits the table regenerated at 137 a second: about 1600 addresses
	// could hold the whole thing dry using under a third of this machine's
	// capacity. At sixteen it regenerates at 2185, which is more than this
	// service can spend at full tilt — so the attack now requires saturating
	// the service, and a saturated service says too_busy, which is visible.
	//
	// TestTargetTableOutrunsTheService keeps that arithmetic true. Raising
	// MaxConcurrent, or making a scan faster, moves the same line.
	targetKeyBits = 16
	targetBuckets = 1 << targetKeyBits

	// targetMaxTracked caps the map. Equal to the number of buckets that can
	// exist, so this only ever guards against a bug. The map holds what
	// traffic has touched, not one entry per bucket.
	targetMaxTracked = targetBuckets
)

// TargetThreshold is the smallest number of scans of one host, inside one
// refill interval, that can produce a refusal.
//
// Exported for one reason: the privacy page states this figure in words, and
// it is the only number on that page from which a reader could work out
// anything about what somebody else has been doing. It moved from two to eight
// in a single change, and the page it is written on had no way of noticing.
//
// Same argument as DefaultRetentionPeriod, and the same test shape. Two
// sources that agree only because nobody compares them are one source written
// twice.
func TargetThreshold() int { return targetBurstMin }

// foldHost reduces the spellings of one name to one string.
//
// Deliberately not a general canonicaliser: it does what DNS itself does when
// it compares names, and nothing more. Anything cleverer here would be a
// second opinion about what a hostname is, and two opinions in two packages
// is the parser mismatch this project spends its effort avoiding.
func foldHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// burstFor is the allowance for one bucket: targetBurstMin plus an amount
// derived from the same per-process key.
//
// Stable for the life of the process, so a legitimate caller sees consistent
// behaviour, and unguessable from outside, because it comes from a key that is
// never written down. Keyed on the bucket rather than the hostname, so it
// needs nothing the limiter does not already hold.
func (l *targetLimiter) burstFor(key uint16) float64 {
	// Written through encoding/binary rather than by shifting bytes out of the
	// identifier. The two are the same bytes; the difference is that a
	// narrowing conversion is something a reader — and a linter — has to
	// convince themselves cannot lose anything, and there is no reason to ask
	// that of either when the standard library will do it.
	var id [2]byte
	binary.BigEndian.PutUint16(id[:], key)

	mac := hmac.New(sha256.New, l.key)
	mac.Write(id[:])
	mac.Write([]byte{'b'})

	return float64(targetBurstMin + int(mac.Sum(nil)[0])%targetBurstSpread)
}

// targetLimiter bounds how often any one host is scanned, whoever asks.
type targetLimiter struct {
	// key is generated per process and never written down. It stops a bucket
	// identifier from being matched against a precomputed table of hostnames.
	// The truncation above is what protects against someone who has the key
	// as well.
	key []byte

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
//
// The host is folded first, and that line is the whole limiter. A hash is
// exact where DNS is not: EXAMPLE.COM, example.com and example.com. reach one
// server and would otherwise reach three buckets, so a caller could spell
// their way past the only budget here that belongs to somebody else.
// scan.SplitTarget already folds it, and this repeats the work on purpose —
// a guard at the entry point protects that entry point, and a guard where the
// decision is made protects every caller, including the ones not written yet.
func (l *targetLimiter) bucketFor(host, port string) uint16 {
	mac := hmac.New(sha256.New, l.key)
	mac.Write([]byte(foldHost(host)))
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
		l.buckets[key] = &bucket{tokens: l.burstFor(key) - 1, seen: now}
		return true
	}

	if elapsed := now.Sub(b.seen); elapsed > 0 {
		b.tokens += float64(elapsed) / float64(l.refill)
		if full := l.burstFor(key); b.tokens > full {
			b.tokens = full
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
//
// Each bucket is measured rather than the whole map being aged by the widest
// allowance it could hold. That distinction arrived with the wider burst: a
// host scanned once refills in one interval, and dropping it then keeps what
// this process knows to about half a minute. Ageing everything by ten
// intervals instead would have held a scanned host's bucket for five minutes
// to no purpose, which is four and a half minutes of state nobody needs.
func (l *targetLimiter) sweepLocked(now time.Time) {
	const sweepEvery = 30 * time.Second

	if now.Sub(l.lastSweep) < sweepEvery {
		return
	}
	l.lastSweep = now

	for key, b := range l.buckets {
		refilled := b.tokens + float64(now.Sub(b.seen))/float64(l.refill)
		if refilled >= l.burstFor(key) {
			delete(l.buckets, key)
		}
	}
}

func (l *targetLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
