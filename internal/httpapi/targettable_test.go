package httpapi

import (
	"strconv"
	"testing"
	"time"
)

// The table has to regenerate faster than this service can possibly spend it.
//
// This is arithmetic rather than behaviour, and it is a test because the
// arithmetic is the only thing holding the property up. Every bucket empty
// means every user refused, and it is worse than an ordinary flood for being
// quiet: nothing is overloaded, no limit visibly fires, the service simply
// says no to everybody.
//
// Measured on the live service on 2026-08-20, a scan of a name that does not
// resolve took 16 to 19 ms. At twelve bits the table regenerated 137 slots a
// second while this service could spend 470, so roughly sixteen hundred
// addresses could hold the whole table dry using under a third of the
// machine's capacity. At sixteen bits it regenerates faster than the service
// can spend at full tilt, which means the attack now requires saturating the
// service — and a saturated service says too_busy, which somebody can see.
//
// Three numbers decide this and two of them are in other files. Raise
// MaxConcurrent, or make a scan faster, and the line moves. That is why the
// check lives here rather than in a comment.
func TestTargetTableOutrunsTheService(t *testing.T) {
	// Below anything ever observed, so the conclusion holds with room to
	// spare rather than exactly.
	const fastestPlausibleScan = 10 * time.Millisecond
	const margin = 2.0

	regenerates := float64(targetBuckets) / targetRefill.Seconds()
	spends := float64(DefaultMaxConcurrent) / fastestPlausibleScan.Seconds()

	t.Logf("the table regenerates %.0f slots/s; this service can spend at most %.0f/s (%.1fx)",
		regenerates, spends, regenerates/spends)

	if regenerates < spends*margin {
		t.Errorf(`the target table can be held empty by a caller this service will happily serve.

  table regenerates : %.0f slots/s   (targetBuckets %d / targetRefill %s)
  service can spend : %.0f scans/s   (DefaultMaxConcurrent %d / %s per scan)
  required margin   : %.0fx

Every bucket empty means every user refused, quietly. Widen targetKeyBits, or
lower DefaultMaxConcurrent, until the first number is %.0f times the second.`,
			regenerates, targetBuckets, targetRefill,
			spends, DefaultMaxConcurrent, fastestPlausibleScan,
			margin, margin)
	}
}

// What a scanned host actually carries is set by the refill, not by the burst.
//
// This is the whole reason the burst can be made secret without spending
// somebody else's server. In a token bucket the sustained rate is one slot per
// refill interval whatever the bucket holds; the burst only decides how many
// may arrive together after a quiet spell. So widening the burst from a fixed
// two to a secret two, three or four costs a scanned host two extra scans in
// its first minute and nothing per hour after that.
func TestSustainedTargetRateDoesNotDependOnTheBurst(t *testing.T) {
	now := time.Now()
	l := newTargetLimiter(func() time.Time { return now })
	const host = "hammered.test"

	burst := spendTargetBudget(l, host, "443")

	const window = time.Hour
	allowed := 0
	for step := time.Duration(0); step < window; step += targetRefill {
		now = now.Add(targetRefill)
		if l.allow(host, "443") {
			allowed++
		}
		if l.allow(host, "443") {
			t.Fatalf("two scans went through inside one refill interval")
		}
	}

	want := int(window / targetRefill)
	if allowed != want {
		t.Errorf("an hour of unbroken demand let %d scans through, want %d", allowed, want)
	}

	t.Logf("burst %d + %d sustained = %d scans in the first hour; a fixed burst of %d would have allowed %d",
		burst, allowed, burst+allowed, targetBurstMin, targetBurstMin+allowed)
}

// A probe from outside must not read off how many times somebody else scanned
// a host.
//
// With a fixed allowance it did, exactly: refused on the first probe meant two
// prior scans, refused on the second meant one, neither meant none. Three
// answers, three certainties.
//
// With the allowance secret and stable per bucket, a probe measures the
// allowance minus the prior scans and cannot separate the two. This asserts
// that at most one signature still pins the count exactly: across the range
// swept here, only a bucket that drew the minimum and has spent all of it
// refuses three times running.
//
// What this deliberately does not assert is worth stating, because the
// difference is the honesty of the claim rather than a detail of the test.
// Being refused at all is not blurred and cannot be — it means at least
// targetBurstMin scans happened inside the interval, which is the limit doing
// exactly what it exists to do. The secret spread hides how many, not whether.
// That residual is on the privacy page and in Known gaps rather than hidden,
// because removing it would mean raising the minimum allowance, which spends
// the scanned host's peak to buy somebody else's privacy.
func TestSecretBurstBlursAProbeFromOutside(t *testing.T) {
	consistent := map[string]map[int]bool{}

	for trial := range 600 {
		for prior := 0; prior <= targetBurstMin; prior++ {
			l := newTargetLimiter(time.Now)
			host := "victim-" + strconv.Itoa(trial) + ".test"

			for range prior {
				l.allow(host, "443")
			}

			signature := ""
			for range 3 {
				if l.allow(host, "443") {
					signature += "o"
				} else {
					signature += "R"
				}
			}
			if consistent[signature] == nil {
				consistent[signature] = map[int]bool{}
			}
			consistent[signature][prior] = true
		}
	}

	certain := 0
	for signature, priors := range consistent {
		t.Logf("probe result %-4s fits %d different histories", signature, len(priors))
		if len(priors) == 1 {
			certain++
		}
	}

	if certain > 1 {
		t.Errorf("%d of %d probe signatures identify the history exactly; with a fixed allowance "+
			"every one of them does, which is the leak this exists to blur", certain, len(consistent))
	}
}

// The allowance is bounded, so a scanned host can never absorb more than the
// documented peak however the key falls.
func TestBurstStaysWithinItsBounds(t *testing.T) {
	l := newTargetLimiter(nil)
	widest := targetBurstMin + targetBurstSpread - 1

	seen := map[int]int{}
	for key := range targetBuckets {
		got := int(l.burstFor(uint16(key)))
		if got < targetBurstMin || got > widest {
			t.Fatalf("bucket %d has an allowance of %d, outside [%d, %d]", key, got, targetBurstMin, widest)
		}
		seen[got]++
	}

	if len(seen) != targetBurstSpread {
		t.Errorf("%d distinct allowances exist, want %d", len(seen), targetBurstSpread)
	}
	for allowance, count := range seen {
		t.Logf("allowance %d: %d buckets (%.1f%%)", allowance, count, 100*float64(count)/float64(targetBuckets))
	}
}

// Stable for the life of the process, so a caller sees consistent behaviour;
// different between processes, so it cannot be worked out once and reused.
func TestBurstIsStablePerBucketAndSecretPerProcess(t *testing.T) {
	l := newTargetLimiter(nil)
	for key := range 200 {
		if l.burstFor(uint16(key)) != l.burstFor(uint16(key)) {
			t.Fatalf("bucket %d changed its allowance between two calls", key)
		}
	}

	other := newTargetLimiter(nil)
	differed := 0
	for key := range 600 {
		if l.burstFor(uint16(key)) != other.burstFor(uint16(key)) {
			differed++
		}
	}

	// Two independent keys should disagree about two times in three.
	if differed < 300 {
		t.Errorf("two processes agreed on %d of 600 allowances; the allowance does not look keyed", 600-differed)
	}
}
