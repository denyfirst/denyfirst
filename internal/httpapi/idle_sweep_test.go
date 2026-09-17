package httpapi

import (
	"testing"
	"time"
)

// firedBy replaces a limiter's timer with one the test fires by hand, and
// counts how often it was armed.
type firedBy struct {
	pending []func()
	armed   int
}

func (f *firedBy) after(_ time.Duration, run func()) *time.Timer {
	f.armed++
	f.pending = append(f.pending, run)
	return nil
}

func (f *firedBy) fire() {
	runs := f.pending
	f.pending = nil
	for _, run := range runs {
		run()
	}
}

// An address is forgotten on time with nobody else arriving.
//
// The privacy page says an address is dropped about three minutes after the
// last request. Until the 2026-09-16 audit (A22) that held only on a service
// somebody else was using: the sweep ran on the next request, so the last
// client of a quiet day was held until the next day.
func TestAnIdleClientIsForgottenWithoutAnotherRequest(t *testing.T) {
	clock := time.Now()
	timer := &firedBy{}
	l := newLimiter(DefaultBurst, DefaultRefill, DefaultMaxTrackedIPs, func() time.Time { return clock })
	l.idle.after = timer.after

	l.allow("v4:203.0.113.7")
	l.allow("v4:203.0.113.7")
	l.allow("v4:203.0.113.9")
	l.idle.after = timer.after
	if timer.armed != 1 {
		t.Fatalf("the timer was armed %d times while running, want once", timer.armed)
	}

	// Still within the window: kept, and the timer runs again.
	clock = clock.Add(time.Minute)
	timer.fire()
	if l.size() != 2 {
		t.Fatalf("a client inside the window was dropped")
	}
	if len(timer.pending) != 1 {
		t.Fatal("the timer stopped while a client was still held")
	}

	// Past the retention period, with no request since: gone, and nothing
	// left running.
	clock = clock.Add(l.RetentionPeriod())
	timer.fire()
	if l.size() != 0 {
		t.Errorf("a client idle past %v is still held with no other request", l.RetentionPeriod())
	}
	if len(timer.pending) != 0 {
		t.Error("the timer is still armed over an empty limiter")
	}

	// And a later client arms it again.
	l.allow("v4:198.51.100.1")
	if len(timer.pending) != 1 {
		t.Error("a new client after the limiter emptied did not arm the timer")
	}
}

// The same for the table of scanned hosts.
func TestAnIdleTargetIsForgottenWithoutAnotherScan(t *testing.T) {
	clock := time.Now()
	timer := &firedBy{}
	l := newTargetLimiter(func() time.Time { return clock })
	l.idle.after = timer.after

	l.allow("example.test", "443")
	l.allow("example.test", "443")
	l.allow("other.example.test", "443")
	if timer.armed != 1 {
		t.Fatalf("the timer was armed %d times while running, want once", timer.armed)
	}

	clock = clock.Add(targetSweepEvery)
	timer.fire()
	if l.size() != 1 {
		t.Fatal("a host scanned twice in a row was dropped before it refilled")
	}

	clock = clock.Add(time.Duration(targetBurstMin+targetBurstSpread) * targetRefill)
	timer.fire()
	if l.size() != 0 {
		t.Error("a refilled host is still held with no other scan")
	}
	if len(timer.pending) != 0 {
		t.Error("the timer is still armed over an empty table")
	}
}

// A sweep a request ran just before the timer fired does not push the timer's
// own sweep a whole interval later.
func TestTheTimerSweepsEvenJustAfterARequestDid(t *testing.T) {
	clock := time.Now()
	timer := &firedBy{}
	l := newLimiter(1, time.Second, 100, func() time.Time { return clock })
	l.idle.after = timer.after

	l.allow("v4:203.0.113.7")

	// Another client arrives when a routine sweep is due, and is new to it.
	clock = clock.Add(l.sweepEvery)
	l.allow("v4:203.0.113.8")

	// Both idle now; the timer fires moments later.
	clock = clock.Add(l.idlePeriod() + time.Second)
	timer.fire()
	if l.size() != 0 {
		t.Errorf("%d clients idle past the period survived the timer's sweep", l.size())
	}
}

// The same, for the table of scanned hosts.
func TestTheTargetTimerSweepsEvenJustAfterAScanDid(t *testing.T) {
	clock := time.Now()
	timer := &firedBy{}
	l := newTargetLimiter(func() time.Time { return clock })
	l.idle.after = timer.after

	clock = clock.Add(time.Second)
	l.allow("example.test", "443")

	// Another scan arrives when a routine sweep is due, and that sweep finds
	// the first host a second short of refilled.
	clock = clock.Add(targetSweepEvery - time.Second)
	l.allow("other.example.test", "443")

	// Half an interval later the first has refilled and the second has not,
	// and the timer fires.
	clock = clock.Add(targetSweepEvery / 2)
	timer.fire()
	if l.size() != 1 {
		t.Errorf("%d hosts held; the refilled one survived the timer's sweep", l.size())
	}
}
