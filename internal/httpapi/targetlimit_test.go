package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// One host absorbs a small burst and then has to wait, whoever is asking.
// Every other limit in this package protects this service; this one protects
// the server being measured, which had no say in the matter.
func TestOneTargetIsLimitedAcrossClients(t *testing.T) {
	now := time.Now()
	l := newTargetLimiter(func() time.Time { return now })

	for i := range targetBurst {
		if !l.allow("example.test", "443") {
			t.Fatalf("scan %d was refused while the target still had slots", i+1)
		}
	}

	if l.allow("example.test", "443") {
		t.Error("the target accepted a scan beyond its burst")
	}

	// A different client asking for the same host is the case this exists
	// for: the budget belongs to the target, not to whoever asks.
	if l.allow("example.test", "443") {
		t.Error("a second client got a fresh budget for the same target")
	}
}

func TestSlotsReturnOverTime(t *testing.T) {
	now := time.Now()
	l := newTargetLimiter(func() time.Time { return now })

	for range targetBurst {
		l.allow("example.test", "443")
	}
	if l.allow("example.test", "443") {
		t.Fatal("the burst was not spent")
	}

	now = now.Add(targetRefill + time.Second)

	if !l.allow("example.test", "443") {
		t.Error("a slot did not return after the refill interval")
	}
}

// Two ports on one host are two budgets, because that is what the server
// experiences: separate listeners doing separate work.
func TestPortsAreCountedSeparately(t *testing.T) {
	now := time.Now()
	l := newTargetLimiter(func() time.Time { return now })

	for range targetBurst {
		l.allow("example.test", "443")
	}
	if l.allow("example.test", "443") {
		t.Fatal("the budget for port 443 was not spent")
	}

	if !l.allow("example.test", "8443") {
		t.Error("port 8443 was refused because port 443 had been scanned")
	}
}

// The key is the whole privacy argument. A bucket identifier must not be
// something a hostname can be recovered from, and the defence is that
// billions of hostnames share every bucket.
func TestBucketsCollideHeavily(t *testing.T) {
	l := newTargetLimiter(nil)

	// Far more distinct hosts than there are buckets, so collisions are
	// certain. If the identifier were wide enough to be reversible, this
	// would produce something close to one bucket per host.
	const hosts = targetBuckets * 4

	seen := map[uint16]int{}
	for i := range hosts {
		key := l.bucketFor("host-"+strconv.Itoa(i)+".test", "443")
		seen[key]++
	}

	if len(seen) > targetBuckets {
		t.Fatalf("the limiter produced %d distinct buckets, above the %d it should have", len(seen), targetBuckets)
	}

	// With four times as many hosts as buckets, essentially every bucket
	// should hold several. A near-injective mapping would mean the truncation
	// is not doing its job.
	shared := 0
	for _, count := range seen {
		if count > 1 {
			shared++
		}
	}
	if shared < len(seen)/2 {
		t.Errorf("only %d of %d buckets hold more than one host; the identifier is too precise to protect a hostname", shared, len(seen))
	}
}

// The key is generated per process, so the same hostname maps to different
// buckets in different runs. Without it, a bucket identifier could be matched
// against a table computed once for every hostname worth checking.
func TestKeyDiffersBetweenProcesses(t *testing.T) {
	first := newTargetLimiter(nil)
	second := newTargetLimiter(nil)

	differences := 0
	for i := range 200 {
		host := "host-" + strconv.Itoa(i) + ".test"
		if first.bucketFor(host, "443") != second.bucketFor(host, "443") {
			differences++
		}
	}

	// With 4096 buckets, two independent keys agree about one time in four
	// thousand, so almost every host should land somewhere else.
	if differences < 150 {
		t.Errorf("only %d of 200 hosts mapped differently between two limiters; the key does not appear to be per process", differences)
	}
}

func TestTargetLimiterMemoryIsBounded(t *testing.T) {
	l := newTargetLimiter(nil)

	for i := range targetBuckets * 10 {
		l.allow("host-"+strconv.Itoa(i)+".test", "443")
	}

	if got := l.size(); got > targetBuckets {
		t.Errorf("the limiter holds %d buckets, above the %d that can exist", got, targetBuckets)
	}
}

func TestTargetLimiterSweepsRefilledBuckets(t *testing.T) {
	now := time.Now()
	l := newTargetLimiter(func() time.Time { return now })

	for i := range 50 {
		l.allow("host-"+strconv.Itoa(i)+".test", "443")
	}
	if l.size() == 0 {
		t.Fatal("nothing was recorded")
	}

	// Past the point where every bucket has refilled, keeping them tells
	// nobody anything.
	now = now.Add(time.Hour)
	l.allow("something-new.test", "443")

	if got := l.size(); got > 2 {
		t.Errorf("%d buckets remain an hour later; a refilled bucket carries no information and should not be kept", got)
	}
}

// End to end: the limit has to be reachable through the handler, or it
// protects nothing.
func TestHandlerRefusesAnOverscannedTarget(t *testing.T) {
	s := New(offlineScanner(), Limits{
		Burst:          1000, // the per-client limit must not be what fires
		Refill:         time.Nanosecond,
		RequestTimeout: 2 * time.Second,
	}, nil)

	body := `{"target":"crowded.test"}`

	for i := range targetBurst {
		w := postFrom(t, s, body, "198.51.100."+strconv.Itoa(i+1)+":5000")
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("scan %d was refused while the target still had slots", i+1)
		}
	}

	// A different client again, so only the target budget can refuse this.
	w := postFrom(t, s, body, "198.51.100.200:5000")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d once the target's budget was spent", w.Code, http.StatusTooManyRequests)
	}

	var resp errorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if resp.Error.Code != "target_busy" {
		t.Errorf("code = %q, want target_busy: the client is not at fault and the message should say so", resp.Error.Code)
	}

	// The refusal must not name the target back to the caller.
	if strings.Contains(w.Body.String(), "crowded.test") {
		t.Errorf("the refusal repeated the target: %s", w.Body.String())
	}
}

// A different host must be unaffected, or the limiter is a denial of service
// against ordinary use.
func TestOtherTargetsAreUnaffected(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	for range targetBurst {
		postFrom(t, s, `{"target":"busy.test"}`, "198.51.100.1:5000")
	}
	if w := postFrom(t, s, `{"target":"busy.test"}`, "198.51.100.2:5000"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("the busy target was not limited, so this test proves nothing")
	}

	if w := postFrom(t, s, `{"target":"quiet.test"}`, "198.51.100.3:5000"); w.Code == http.StatusTooManyRequests {
		t.Error("an unrelated target was refused")
	}
}

func TestTargetLimitCarriesRetryAfter(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	for range targetBurst {
		postFrom(t, s, `{"target":"busy2.test"}`, "198.51.100.10:5000")
	}
	w := postFrom(t, s, `{"target":"busy2.test"}`, "198.51.100.11:5000")

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("Retry-After is missing, so a caller has nothing to wait for")
	}
}
