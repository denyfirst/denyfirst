package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/scan"
	"github.com/denyfirst/porch/internal/verify"
)

type verifyAnswer struct {
	Required bool `json:"required"`
	Verified bool `json:"verified"`
	Records  []struct {
		Domain string `json:"domain"`
		Name   string `json:"name"`
		Value  string `json:"value"`
	} `json:"records"`
}

func askVerify(t *testing.T, s *Server, target string) (int, verifyAnswer, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"target": target})
	w := postTo(t, s, "/api/v1/verify", string(body), "203.0.113.60:5000")
	var got verifyAnswer
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decoding %s: %v", w.Body.String(), err)
		}
	}
	return w.Code, got, w.Body.String()
}

// The page is told what to publish, and whether it has been.
func TestTheVerifyEndpointNamesTheRecordAndSaysWhetherItIsThere(t *testing.T) {
	scope, _ := scopeProving("proven.test")
	var tlsReached, webReached atomic.Bool
	s := verifyingService(scope, &tlsReached, &webReached)

	code, got, body := askVerify(t, s, "www.unproven.test")
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	if !got.Required || got.Verified {
		t.Errorf("an unproven name: %+v", got)
	}
	if len(got.Records) != 2 || got.Records[0].Domain != "www.unproven.test" || got.Records[1].Domain != "unproven.test" {
		t.Fatalf("records are %+v, want the name and then its parent", got.Records)
	}
	for _, r := range got.Records {
		if r.Name != verify.Label+"."+r.Domain || r.Value != verify.Token(verificationSecret, r.Domain) {
			t.Errorf("a record does not match what the boundary checks: %+v", r)
		}
	}

	// A parent's proof covers the name, and the endpoint says so.
	if _, got, _ := askVerify(t, s, "deep.www.proven.test"); !got.Verified {
		t.Errorf("a name beneath a proven domain is reported unverified: %+v", got)
	}

	// Nothing was dialled: asking is a DNS lookup and nothing else.
	if tlsReached.Load() || webReached.Load() {
		t.Error("asking whether a name is proven opened a connection to it")
	}
}

// A mail address and a port are read as the name they name.
func TestTheVerifyEndpointReadsWhatTheChecksRead(t *testing.T) {
	scope, _ := scopeProving("proven.test")
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)

	for _, target := range []string{"someone@proven.test", "proven.test:993", "PROVEN.test."} {
		code, got, body := askVerify(t, s, target)
		if code != http.StatusOK || !got.Verified {
			t.Errorf("%q: %d %s", target, code, body)
		}
		if strings.Contains(body, "someone") {
			t.Errorf("%q: the local part came back: %s", target, body)
		}
	}
	for _, target := range []string{"", "localhost", "intranet", "192.0.2.1", "bad name.test", "someone@"} {
		if code, _, _ := askVerify(t, s, target); code == http.StatusOK {
			t.Errorf("%q was answered", target)
		}
	}
}

// A deployment that asks for no proof says so and hands out nothing.
func TestAnOpenDeploymentHasNothingToVerify(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	code, got, body := askVerify(t, s, "example.test")
	if code != http.StatusOK || got.Required || got.Verified || len(got.Records) != 0 {
		t.Errorf("%d %s", code, body)
	}
}

type failingChallenges struct{}

func (failingChallenges) LookupChallenge(context.Context, string) ([]string, bool, error) {
	return nil, false, errors.New("resolver 10.0.0.53 timed out")
}

// A lookup that failed is not a name that is unproven, and says nothing of the
// resolver.
func TestAFailedChallengeLookupIsNotUnverified(t *testing.T) {
	s := New(&scan.Scanner{Verify: &verify.Scope{Secret: verificationSecret, Resolver: failingChallenges{}}},
		Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	code, _, body := askVerify(t, s, "example.test")
	if code != http.StatusBadGateway {
		t.Errorf("status %d: %s", code, body)
	}
	if strings.Contains(body, "10.0.0.53") || strings.Contains(body, "example.test") {
		t.Errorf("the refusal carries more than its shape: %s", body)
	}
}

// The endpoint walks the same guards a scan does.
func TestTheVerifyEndpointHasTheScanGuards(t *testing.T) {
	scope, _ := scopeProving()
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)

	r := postTo(t, s, "/api/v1/verify", `{"target":"example.test","x":1}`, "203.0.113.61:5000")
	if got := errorCode(t, r); got != "bad_request" {
		t.Errorf("an unknown field: %q", got)
	}

	tight := New(&scan.Scanner{Verify: scope}, Limits{ProofBurst: 1, ProofRefill: time.Hour}, nil)
	postTo(t, tight, "/api/v1/verify", `{"target":"example.test"}`, "203.0.113.62:5000")
	if got := errorCode(t, postTo(t, tight, "/api/v1/verify", `{"target":"example.test"}`, "203.0.113.62:5000")); got != "rate_limited" {
		t.Errorf("a second ask inside the budget: %q", got)
	}

	if got := errorCode(t, postTo(t, s, "/api/v1/verify", `{"target":"example.mil"}`, "203.0.113.63:5000")); got != "excluded" {
		t.Errorf("an excluded name: %q", got)
	}
}

// At most a handful of records, however deep the name.
func TestTheVerifyRecordsAreBounded(t *testing.T) {
	scope, _ := scopeProving()
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)
	_, got, _ := askVerify(t, s, "a.b.c.d.e.f.g.example.test")
	if len(got.Records) != maxVerifyRecords {
		t.Errorf("%d records", len(got.Records))
	}
}

// Only the verify endpoint is exempt from being driven as a scan.
func TestOnlyTheVerifyEndpointAsksWithoutScanning(t *testing.T) {
	s := New(offlineScanner(), Limits{}, nil)
	var asking []string
	for _, rt := range s.routes {
		if rt.asksOnly {
			asking = append(asking, rt.method+" "+rt.path)
		}
	}
	if len(asking) != 1 || asking[0] != "POST /api/v1/verify" {
		t.Errorf("routes exempt from the scan boundary tests: %v", asking)
	}
}

type fileServed struct{ value string }

func (f fileServed) FetchChallenge(context.Context, string) (string, error) { return f.value, nil }

// The endpoint answers for the zone proof, which every check accepts. A file
// opens the web check alone, so a page told "verified" by one would run checks
// that are then refused.
func TestAServedFileIsNotReportedAsProofForEveryCheck(t *testing.T) {
	scope, _ := scopeProving()
	scope.Fetcher = fileServed{value: verify.Token(verificationSecret, "files.test")}
	var a, b atomic.Bool
	s := verifyingService(scope, &a, &b)

	if _, got, body := askVerify(t, s, "files.test"); got.Verified {
		t.Errorf("a served file was reported as proof for every check: %s", body)
	}
}

// Asking whether domains are proven spends an allowance of its own (audit
// 2026-09-18, D04): opening a Domains page of ten leaves every scan in the
// allowance, and scanning leaves every proof check. The proof allowance is
// bounded all the same, and says which allowance ran out.
func TestProvingDomainsDoesNotSpendTheScanAllowance(t *testing.T) {
	scope, _ := scopeProving()
	s := New(&scan.Scanner{Verify: scope}, Limits{Burst: 2, Refill: time.Hour, ProofBurst: 10, ProofRefill: time.Hour}, nil)
	const from = "203.0.113.70:5000"

	for i := range 10 {
		if r := postTo(t, s, "/api/v1/verify", `{"target":"d`+string(rune('a'+i))+`.example.test"}`, from); r.Code != http.StatusOK {
			t.Fatalf("proof check %d: %d %s", i+1, r.Code, r.Body.String())
		}
	}
	for i := range 2 {
		if got := errorCode(t, postTo(t, s, "/api/v1/scan", `{"target":"example.test"}`, from)); got == "rate_limited" {
			t.Fatalf("scan %d after ten proof checks was refused for the allowance", i+1)
		}
	}
	if got := errorCode(t, postTo(t, s, "/api/v1/scan", `{"target":"example.test"}`, from)); got != "rate_limited" {
		t.Errorf("the scan allowance is not bounded any more: %q", got)
	}

	r := postTo(t, s, "/api/v1/verify", `{"target":"example.test"}`, from)
	if got := errorCode(t, r); got != "rate_limited" || !strings.Contains(r.Body.String(), "proof checks") {
		t.Errorf("an eleventh proof check: %q, %s", got, r.Body.String())
	}

	// The other way round: a spent scan allowance leaves proof checks.
	other := New(&scan.Scanner{Verify: scope}, Limits{Burst: 1, Refill: time.Hour}, nil)
	postTo(t, other, "/api/v1/scan", `{"target":"example.test"}`, from)
	if r := postTo(t, other, "/api/v1/verify", `{"target":"example.test"}`, from); r.Code != http.StatusOK {
		t.Errorf("a spent scan allowance refused a proof check: %d %s", r.Code, r.Body.String())
	}
}

// slowZone answers a challenge lookup only once released, or when the asker
// gives up, and remembers the most lookups it had in flight at once.
type slowZone struct {
	release  chan struct{}
	inFlight atomic.Int32
	most     atomic.Int32
}

func (z *slowZone) LookupChallenge(ctx context.Context, _ string) ([]string, bool, error) {
	n := z.inFlight.Add(1)
	defer z.inFlight.Add(-1)
	for {
		m := z.most.Load()
		if n <= m || z.most.CompareAndSwap(m, n) {
			break
		}
	}
	select {
	case <-z.release:
		return nil, false, nil
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
}

// However many ask, at most MaxConcurrentProofs lookups are in flight (D10),
// apart from the scan slots: with one scan slot, two proof lookups run. A
// request that waits past its deadline is released with a refusal rather than
// run late, and once the slow lookups finish the next one is answered.
func TestProofLookupsInFlightAreBounded(t *testing.T) {
	zone := &slowZone{release: make(chan struct{})}
	scope := &verify.Scope{Secret: verificationSecret, Resolver: zone}
	s := New(&scan.Scanner{Verify: scope}, Limits{
		MaxConcurrent: 1, MaxConcurrentProofs: 2, RequestTimeout: 30 * time.Second,
		ProofBurst: 100, ProofRefill: time.Nanosecond,
	}, nil)

	type answer struct {
		code int
		body string
	}
	// ask posts from its own address, giving up after wait.
	ask := func(i int, wait time.Duration) <-chan answer {
		out := make(chan answer, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), wait)
			defer cancel()
			r := httptest.NewRequest(http.MethodPost, "/api/v1/verify", strings.NewReader(`{"target":"example.test"}`)).WithContext(ctx)
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = "203.0.113.71:" + strconv.Itoa(5000+i)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			out <- answer{w.Code, w.Body.String()}
		}()
		return out
	}

	first := []<-chan answer{ask(0, time.Minute), ask(1, time.Minute)}
	deadline := time.Now().Add(5 * time.Second)
	for zone.inFlight.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("two proof lookups did not start alongside one scan slot: %d in flight", zone.inFlight.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The slots are full: these wait, give up, and are refused unasked.
	queued := []<-chan answer{ask(2, 300*time.Millisecond), ask(3, 300*time.Millisecond), ask(4, 300*time.Millisecond)}
	for _, q := range queued {
		a := <-q
		if a.code != http.StatusServiceUnavailable || !strings.Contains(a.body, "too_busy") {
			t.Errorf("a proof check that gave up in the queue: %d %s", a.code, a.body)
		}
	}
	if most := zone.most.Load(); most != 2 {
		t.Errorf("%d lookups were in flight at once, want the bound of 2", most)
	}

	close(zone.release)
	for _, f := range first {
		if a := <-f; a.code != http.StatusOK {
			t.Errorf("a lookup that held a slot: %d %s", a.code, a.body)
		}
	}
	if a := <-ask(5, time.Minute); a.code != http.StatusOK {
		t.Errorf("after the slots emptied: %d %s", a.code, a.body)
	}
}
