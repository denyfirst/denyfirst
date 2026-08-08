package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// FuzzScanHandler sends arbitrary bodies to the endpoint that strangers reach.
//
// The strongest assertion here is the one about reflection. Invariant I3 says
// an error message describes the rule and never repeats what was sent, and
// until now that was checked with two hand-written strings. A fuzzer tries
// millions, including the shapes nobody would think to write down.
func FuzzScanHandler(f *testing.F) {
	seeds := []string{
		`{"target":"example.test"}`,
		`{"target":"example.test:8443"}`,
		`{"target":"example.test:22"}`,
		`{"target":""}`,
		`{"target":"<script>alert(1)</script>"}`,
		`{"target":"exam ple.test"}`,
		`{}`,
		`[]`,
		`null`,
		`not json`,
		``,
		`{"target":"a","extra":1}`,
		`{"target":"a"} {"target":"b"}`,
		`{"TARGET":"example.test"}`,
		`{"target":123}`,
		`{"target":["example.test"]}`,
		`{"target":{"host":"example.test"}}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	// A generous burst keeps the rate limiter from turning every case into a
	// 429, which would test nothing.
	s := New(offlineScanner(), Limits{
		Burst:          1_000_000,
		Refill:         time.Nanosecond,
		RequestTimeout: 2 * time.Second,
	}, nil)

	f.Fuzz(func(t *testing.T, body string) {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "203.0.113.50:5000"

		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)

		// Malformed input is the client's problem and must be reported as
		// such. A 500 means the handler was surprised, which is a bug here
		// rather than a bad request.
		if w.Code == http.StatusInternalServerError {
			t.Fatalf("body %q produced a 500", body)
		}
		if w.Code < 200 || w.Code > 599 {
			t.Fatalf("body %q produced status %d", body, w.Code)
		}

		// Whatever happened, the answer is JSON. A caller parsing responses
		// should never meet a bare string.
		if w.Body.Len() > 0 {
			var any any
			if err := json.Unmarshal(w.Body.Bytes(), &any); err != nil {
				t.Fatalf("body %q produced a response that is not JSON: %v", body, err)
			}
		}

		// Every response carries the policy, error or not.
		if got := w.Header().Get("Content-Security-Policy"); got == "" {
			t.Fatalf("body %q produced a response with no Content-Security-Policy", body)
		}
		if got := w.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("body %q produced Cache-Control %q, want no-store", body, got)
		}

		// Invariant I3. Only error responses are checked: a successful scan
		// names its target on purpose, and that is not a reflection.
		//
		// Short inputs are skipped because a handful of characters can appear
		// in a fixed message by coincidence, which would be a false alarm
		// rather than a finding.
		if w.Code >= 400 && len(body) >= 12 {
			if strings.Contains(w.Body.String(), body) {
				t.Fatalf("an error response repeated the request body verbatim: %s", w.Body.String())
			}
		}
	})
}
