package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/policy"
)

// postMail sends a mail scan the way a client would.
func postMail(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/mail/scan", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "203.0.113.40:5000"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// An address is accepted, and only its domain goes any further.
//
// The mail scanner has always dropped a local part; the service refused the
// address before the scanner saw it, so pasting one was an error on one surface
// and the natural thing on the other (audit A32).
func TestAMailAddressIsAcceptedAsItsDomain(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	w := postMail(t, s, `{"target":"someone.private@example.test"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("an address was refused: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "someone") {
		t.Errorf("the local part reached the report: %s", w.Body.String())
	}
	var got struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Domain != "example.test" {
		t.Errorf("the report is about %q", got.Domain)
	}

	for _, body := range []string{`{"target":"someone@"}`, `{"target":"@"}`,
		`{"target":"someone@example.test:25"}`, `{"target":"someone@192.0.2.1"}`} {
		if w := postMail(t, s, body); w.Code == http.StatusOK {
			t.Errorf("%s was scanned", body)
		} else if strings.Contains(w.Body.String(), "someone") {
			t.Errorf("%s: the refusal repeats the local part: %s", body, w.Body.String())
		}
	}
}

// Mail scans are counted under their own name and rule set, and move nothing
// else (audit A32: a mail scan counted nowhere).
func TestAMailScanIsCountedAsOne(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)
	before := s.Stats()

	if w := postMail(t, s, `{"target":"example.test"}`); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}

	after := s.Stats()
	mail := after.Checks[checkMail]
	if mail.Total != 1 || mail.Today != 1 {
		t.Errorf("the mail block is %+v", mail)
	}
	if mail.Policy != policy.MailVersion {
		t.Errorf("the mail block names rule set %q", mail.Policy)
	}
	if after.Total != before.Total || after.Today != before.Today {
		t.Errorf("a mail scan moved the published TLS figures: %+v", after)
	}
}
