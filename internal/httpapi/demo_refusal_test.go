//go:build demo

package httpapi

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// A host this deployment does not demonstrate is refused in words, and counted.
//
// Scanner.Scan refuses the same host and that is where the property lives.
// This is the other half: a caller gets a sentence and a way forward rather
// than a scan that failed, and the refusal is counted as what it is rather
// than as a host that could not be reached — a figure rising here would say
// visitors are asking for something this deployment does not do, which is how
// we would learn the page is not explaining itself.
func TestTheDemonstrationRefusalIsAnsweredAndCounted(t *testing.T) {
	s := New(offlineScanner(), Limits{Burst: 1000, Refill: time.Nanosecond}, nil)

	w := postFrom(t, s, `{"target":"example.com"}`, "203.0.113.9:5000")

	if w.Code != http.StatusForbidden {
		t.Errorf("returned %d, want 403", w.Code)
	}
	if got := errorCode(t, w); got != "not_demonstrated" {
		t.Errorf("refused as %q, want %q", got, "not_demonstrated")
	}

	// The message has to leave the reader somewhere to go. A refusal that
	// only says no teaches them the service is broken.
	body := w.Body.String()
	for _, want := range []string{"hosts this project owns", "github.com/denyfirst/denyfirst"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal does not say %q", want)
		}
	}

	// And it does not repeat the host back into a message that is printed.
	if strings.Contains(body, "example.com") {
		t.Error("the refusal echoes the host it was given")
	}

	if got := s.counts.snapshot().Refused["not_demonstrated"]; got != 1 {
		t.Errorf("the refusal was counted %d times, want 1", got)
	}
}
