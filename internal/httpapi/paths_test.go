package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The check is addressed under its own name, and the old path keeps working.
//
// A page can be redirected because a browser follows a redirect on a GET and
// nothing is lost. A POST cannot: 307 and 308 preserve the body, 301 and 302
// do not, and clients disagree about which they follow. A caller whose body
// is silently dropped receives an error that looks like it came from the scan
// rather than from the move.
//
// So both paths are served by the same handler and answer identically. That
// is a promise, and this is where it is kept.
func TestBothScanPathsAreServedAndNeitherRedirects(t *testing.T) {
	for _, path := range []string{"/api/v1/tls/scan", "/api/v1/scan"} {
		s := New(offlineScanner(), Limits{}, nil)

		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"target":""}`))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "203.0.113.7:5000"

		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)

		if w.Code >= 300 && w.Code < 400 {
			t.Errorf("POST %s returned %d — a redirect on a POST loses the body for some clients",
				path, w.Code)
			continue
		}
		if w.Code == http.StatusNotFound {
			t.Errorf("POST %s returned 404; a path somebody has already scripted against cannot vanish", path)
			continue
		}

		// The same request reaches the same handler and is refused for the
		// same reason, which is what "identically" has to mean.
		if got := errorCode(t, w); got != errorCode(t, post(t, New(offlineScanner(), Limits{}, nil), `{"target":""}`)) {
			t.Errorf("POST %s was refused as %q, which is not what the other path answers", path, got)
		}
	}
}

// A GET is not a scan, whichever path it arrives on.
//
// The target travels in the body so that it stays out of browser history, out
// of a Referer header and out of every proxy log on the way. A path that
// answered a GET would put it back in all three.
func TestNeitherScanPathAnswersAGet(t *testing.T) {
	for _, path := range []string{"/api/v1/tls/scan", "/api/v1/scan"} {
		s := New(offlineScanner(), Limits{}, nil)

		r := httptest.NewRequest(http.MethodGet, path+"?target=example.com", nil)
		r.RemoteAddr = "203.0.113.7:5000"

		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)

		if w.Code == http.StatusOK {
			t.Errorf("GET %s was answered; a target in a URL is a target in a log", path)
		}
	}
}
