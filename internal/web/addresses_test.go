package web

import (
	"net/http"
	"strings"
	"testing"
)

// Where things live, and why the two redirects are different kinds.
//
// The project has one check today and expects more. A site with one service
// and a service with one site are the same thing right up until the second
// service, and by then every report anybody has shared points at "/". So the
// check was given an address of its own while moving it costs nothing.

// The project's own pages stay at the root, and the check's live under it.
//
// Privacy and terms are promises the project makes about everything it runs,
// not about this scan; security.txt and the key are how somebody reaches a
// person. None of those belong under a service, and a copy of them under each
// one would be four copies of a promise to keep in step.
func TestTheProjectsPagesStayAtTheRootAndTheChecksDoNot(t *testing.T) {
	project := map[string]bool{
		"/privacy": true,
		"/terms":   true,
	}

	for path := range pages {
		switch {
		case project[path]:
		case strings.HasPrefix(path, "/tls"):
		default:
			t.Errorf("%s is neither one of the project's own pages nor under a check; "+
				"decide which it is before a second check makes the question urgent", path)
		}
	}

	for path := range project {
		if _, ok := pages[path]; !ok {
			t.Errorf("%s is not served, and it is one of the project's own pages", path)
		}
	}

	// The check is where it says it is.
	if w := get(t, "/tls"); w.Code != http.StatusOK {
		t.Errorf("GET /tls returned %d", w.Code)
	}
	if w := get(t, "/tls/method"); w.Code != http.StatusOK {
		t.Errorf("GET /tls/method returned %d", w.Code)
	}
}

// The root stands in. It does not move.
//
// "/" sends a visitor to the one check there is, and will stop doing so when
// there is a front page to put there. That is a temporary state and the
// status code says so: a permanent redirect is a promise that an address has
// finished changing, and this one has not. The method page's redirect is the
// other kind, because it is not coming back to the root.
func TestTheRootStandsInAndSaysSoInTheStatusCode(t *testing.T) {
	w := get(t, "/")

	if w.Code != http.StatusFound {
		t.Errorf("GET / returned %d, want 302 — the root is going to change, and a "+
			"permanent redirect would say the opposite", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/tls" {
		t.Errorf("GET / redirects to %q, want /tls", got)
	}

	// Nothing may be in both tables: an address is either finished moving or
	// it is not.
	for path := range standingIn {
		if to, found := moved[path]; found {
			t.Errorf("%s stands in and is also permanently moved to %s", path, to)
		}
	}

	// The one that really did move.
	m := get(t, "/method")
	if m.Code != http.StatusMovedPermanently {
		t.Errorf("GET /method returned %d, want 301", m.Code)
	}
	if got := m.Header().Get("Location"); got != "/tls/method" {
		t.Errorf("GET /method redirects to %q, want /tls/method", got)
	}
}

// Every link the pages carry points at something this server answers.
//
// Moving a page is where internal links rot, and a footer link is on every
// page of the site — so one stale href is stale everywhere at once.
func TestEveryInternalLinkResolves(t *testing.T) {
	answered := func(path string) bool {
		if _, ok := pages[path]; ok {
			return true
		}
		if _, ok := files[path]; ok {
			return true
		}
		if _, ok := moved[path]; ok {
			return true
		}
		_, ok := standingIn[path]
		return ok
	}

	seen := 0
	for path := range pages {
		body := get(t, path).Body.String()
		for _, part := range strings.Split(body, `href="`)[1:] {
			href := part[:strings.Index(part, `"`)]
			if !strings.HasPrefix(href, "/") {
				continue
			}
			seen++
			if i := strings.Index(href, "#"); i >= 0 {
				href = href[:i]
			}
			if href == "" {
				continue
			}
			if !answered(href) {
				t.Errorf("%s links to %s, which this server does not answer", path, href)
			}
		}
	}
	if seen < 8 {
		t.Fatalf("only %d internal links were found, which is too few to be right", seen)
	}
}

// The script calls the check's own path.
//
// The page moved under the check and the call it makes moved with it. The old
// path is still answered — see the API's own test for why it is not a
// redirect — but the page this repository ships uses the current one.
func TestTheScriptCallsTheChecksOwnPath(t *testing.T) {
	source := script(t)

	if !strings.Contains(source, `fetch("/api/v1/tls/scan"`) {
		t.Error("the page does not call the check's own API path")
	}
	if strings.Contains(source, `fetch("/api/v1/scan"`) {
		t.Error("the page still calls the old API path")
	}
	if !strings.Contains(source, `const METHOD_PAGE = "/tls/method"`) {
		t.Error("the report points at a method page that is no longer there")
	}
}
