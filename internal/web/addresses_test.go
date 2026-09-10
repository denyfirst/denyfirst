package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/webprobe"
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

	// The question this test was written to ask ahead of time. There are two
	// checks now, so the answer is a list rather than one prefix — and a
	// third check added without an entry here fails rather than quietly
	// putting a page at the root.
	checks := []string{"/tls", "/web"}

	underACheck := func(path string) bool {
		for _, prefix := range checks {
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				return true
			}
		}
		return false
	}

	for path := range pages {
		switch {
		case project[path]:
		case underACheck(path):
		default:
			t.Errorf("%s is neither one of the project's own pages nor under a check; "+
				"decide which it is before a third check makes the question urgent", path)
		}
	}

	for path := range project {
		if _, ok := pages[path]; !ok {
			t.Errorf("%s is not served, and it is one of the project's own pages", path)
		}
	}

	// Every check's method page is where that check says it is.
	//
	// The limits of a TLS handshake are not the limits of a header check, and
	// a page trying to be both would be true of neither.
	for _, path := range []string{"/tls", "/tls/method", "/web/method"} {
		if w := get(t, path); w.Code != http.StatusOK {
			t.Errorf("GET %s returned %d", path, w.Code)
		}
	}
}

// An address this project sends to somebody else's server resolves here.
//
// N7 gives the web probe a user agent naming a page that explains exactly
// what was sent, because a probe that hides is one an administrator can only
// be alarmed by while one that identifies itself is one they can make a
// decision about. That promise is only as good as the address: a 404 makes
// the probe look like it is hiding, to the one reader who went looking.
//
// TestEveryInternalLinkResolves follows the links on the pages. This is the
// other direction — an address this program puts in a request it makes — and
// it was not covered by anything until the address it names had gone
// unserved through an entire release.
func TestEveryAddressThisProjectSendsOutResolves(t *testing.T) {
	// Each is a string this project transmits to a third party, and the path
	// it promises them.
	for _, tc := range []struct {
		what string
		sent string
	}{
		{"the web probe's user agent", webprobe.DefaultUserAgent},
	} {
		path := pathOfDenyfirstURL(t, tc.sent)
		if path == "" {
			t.Errorf("%s names no address on this site: %q", tc.what, tc.sent)
			continue
		}

		w := get(t, path)
		if w.Code == http.StatusOK {
			continue
		}
		if location := w.Header().Get("Location"); w.Code/100 == 3 && location != "" {
			if get(t, location).Code == http.StatusOK {
				continue
			}
		}
		t.Errorf("%s tells an administrator to read %s, and this site answers %d. "+
			"The whole reason the probe identifies itself is that the address it gives leads somewhere",
			tc.what, path, w.Code)
	}
}

// pathOfDenyfirstURL pulls the path out of the first denyfirst.dev address in
// a string, which is the shape a user agent comment uses.
func pathOfDenyfirstURL(t *testing.T, s string) string {
	t.Helper()

	const marker = "https://denyfirst.dev"
	i := strings.Index(s, marker)
	if i < 0 {
		return ""
	}

	rest := s[i+len(marker):]
	if end := strings.IndexAny(rest, " )\t\r\n"); end >= 0 {
		rest = rest[:end]
	}
	if rest == "" {
		return "/"
	}
	return rest
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

			fragment := ""
			if i := strings.Index(href, "#"); i >= 0 {
				href, fragment = href[:i], href[i+1:]
			}
			if href == "" {
				continue
			}
			if !answered(href) {
				t.Errorf("%s links to %s, which this server does not answer", path, href)
				continue
			}

			// The heading a link aims at exists on the page it aims at.
			//
			// Stripping the fragment and stopping was enough while every
			// link's target was a page somebody had just written. It stopped
			// being enough the moment a page was written against another
			// page's headings: /privacy#exclusion pointed at a section that
			// has never existed, the link resolved because /privacy does, and
			// a reader following it would have landed at the top of a long
			// page with no idea which part answered them.
			if fragment == "" {
				continue
			}
			if _, isPage := pages[href]; !isPage {
				continue
			}
			if target := get(t, href).Body.String(); !strings.Contains(target, `id="`+fragment+`"`) {
				t.Errorf("%s links to %s#%s, and %s carries no heading with that id",
					path, href, fragment, href)
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
