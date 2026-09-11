package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/denyfirst/denyfirst/internal/demo"
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
	// Nothing may be in both tables: an address is either finished moving or
	// it is not. True of every build, so it is asserted before the branch —
	// an assertion below one is an assertion half the builds never run.
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

	// The root itself differs by deployment since 2026-09-12, and this is where
	// that is asserted rather than assumed.
	//
	// On the demonstration it still stands in for /tls: that deployment exists
	// to explain a check to somebody who arrived from a log line, and a console
	// asking them to choose checks answers a question they did not ask. On an
	// installation somebody runs themselves the root is the tool, because
	// nobody there needs persuading that scanning is safe.
	w := get(t, "/")

	if !demo.Enabled {
		if w.Code != http.StatusOK {
			t.Fatalf("GET / returned %d on a self-hosted build, want 200: the root is the tool "+
				"there, not a redirect to one check of three", w.Code)
		}
		if got := w.Header().Get("Location"); got != "" {
			t.Errorf("GET / redirects to %q on a self-hosted build", got)
		}
		return
	}

	if w.Code != http.StatusFound {
		t.Errorf("GET / returned %d, want 302 — the root is going to change, and a "+
			"permanent redirect would say the opposite", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/tls" {
		t.Errorf("GET / redirects to %q, want /tls", got)
	}
}

// Every link the pages carry points at something this server answers.
//
// Moving a page is where internal links rot, and a footer link is on every
// page of the site — so one stale href is stale everywhere at once.
func TestEveryInternalLinkResolves(t *testing.T) {
	answered := func(path string) bool {
		// rendered rather than pages, because the console is not in that table:
		// its content depends on how the program was started, so it is built
		// separately and lands here. A link checker reading only the table
		// would call the root unanswered on every installation that serves it.
		if _, ok := rendered[path]; ok {
			return true
		}
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
	for path := range rendered {
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

// Each check calls its own path, and points at its own method page.
//
// One script serves both pages, so the addresses are a table in it rather than
// a constant. That is the thing worth checking: not that some string is
// present, but that each check names the endpoint and the page that belong to
// it. A table where one row carried the other's path would send a reader to
// limits that are not theirs and would grade one check with the other's rules.
func TestEachCheckCallsItsOwnPaths(t *testing.T) {
	source := script(t)

	for _, tc := range []struct {
		check      string
		endpoint   string
		methodPage string
	}{
		{"tls", "/api/v1/tls/scan", "/tls/method"},
		{"web", "/api/v1/web/scan", "/web/method"},

		// The mail check has no method page of its own yet, so its row
		// declares none. An empty string rather than a borrowed page: the
		// console prints that check's limits in full instead, which is the
		// same decision the command line made. A URL for a page nobody has
		// written is worse than no URL, because a reader follows it.
		{"mail", "/api/v1/mail/scan", ""},
	} {
		for _, want := range []string{
			`endpoint: "` + tc.endpoint + `"`,
			`methodPage: "` + tc.methodPage + `"`,
		} {
			if !strings.Contains(source, want) {
				t.Errorf("the %s check does not declare %s", tc.check, want)
			}
		}

		// And any address it points at is one this service answers.
		if tc.methodPage == "" {
			continue
		}
		if _, ok := pages[tc.methodPage]; !ok {
			t.Errorf("the %s check points at %s, which this site does not serve", tc.check, tc.methodPage)
		}
	}

	// The old path is still answered — see the API's own test for why it is
	// not a redirect — but the page this repository ships uses the current one.
	if strings.Contains(source, `fetch("/api/v1/scan"`) {
		t.Error("the page still calls the old API path")
	}

	// The endpoint is read from the table rather than written at the call.
	//
	// It reads spec.endpoint rather than CHECK.endpoint since 2026-09-12: the
	// console runs several checks from one page, so which one is being run is
	// an argument now instead of a constant chosen when the page loaded. The
	// property being asserted is unchanged — the fetch takes its address from
	// the table, whatever selected the row.
	if !strings.Contains(source, "fetch(spec.endpoint,") {
		t.Error("the script does not fetch the endpoint the table declared, so the table decides nothing")
	}

	// And the console runs every check the table holds.
	//
	// A check declared and never offered is a check nobody can run from the
	// page that exists to run them.
	for _, name := range []string{"tls", "web", "mail"} {
		if !strings.Contains(source, `"`+name+`"`) {
			t.Errorf("the console's order does not name the %s check", name)
		}
	}
}

// A page says which check it is, and the script believes the page.
//
// Not the path. A path is a thing that moves — this project has moved two of
// them already — and a script that worked out which check it was running by
// reading the URL would be wrong the day one moves again, quietly, by grading
// a web report with the TLS renderer.
func TestEachScanPageDeclaresItsCheck(t *testing.T) {
	for path, check := range map[string]string{
		"/tls": "tls",
		"/web": "web",
	} {
		body, ok := rendered[path]
		if !ok {
			t.Errorf("%s is not served", path)
			continue
		}
		if !strings.Contains(string(body), `data-check="`+check+`"`) {
			t.Errorf("%s does not declare itself as the %q check, so the script would fall back to "+
				"another check's endpoint and renderer", path, check)
		}
	}
}

// A check's page sends a reader to that check's limits, footer included.
//
// The footer is the one piece of markup every page shares, and it carried one
// address while there was one check. The moment there were two, /web served a
// report and then offered "How a report is read" pointing at the limits of a
// TLS handshake — which is the confusion the method pages are separate to
// prevent, arriving through the only element that is on every page at once.
//
// Caught by looking at the rendered page rather than by reading the layout,
// because what a reader clicks is the rendered href.
func TestEachCheckPageSendsAReaderToItsOwnLimits(t *testing.T) {
	for path, want := range map[string]string{
		"/tls":        "/tls/method",
		"/tls/method": "/tls/method",
		"/web":        "/web/method",
		"/web/method": "/web/method",
	} {
		body := string(rendered[path])
		if body == "" {
			t.Errorf("%s is not served", path)
			continue
		}

		other := "/tls/method"
		if want == "/tls/method" {
			other = "/web/method"
		}

		if !strings.Contains(body, `href="`+want+`">How a report is read`) {
			t.Errorf("%s does not point its footer at %s", path, want)
		}
		if strings.Contains(body, `href="`+other+`">How a report is read`) {
			t.Errorf("%s points its footer at %s, which is another check's limits", path, other)
		}
	}

	// A page that is not a check's still points somewhere, because a reader
	// who arrived from a report has to be able to get back to what it means.
	for _, path := range []string{"/privacy", "/terms"} {
		if !strings.Contains(string(rendered[path]), `>How a report is read`) {
			t.Errorf("%s carries no link explaining how a report is read", path)
		}
	}
}
