package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, r)
	return w
}

// Every route resolves. A fragment renamed without updating the table would
// otherwise be a page with a hole in it, found by a visitor.
func TestEveryRouteResolves(t *testing.T) {
	for path := range pages {
		w := get(t, path)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s returned %d", path, w.Code)
		}
		if w.Body.Len() == 0 {
			t.Errorf("GET %s returned an empty body", path)
		}
	}
	for path := range files {
		w := get(t, path)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s returned %d", path, w.Code)
		}
	}
}

// The reason for one layout is that four copies of a footer become four
// versions of it. This fails the moment a page stops sharing the shell.
func TestEveryPageCarriesTheSameShell(t *testing.T) {
	for path := range pages {
		body := get(t, path).Body.String()

		for _, required := range []string{
			`class="masthead"`,
			`class="wordmark"`,
			`class="colophon"`,
			`href="/scanning"`,
			`href="/privacy"`,
			`href="/terms"`,
			`id="tally"`,
		} {
			if !strings.Contains(body, required) {
				t.Errorf("%s is missing %s from the shared layout", path, required)
			}
		}
	}
}

// Each page needs a title of its own. A site where every tab says the same
// thing is a site nobody can navigate from their history.
func TestEachPageHasItsOwnTitle(t *testing.T) {
	seen := map[string]string{}

	for path := range pages {
		body := get(t, path).Body.String()

		start := strings.Index(body, "<title>")
		end := strings.Index(body, "</title>")
		if start < 0 || end < start {
			t.Errorf("%s has no title", path)
			continue
		}
		title := body[start+len("<title>") : end]

		if other, found := seen[title]; found {
			t.Errorf("%s and %s share the title %q", path, other, title)
		}
		seen[title] = path
	}
}

// Only the page that needs a script should load one. The fewer routes that
// execute code, the smaller the question of what that code does.
func TestOnlyTheScannerLoadsAScript(t *testing.T) {
	if !strings.Contains(get(t, "/").Body.String(), `src="/app.js"`) {
		t.Error("the scanner page does not load its script")
	}

	for _, path := range []string{"/scanning", "/terms", "/privacy"} {
		if strings.Contains(get(t, path).Body.String(), `src="/app.js"`) {
			t.Errorf("%s loads a script it does not need", path)
		}
	}
}

// The routes are an allow list, so nothing outside it is reachable, including
// anything that would be found by walking the embedded tree.
func TestUnlistedPathsAreNotServed(t *testing.T) {
	paths := []string{
		"/assets/index.html",
		"/assets/layout.html",
		"/layout.html",
		"/index.html",
		"/web.go",
		"/../web.go",
		"/assets",
		"/nothing-here",
		"/.git/config",
	}

	for _, path := range paths {
		if w := get(t, path); w.Code != http.StatusNotFound {
			t.Errorf("GET %s returned %d, want 404", path, w.Code)
		}
	}
}

// The page needs a stylesheet and a script; the API needs nothing. Sharing one
// policy between them is how a strict header quietly becomes a permissive one.
func TestContentSecurityPolicyAllowsOnlySelf(t *testing.T) {
	csp := get(t, "/").Header().Get("Content-Security-Policy")

	if csp == "" {
		t.Fatal("no Content-Security-Policy on the page")
	}

	for _, required := range []string{
		"default-src 'none'",
		"script-src 'self'",
		"style-src 'self'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
	} {
		if !strings.Contains(csp, required) {
			t.Errorf("the policy is missing %q: %s", required, csp)
		}
	}

	// Everything above is worth having only because of this. An inline
	// allowance would make the rest close to decorative.
	for _, forbidden := range []string{"unsafe-inline", "unsafe-eval", "*", "data:"} {
		if strings.Contains(csp, forbidden) {
			t.Errorf("the policy contains %q: %s", forbidden, csp)
		}
	}
}

// A page that carries inline style or script would force 'unsafe-inline' into
// the policy sooner or later. Keeping the assets free of it is what lets the
// policy stay strict.
func TestNoInlineStyleOrScript(t *testing.T) {
	for path := range pages {
		body := get(t, path).Body.String()

		for _, pattern := range []string{"<style", " style=", " onclick=", " onload=", " onerror="} {
			if strings.Contains(body, pattern) {
				t.Errorf("%s contains %q, which the policy forbids", path, pattern)
			}
		}
		// A script tag is permitted only as a reference to a file.
		if strings.Contains(body, "<script>") {
			t.Errorf("%s contains an inline script", path)
		}
	}
}

// Open item 6 of the threat model: the endpoint echoes the target on success,
// and hostnames are attacker-chosen. The first place that renders one is where
// this becomes exploitable, so the rendering code must have no way to reach a
// markup parser at all.
func TestScriptCannotInjectMarkup(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}

	forbidden := []string{
		"innerHTML",
		"outerHTML",
		"insertAdjacentHTML",
		"document.write",
		"eval(",
		"new Function(",
		"createContextualFragment",
	}

	source := string(script)
	for _, name := range forbidden {
		// The comment at the top of the file names these deliberately, so
		// only occurrences outside a comment would matter. Counting is enough
		// to notice a new one appearing.
		if strings.Count(source, name) > 1 {
			t.Errorf("the script mentions %s more than once; every node must be built with createElement and textContent", name)
		}
	}
}

func TestHeadersOnEveryResponse(t *testing.T) {
	responses := map[string]*httptest.ResponseRecorder{
		"home":    get(t, "/"),
		"privacy": get(t, "/privacy"),
		"asset":   get(t, "/style.css"),
		"404":     get(t, "/nothing-here"),
	}

	required := map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cache-Control":                "no-store",
	}

	for name, w := range responses {
		for header, want := range required {
			if got := w.Header().Get(header); got != want {
				t.Errorf("%s: %s = %q, want %q", name, header, got, want)
			}
		}
		if w.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("%s: no Content-Security-Policy", name)
		}
	}
}

func TestOnlyReadMethodsAreServed(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		r := httptest.NewRequest(method, "/", nil)
		w := httptest.NewRecorder()
		Handler().ServeHTTP(w, r)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s / returned %d, want 405", method, w.Code)
		}
	}
}

// The page has to explain itself to a reader whose browser runs no script,
// rather than presenting a form that silently does nothing.
func TestPageWorksWithoutScript(t *testing.T) {
	page := get(t, "/").Body.String()

	if !strings.Contains(page, "<noscript>") {
		t.Error("the page has no noscript block; without one the form appears to work and does not")
	}
	if !strings.Contains(page, "command line") {
		t.Error("the noscript block does not point anywhere a reader can actually go")
	}
}

// An administrator who finds this page from an address in their logs needs
// two things immediately: what was sent, and how to stop it. Both must be on
// the page rather than a link away.
func TestScanningPageAnswersTheUrgentQuestions(t *testing.T) {
	page := strings.ToLower(get(t, "/scanning").Body.String())

	for _, required := range []string{
		"abuse@denyfirst.dev",
		"handshake",
		"excluded",
		"scanner.denyfirst.dev",
	} {
		if !strings.Contains(page, strings.ToLower(required)) {
			t.Errorf("the scanning page does not mention %q", required)
		}
	}
}

// The privacy page has to state the boundary as well as the promise. A page
// that claims nothing is visible anywhere would be wrong, and being wrong
// about privacy is worse than being narrow about it.
func TestPrivacyPageStatesItsBoundary(t *testing.T) {
	page := strings.ToLower(get(t, "/privacy").Body.String())

	for _, required := range []string{
		"network provider",
		"rented server",
		"no analytics",
		"cookies",
	} {
		if !strings.Contains(page, required) {
			t.Errorf("the privacy page does not address %q", required)
		}
	}
}

// The terms have to put the decision to scan with the person making it.
func TestTermsPlaceResponsibility(t *testing.T) {
	page := strings.ToLower(get(t, "/terms").Body.String())

	for _, required := range []string{
		"permission",
		"without warranty",
		"agpl",
	} {
		if !strings.Contains(page, required) {
			t.Errorf("the terms do not address %q", required)
		}
	}
}
