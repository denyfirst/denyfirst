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
		if w := get(t, path); w.Code != http.StatusOK {
			t.Errorf("GET %s returned %d", path, w.Code)
		}
	}
}

// The old addresses are printed on scanning notices and may be sitting in
// somebody's notes, so they redirect rather than disappearing.
func TestOldPathsRedirect(t *testing.T) {
	for from, to := range moved {
		w := get(t, from)

		if w.Code != http.StatusMovedPermanently {
			t.Errorf("GET %s returned %d, want 301", from, w.Code)
			continue
		}
		if got := w.Header().Get("Location"); got != to {
			t.Errorf("GET %s redirects to %q, want %q", from, got, to)
		}
	}
}

// The reason for one layout is that copies of a footer become versions of it.
// This fails the moment a page stops sharing the shell.
func TestEveryPageCarriesTheSameShell(t *testing.T) {
	for path := range pages {
		body := get(t, path).Body.String()

		for _, required := range []string{
			`class="masthead"`,
			`class="wordmark"`,
			`class="colophon"`,
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
	if !strings.Contains(get(t, "/tls").Body.String(), `src="/app.js"`) {
		t.Error("the scanner page does not load its script")
	}

	for _, path := range []string{"/privacy", "/terms"} {
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
		if strings.Contains(body, "<script>") {
			t.Errorf("%s contains an inline script", path)
		}
	}
}

// The endpoint echoes the target on success, and hostnames are chosen by
// whoever asks. The first place that renders one is where that becomes
// exploitable, so the rendering code must have no way to reach a markup
// parser at all.
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
		"home":     get(t, "/"),
		"privacy":  get(t, "/privacy"),
		"asset":    get(t, "/style.css"),
		"redirect": get(t, "/scanning"),
		"404":      get(t, "/nothing-here"),
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
	page := get(t, "/tls").Body.String()

	if !strings.Contains(page, "<noscript>") {
		t.Error("the page has no noscript block; without one the form appears to work and does not")
	}
	if !strings.Contains(page, "command line") {
		t.Error("the noscript block does not point anywhere a reader can actually go")
	}
}

// The scanner page carries the tool and a link, and the explanation lives on
// the page written for it. A paragraph that repeats a link is a paragraph the
// reader learns to skip, and the skipping generalises.
func TestTheScannerPageDoesNotRepeatThePrivacyPage(t *testing.T) {
	page := get(t, "/tls").Body.String()

	if !strings.Contains(page, `href="/privacy#scans"`) {
		t.Error("the scanner page does not link to the explanation of what a scan sends")
	}

	// Wording that used to be duplicated here and is now only on /privacy.
	for _, moved := range []string{
		"out of every proxy log",
		"real handshake at every TLS version",
		"written down at this end",
	} {
		if strings.Contains(page, moved) {
			t.Errorf("the scanner page still repeats %q, which the privacy page says at length", moved)
		}
	}

	// The one line that has to stay: it is what the tool is for.
	//
	// Matched without regard to case, because the line lives in the heading
	// now and lost its capital when it moved there. What matters is that the
	// claim is still made, not where the sentence happens to break.
	if !strings.Contains(strings.ToLower(page), "not what it advertises") {
		t.Error("the scanner page no longer says what it is for")
	}
}

// An empty findings list means two different things, and the script has to
// tell them apart. "Nothing fell short of the rules" under a scan that
// reached nothing is true and reads as a pass, which is the single worst
// thing a report of this kind can do.
//
// This checks the script rather than a rendered page, because the page is
// assembled in the browser. It is a shape check: the wording is there and the
// branch that chooses it is there.
func TestEmptyFindingsDistinguishesCleanFromAbsent(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("reading the script: %v", err)
	}
	source := string(script)

	for _, required := range []string{
		"Nothing here fell short of the rules.",
		"Nothing was measured, so nothing could be graded.",
		`verdict === "ungraded"`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("the script does not contain %q", required)
		}
	}

	// The resolved verdict has to reach both sections. Passing data.verdict
	// straight through hands them undefined exactly when the distinction
	// matters, because the field is omitted rather than set to "ungraded".
	if strings.Contains(source, "notes(data.notes, data.verdict)") ||
		strings.Contains(source, "findings(data.findings, data.verdict)") {
		t.Error("a section is given data.verdict, which is absent for an ungraded scan; give it the resolved value")
	}
}

// One page now answers what used to be three. An administrator who arrives
// from a scanning notice needs two things immediately — what was sent, and
// how to stop it — and a reader worried about privacy needs a third. All must
// be on this page rather than a link away.
func TestPrivacyPageAnswersEveryUrgentQuestion(t *testing.T) {
	page := strings.ToLower(strings.Join(strings.Fields(get(t, "/privacy").Body.String()), " "))

	required := []string{
		// Somebody who found this page from a log entry.
		"abuse@denyfirst.dev",
		"handshake",
		"excluded",
		"scanner.denyfirst.dev",
		"no page is requested",

		// Somebody reading it as a privacy policy.
		"three minutes",
		"no cookies",
		"network provider",
		"rented server",

		// The limits of what the tool claims.
		//
		// This used to require "revocation is not checked", which was the
		// honest sentence for as long as nothing parsed a response. When
		// internal/ocsp landed, this test was the thing holding a false
		// statement on a page whose whole value is that its statements are
		// true — a test can pin a claim in place exactly as well as it can
		// protect one, and nothing distinguishes the two from inside.
		//
		// What is required now is the property that did not change: no
		// authority is contacted. The claim that did change is checked
		// against the code in TestThePagesDoNotDenyACheckThatNowHappens
		// rather than against a sentence.
		"no certificate authority is asked anything",
		"transparency logs are not queried",
		"without warranty",
	}

	for _, phrase := range required {
		if !strings.Contains(page, phrase) {
			t.Errorf("the privacy page does not address %q", phrase)
		}
	}
}

// The jump links are what make one long page usable for a reader who wants
// one section. Every one has to land somewhere.
func TestJumpLinksHaveTargets(t *testing.T) {
	body := get(t, "/privacy").Body.String()

	for _, anchor := range []string{"kept", "logs", "scans", "stopping", "promises"} {
		if !strings.Contains(body, `href="#`+anchor+`"`) {
			t.Errorf("no jump link points to #%s", anchor)
		}
		if !strings.Contains(body, `id="`+anchor+`"`) {
			t.Errorf("nothing on the page has id %q", anchor)
		}
	}
}

// The terms have to put the decision to scan with the person making it.
func TestTermsPlaceResponsibility(t *testing.T) {
	page := strings.ToLower(strings.Join(strings.Fields(get(t, "/terms").Body.String()), " "))

	for _, required := range []string{
		"permission",
		"without warranty",
		"agpl",
		"run your own",
	} {
		if !strings.Contains(page, required) {
			t.Errorf("the terms do not address %q", required)
		}
	}
}
