//go:build !demo

package web

import (
	"sort"
	"strings"
	"testing"
)

// guardedAs renders the whole site as an installation behind a password,
// reads one page, and puts every rendered page back as it was.
func guardedAs(t *testing.T, path string) string {
	t.Helper()
	before := map[string][]byte{}
	for p, body := range rendered {
		before[p] = body
	}
	t.Cleanup(func() {
		for p := range rendered {
			if _, ok := before[p]; !ok {
				delete(rendered, p)
			}
		}
		for p, body := range before {
			rendered[p] = body
		}
		signedIn = false
	})
	Configure(true, true, true)
	return get(t, path).Body.String()
}

// Behind a password every page offers a way out, and loads the one script
// that signs out; without one, none does.
func TestEveryPageBehindAPasswordOffersAWayOut(t *testing.T) {
	paths := []string{"/", "/domains", "/history", "/installation", "/docs", "/privacy", "/tls/method"}

	// Without a password first: the guarded rendering is put back only when
	// the test ends.
	for _, path := range paths {
		page := get(t, path).Body.String()
		if strings.Contains(page, `id="sign-out"`) || strings.Contains(page, "/session.js") {
			t.Errorf("%s: with no password, the page offers to sign out", path)
		}
	}
	if w := get(t, "/login"); w.Code == 200 {
		t.Error("/login answers on an installation with no password")
	}

	for _, path := range paths {
		page := guardedAs(t, path)
		if !strings.Contains(page, `<button class="topbar-signout" id="sign-out" type="button">Sign out</button>`) {
			t.Errorf("%s: behind a password, no way to sign out", path)
		}
		if !strings.Contains(page, `<script src="/session.js"></script>`) {
			t.Errorf("%s: behind a password, the script that signs out is not loaded", path)
		}
	}
}

// The sign-in page shows nothing about the installation: no rail, no scope,
// no links into what is behind the gate.
func TestTheSignInPageShowsNothingBehindTheGate(t *testing.T) {
	page := guardedAs(t, "/login")
	for _, never := range []string{`<aside class="rail">`, `class="topbar"`, "shown control of", `href="/domains"`, `href="/history"`, `href="/docs"`, `src="/app.js"`} {
		if strings.Contains(page, never) {
			t.Errorf("the sign-in page carries %q", never)
		}
	}
	for _, want := range []string{`<form class="panel signin-form" id="signin-form"`, `type="password"`, `autocomplete="current-password"`, `<script src="/session.js"></script>`} {
		if !strings.Contains(page, want) {
			t.Errorf("the sign-in page lacks %q", want)
		}
	}
}

// What anybody may reach is the sign-in page and what it draws and runs
// with, and nothing that says anything about the installation.
func TestOnlyTheSignInPageAndWhatItNeedsArePublic(t *testing.T) {
	got := PublicPaths()
	sort.Strings(got)
	want := []string{"/favicon.svg", "/login", "/session.js", "/style.css", "/theme.js"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("public paths are %v, want %v", got, want)
	}
}

// The installation and privacy pages say a password is there, and what it
// means, exactly where it is.
func TestThePagesSayWhetherAPasswordIsInFront(t *testing.T) {
	installation := flatten(guardedAs(t, "/installation"))
	if !strings.Contains(installation, "Behind a password") || !strings.Contains(installation, `id="password-form"`) {
		t.Error("the installation page behind a password does not say so, or offers no way to change it")
	}
	// Two parts, each headed, so the form does not read as more of the facts.
	if !strings.Contains(installation, `<h2 class="work-section">How it runs</h2>`) || !strings.Contains(installation, `<h2 class="work-section">Password</h2>`) {
		t.Error("the installation page does not head its two parts")
	}
	privacy := flatten(guardedAs(t, "/privacy"))
	if !strings.Contains(privacy, "One cookie, set when you sign in") || strings.Contains(privacy, "No cookies") {
		t.Error("the privacy page behind a password does not describe its one cookie")
	}

	open := workspaceWith(t, "/installation", true, false)
	if !strings.Contains(open, "No password.") || strings.Contains(open, `id="password-form"`) {
		t.Error("the installation page with no password does not say so, or offers to change one")
	}
	if privacy := workspaceWith(t, "/privacy", true, false); !strings.Contains(privacy, "No cookies") {
		t.Error("the privacy page with no password no longer says it sets no cookies")
	}
}

// session.js asks the session endpoints and moves the browser. It reads no
// report, stores nothing and builds no markup.
func TestTheSessionScriptDoesOnlyThat(t *testing.T) {
	src, err := assets.ReadFile("assets/session.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	for _, want := range []string{`send("POST", "/api/v1/session"`, `send("DELETE", "/api/v1/session")`, `send("POST", "/api/v1/password"`, `window.location.assign("/login")`} {
		if !strings.Contains(js, want) {
			t.Errorf("session.js no longer contains %q", want)
		}
	}
	for _, never := range []string{"localStorage", "sessionStorage", "document.cookie", "innerHTML", "/api/v1/tls", "/api/v1/web", "/api/v1/mail", "sendBeacon"} {
		if strings.Contains(js, never) {
			t.Errorf("session.js contains %q", never)
		}
	}
}

// Behind a password, History lists what is kept and opens it with the same
// builders New check uses; the list is asked for after the page loads, and
// nothing of it is in the page. Without a password History runs no script.
func TestHistoryBehindAPasswordListsOpensAndDeletes(t *testing.T) {
	open := get(t, "/history").Body.String()
	if strings.Contains(open, `src="/app.js"`) || strings.Contains(open, `id="history-table"`) {
		t.Error("History without a password loads the script or draws the list")
	}

	page := guardedAs(t, "/history")
	for _, want := range []string{`<script src="/app.js"></script>`, `id="history-table"`, `<tbody id="history-rows"></tbody>`, `id="history-report"`} {
		if !strings.Contains(page, want) {
			t.Errorf("History behind a password lacks %q", want)
		}
	}

	src := script(t)
	start := strings.Index(src, "const historyBox = ")
	if start < 0 {
		t.Fatal("app.js has no history module")
	}
	history := src[start:]
	for _, want := range []string{
		`historyRequest("GET", "/api/v1/history")`,
		`historyRequest("GET", "/api/v1/history/" + entry.id)`,
		`historyRequest("DELETE", "/api/v1/history/" + entry.id)`,
		"if (!window.confirm(",
		"view.build(record.report)",
		`window.location.assign("/login")`,
	} {
		if !strings.Contains(history, want) {
			t.Errorf("the history module no longer contains %q", want)
		}
	}
	// Asked before it is deleted: the confirmation comes first.
	if strings.Index(history, "if (!window.confirm(") > strings.Index(history, `historyRequest("DELETE"`) {
		t.Error("a report is deleted before anybody is asked")
	}
	if strings.Contains(history, "innerHTML") {
		t.Error("the history module builds markup from strings")
	}

	privacy := flatten(guardedAs(t, "/privacy"))
	if !strings.Contains(privacy, "encrypted under a key the password seals") {
		t.Error("the privacy page behind a password does not say how results are kept")
	}
}

// The sign-in page's footer is at the foot of the window and centred under
// the card, not floating mid-page flush left.
func TestTheSignInFooterSitsAtTheFootCentred(t *testing.T) {
	css := stylesheet(t)
	for _, want := range []string{
		".workspace-signin .workspace-main { min-height: 100vh; }",
		".workspace-signin .colophon-row { justify-content: center; }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css no longer contains %q", want)
		}
	}
}

// Behind a password, Domains keeps a list and asks DNS about each domain on
// it, one after another, stopping when the budget says wait. Without one there
// is no list.
func TestDomainsBehindAPasswordKeepsAListAndAsksEachOne(t *testing.T) {
	if open := workspaceWith(t, "/domains", true, false); strings.Contains(open, `id="domain-table"`) {
		t.Error("Domains without a password draws a kept list")
	}
	page := guardedAs(t, "/domains")
	for _, want := range []string{`id="domain-table"`, `<tbody id="domain-rows"></tbody>`, `<h2 class="work-section">Your domains</h2>`} {
		if !strings.Contains(page, want) {
			t.Errorf("Domains behind a password lacks %q", want)
		}
	}

	src := script(t)
	start := strings.Index(src, "const domainTable = ")
	if start < 0 {
		t.Fatal("app.js has no domain list module")
	}
	list := src[start:]
	if end := strings.Index(list, "if (domainTable) loadDomains();"); end > 0 {
		list = list[:end]
	}
	for _, want := range []string{
		`domainRequest("GET", "/api/v1/domains")`,
		`domainRequest("DELETE", "/api/v1/domains/" + encodeURIComponent(domain.name))`,
		"const answer = await check(domain.name, VERIFY);",
		"if (!(await proveRow(m.domain, m.proof))) {",
		`return err.status !== 429;`,
		"if (!window.confirm(",
	} {
		if !strings.Contains(list, want) {
			t.Errorf("the domain list module no longer contains %q", want)
		}
	}
	if !strings.Contains(src, `await domainRequest("POST", "/api/v1/domains", { domain: target.value.trim() });`) {
		t.Error("adding a domain behind a password does not keep it on the list")
	}
	// Proven or not is asked, never kept.
	if strings.Contains(list, "localStorage") || strings.Contains(list, "innerHTML") {
		t.Error("the domain list module stores state or builds markup from strings")
	}

	if privacy := flatten(guardedAs(t, "/privacy")); !strings.Contains(privacy, "The domains you add under Domains are kept") {
		t.Error("the privacy page behind a password does not say the domain list is kept")
	}
}
