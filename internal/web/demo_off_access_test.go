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
