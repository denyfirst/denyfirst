package access

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testPassword = "correct horse battery"

// behind is an installation's handler behind a gate: it answers every path
// it is asked for, so what reaches it is whatever the gate let through.
func behind(t *testing.T) (*Gate, http.Handler) {
	t.Helper()
	g := NewGate(accessFile(t, testPassword), []string{"/login", "/style.css"})
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("inside"))
	})
	return g, g.Wrap(inner)
}

func do(h http.Handler, method, path, body string, cookie *http.Cookie, header map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.10:5000"
	// The browser at the near end of an SSH tunnel, as the guide sets it up.
	r.Host = "localhost:8080"
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		r.Header.Set(k, v)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func signIn(t *testing.T, h http.Handler, password string) (*http.Cookie, *httptest.ResponseRecorder) {
	t.Helper()
	w := do(h, http.MethodPost, "/api/v1/session", `{"password":"`+password+`"}`, nil, nil)
	for _, c := range w.Result().Cookies() {
		if c.Name == CookieName {
			return c, w
		}
	}
	return nil, w
}

// Nothing but the sign-in page and what it draws with is reachable without a
// session: a page is sent to sign in, and anything else is refused.
func TestNothingIsReachableWithoutSigningIn(t *testing.T) {
	_, h := behind(t)

	for _, path := range []string{"/", "/domains", "/history", "/docs", "/privacy"} {
		w := do(h, http.MethodGet, path, "", nil, nil)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
			t.Errorf("GET %s without a session: %d to %q, want 303 to /login", path, w.Code, w.Header().Get("Location"))
		}
		if strings.Contains(w.Body.String(), "inside") {
			t.Errorf("GET %s without a session reached the installation", path)
		}
	}
	for _, rq := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/tls/scan"},
		{http.MethodPost, "/api/v1/verify"},
		{http.MethodGet, "/api/v1/stats"},
		{http.MethodPost, "/"},
	} {
		w := do(h, rq.method, rq.path, `{"target":"example.com"}`, nil, nil)
		if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "inside") {
			t.Errorf("%s %s without a session: %d, want 401", rq.method, rq.path, w.Code)
		}
	}
	for _, path := range []string{"/login", "/style.css"} {
		if w := do(h, http.MethodGet, path, "", nil, nil); w.Body.String() != "inside" {
			t.Errorf("GET %s, which the sign-in page needs, was not let through", path)
		}
	}
}

// The right password opens a session in a cookie a script cannot read and
// another site cannot send; the wrong one does not.
func TestTheRightPasswordOpensASession(t *testing.T) {
	g, h := behind(t)

	if g.Key() != nil {
		t.Fatal("the data key is held before anyone has signed in")
	}
	if c, w := signIn(t, h, "not the password"); c != nil || w.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong password: %d, cookie %v", w.Code, c)
	}
	if g.Key() != nil {
		t.Error("a wrong password opened the data key")
	}

	c, w := signIn(t, h, testPassword)
	if c == nil || w.Code != http.StatusNoContent {
		t.Fatalf("the right password: %d, no session", w.Code)
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Errorf("the session cookie is readable by script or sent from other sites: %+v", c)
	}
	if c.MaxAge <= 0 || time.Duration(c.MaxAge)*time.Second > SessionLife {
		t.Errorf("the session cookie lasts %ds, want at most %s", c.MaxAge, SessionLife)
	}
	if len(g.Key()) != 32 {
		t.Error("signing in did not make the data key available")
	}
	if w := do(h, http.MethodGet, "/history", "", c, nil); w.Body.String() != "inside" {
		t.Errorf("a signed-in request did not reach the installation: %d", w.Code)
	}
	if w := do(h, http.MethodGet, "/history", "", &http.Cookie{Name: CookieName, Value: c.Value + "x"}, nil); w.Code != http.StatusSeeOther {
		t.Error("an altered session token was accepted")
	}
}

// A session ends when its owner signs out, and after SessionLife whatever
// they do.
func TestASessionEnds(t *testing.T) {
	g, h := behind(t)
	c, _ := signIn(t, h, testPassword)

	w := do(h, http.MethodDelete, "/api/v1/session", "", c, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("signing out: %d", w.Code)
	}
	if do(h, http.MethodGet, "/", "", c, nil).Code != http.StatusSeeOther {
		t.Error("a session still works after signing out")
	}

	c, _ = signIn(t, h, testPassword)
	later := time.Now().Add(SessionLife + time.Minute)
	g.now = func() time.Time { return later }
	if do(h, http.MethodGet, "/", "", c, nil).Code != http.StatusSeeOther {
		t.Error("a session still works after SessionLife")
	}
}

// Changing the password needs the current one, and ends every other session:
// a password changed because it leaked stops working wherever it leaked to.
func TestChangingThePasswordEndsOtherSessions(t *testing.T) {
	_, h := behind(t)
	mine, _ := signIn(t, h, testPassword)
	theirs, _ := signIn(t, h, testPassword)

	if w := do(h, http.MethodPost, "/api/v1/password", `{"password":"wrong","next":"a new long password"}`, mine, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("a change with the wrong current password: %d", w.Code)
	}
	if w := do(h, http.MethodPost, "/api/v1/password", `{"password":"`+testPassword+`","next":"short"}`, mine, nil); w.Code != http.StatusBadRequest {
		t.Errorf("a change to a short password: %d", w.Code)
	}
	if w := do(h, http.MethodPost, "/api/v1/password", `{"password":"`+testPassword+`","next":"a new long password"}`, nil, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("a change without a session: %d", w.Code)
	}
	if w := do(h, http.MethodPost, "/api/v1/password", `{"password":"`+testPassword+`","next":"a new long password"}`, mine, nil); w.Code != http.StatusNoContent {
		t.Fatalf("a change with the right password: %d %s", w.Code, w.Body.String())
	}

	if do(h, http.MethodGet, "/", "", mine, nil).Body.String() != "inside" {
		t.Error("the session that changed the password was ended")
	}
	if do(h, http.MethodGet, "/", "", theirs, nil).Code != http.StatusSeeOther {
		t.Error("another session survived a password change")
	}
	if c, _ := signIn(t, h, testPassword); c != nil {
		t.Error("the old password still signs in")
	}
}

// Guessing is slow for one address: a burst, then refused.
func TestGuessingIsLimited(t *testing.T) {
	_, h := behind(t)
	refused := false
	for range attemptBurst + 2 {
		if _, w := signIn(t, h, "a wrong guess"); w.Code == http.StatusTooManyRequests {
			refused = true
			if w.Header().Get("Retry-After") == "" {
				t.Error("a refused attempt does not say when to try again")
			}
		}
	}
	if !refused {
		t.Errorf("%d wrong guesses from one address were all answered", attemptBurst+2)
	}
}

// Another site cannot sign a visitor in or out, or change their password: a
// browser says where a request came from, and a form cannot send JSON.
func TestAnotherSiteCannotUseTheSessionEndpoints(t *testing.T) {
	_, h := behind(t)
	c, _ := signIn(t, h, testPassword)
	cross := map[string]string{"Sec-Fetch-Site": "cross-site"}

	if w := do(h, http.MethodPost, "/api/v1/session", `{"password":"`+testPassword+`"}`, nil, cross); w.Code != http.StatusForbidden {
		t.Errorf("a cross-site sign-in: %d", w.Code)
	}
	if w := do(h, http.MethodDelete, "/api/v1/session", "", c, cross); w.Code != http.StatusForbidden {
		t.Errorf("a cross-site sign-out: %d", w.Code)
	}
	if w := do(h, http.MethodPost, "/api/v1/password", `{"password":"`+testPassword+`","next":"a new long password"}`, c, cross); w.Code != http.StatusForbidden {
		t.Errorf("a cross-site password change: %d", w.Code)
	}

	r := httptest.NewRequest(http.MethodPost, "/api/v1/session", strings.NewReader("password="+testPassword))
	r.Host = "localhost:8080"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("a form post to sign in: %d, want 415", w.Code)
	}
}

// The session table does not grow without bound.
func TestTheSessionTableIsBounded(t *testing.T) {
	g, _ := behind(t)
	for range maxSessions + 5 {
		if _, err := g.signIn(testPassword); err != nil {
			t.Fatal(err)
		}
	}
	g.mu.Lock()
	n := len(g.sessions)
	g.mu.Unlock()
	if n > maxSessions {
		t.Errorf("%d sessions held, bound is %d", n, maxSessions)
	}
}

// A public path is that path, not everything that begins like it.
func TestAPublicPathIsExact(t *testing.T) {
	_, h := behind(t)
	for _, path := range []string{"/login/../history", "/loginx", "/login/history", "/style.css/x", "/style.css.bak"} {
		if w := do(h, http.MethodGet, path, "", nil, nil); w.Body.String() == "inside" {
			t.Errorf("GET %s reached the installation without a session", path)
		}
	}
}

// A password change needs a live session, not only a cookie by that name.
func TestAPasswordChangeNeedsALiveSession(t *testing.T) {
	_, h := behind(t)
	bogus := &http.Cookie{Name: CookieName, Value: "not-a-session"}
	w := do(h, http.MethodPost, "/api/v1/password", `{"password":"`+testPassword+`","next":"a new long password"}`, bogus, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("a change with a made-up session: %d, want 401", w.Code)
	}
	if c, _ := signIn(t, h, testPassword); c == nil {
		t.Error("a made-up session changed the password")
	}
}

// A browser that says the request came from another site, or from another
// name on this one, is refused.
func TestOnlyThisPageMaySignIn(t *testing.T) {
	_, h := behind(t)
	for _, site := range []string{"cross-site", "same-site"} {
		w := do(h, http.MethodPost, "/api/v1/session", `{"password":"`+testPassword+`"}`, nil, map[string]string{"Sec-Fetch-Site": site})
		if w.Code != http.StatusForbidden {
			t.Errorf("a sign-in sent %s: %d, want 403", site, w.Code)
		}
	}
}

// A password never crosses the network in the clear: plain HTTP to a public
// name is refused before the password is read, and a session set by hand on
// such a request does not count. TLS works, and so does localhost, which is
// what an SSH tunnel looks like to the browser.
func TestAPasswordIsTakenOnlyOverAPrivateTransport(t *testing.T) {
	_, h := behind(t)
	send := func(host string, tlsOn bool, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = "192.0.2.10:5000"
		r.Host = host
		if tlsOn {
			r.TLS = &tls.ConnectionState{}
		}
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := send("scan.example.com", false, http.MethodPost, "/api/v1/session", `{"password":"`+testPassword+`"}`, nil); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "insecure_transport") {
		t.Errorf("a sign-in over plain HTTP to a public name: %d %s", w.Code, w.Body.String())
	}
	for _, host := range []string{"localhost:8080", "127.0.0.1:8080", "[::1]:8080", "LOCALHOST"} {
		if w := send(host, false, http.MethodPost, "/api/v1/session", `{"password":"`+testPassword+`"}`, nil); w.Code != http.StatusNoContent {
			t.Errorf("a sign-in over plain HTTP to %s: %d", host, w.Code)
		}
	}
	w := send("scan.example.com", true, http.MethodPost, "/api/v1/session", `{"password":"`+testPassword+`"}`, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("a sign-in over TLS: %d", w.Code)
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == CookieName {
			session = c
		}
	}
	if session == nil {
		t.Fatal("no session over TLS")
	}
	if w := send("scan.example.com", true, http.MethodGet, "/history", "", session); w.Body.String() != "inside" {
		t.Error("a session over TLS did not reach the installation")
	}
	if w := send("scan.example.com", false, http.MethodGet, "/history", "", session); w.Body.String() == "inside" {
		t.Error("a session sent by hand over plain HTTP to a public name reached the installation")
	}
	if w := send("scan.example.com", false, http.MethodPost, "/api/v1/password", `{"password":"`+testPassword+`","next":"a new long password"}`, session); w.Code == http.StatusNoContent {
		t.Error("a password change over plain HTTP to a public name went through")
	}
}

// An address that tried to sign in is forgotten once its allowance has
// refilled, on time even when nobody else arrives (audit 2026-09-18, D08). It
// used to be kept until a thousand others came, which on a quiet installation
// is for as long as it runs, while the privacy page promised minutes.
func TestASignInAddressIsForgottenOnceItsAllowanceRefills(t *testing.T) {
	g, _ := behind(t)
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }
	t.Cleanup(func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.sweeper != nil {
			g.sweeper.Stop()
		}
	})
	held := func(key string) bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		_, ok := g.attempts[key]
		return ok
	}

	for range attemptBurst {
		g.allow("192.0.2.1")
	}
	if g.allow("192.0.2.1") {
		t.Fatal("the allowance is not spent after a burst")
	}
	g.mu.Lock()
	armed := g.sweeper != nil
	g.mu.Unlock()
	if !armed {
		t.Error("an address is held and nothing is set to forget it")
	}

	// Before it has refilled it is kept, so waiting does not buy a guesser
	// a fresh burst sooner than refilling would.
	now = now.Add(attemptBurst*attemptInterval - time.Second)
	g.sweep()
	if !held("192.0.2.1") {
		t.Error("an address was forgotten before its allowance refilled")
	}

	// Then the timer's sweep drops it, with nobody else arriving.
	now = now.Add(time.Second)
	g.sweep()
	if held("192.0.2.1") {
		t.Error("an address is still held once its allowance has refilled")
	}
	g.mu.Lock()
	armed = g.sweeper != nil
	g.mu.Unlock()
	if armed {
		t.Error("a timer is still set with nothing to forget")
	}

	// And a later sign-in from elsewhere sweeps too: a day later, only the
	// newcomer is held.
	g.allow("192.0.2.1")
	now = now.Add(24 * time.Hour)
	g.allow("198.51.100.7")
	if held("192.0.2.1") || !held("198.51.100.7") {
		t.Error("a day-old address outlived a later sign-in")
	}

	if attemptsForgotten > 6*time.Minute {
		t.Errorf("addresses are kept %v, longer than the privacy page says", attemptsForgotten)
	}
}
