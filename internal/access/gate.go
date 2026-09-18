package access

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CookieName is the one cookie an installation sets, and only on sign-in.
const CookieName = "porch_session"

// SessionLife is how long a sign-in lasts, whatever is done with it. Twelve
// hours is a working day with room; the next one starts with the password.
const SessionLife = 12 * time.Hour

// maxSessions bounds the table. The oldest goes first, so a flood of
// sign-ins costs the flooder their own sessions and nobody else's for long.
const maxSessions = 32

// Sign-in attempts per client address: a burst, then one per interval. A
// derivation costs a few hundred milliseconds of one core, which is what
// makes guessing slow; this is what makes it slow for one address, and the
// single derivation slot is what keeps many addresses from taking the CPU.
const (
	attemptBurst    = 5
	attemptInterval = time.Minute
	maxTracked      = 1024

	// attemptsForgotten is how long after its last attempt an address is
	// dropped: by then its allowance has refilled, so forgetting it changes
	// nothing. The privacy page says this number. The map used to keep an
	// address until a thousand others arrived (audit 2026-09-18, D08), which
	// on a quiet installation is for as long as it runs.
	attemptsForgotten = attemptBurst * attemptInterval
)

// Gate decides which requests reach the installation, and holds its data key
// once somebody has signed in.
type Gate struct {
	path   string
	public map[string]bool
	now    func() time.Time

	mu       sync.Mutex
	key      []byte
	sessions map[[32]byte]time.Time
	attempts map[string]*bucket

	// sweeper drops idle addresses on time while there are any, even when
	// nobody else arrives to prompt it. Nil while the map is empty.
	sweeper *time.Timer

	// derive admits one password derivation at a time.
	derive chan struct{}
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewGate guards an installation whose access file is at path. public names
// the paths anybody may reach: the sign-in page and what it needs to draw.
func NewGate(path string, public []string) *Gate {
	g := &Gate{
		path:     path,
		public:   map[string]bool{},
		now:      time.Now,
		sessions: map[[32]byte]time.Time{},
		attempts: map[string]*bucket{},
		derive:   make(chan struct{}, 1),
	}
	for _, p := range public {
		g.public[p] = true
	}
	return g
}

// Key returns the data key, or nil until the first sign-in since the program
// started. Callers encrypting with it must treat nil as "nothing may be kept
// yet", never as "keep it in the clear".
func (g *Gate) Key() []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.key == nil {
		return nil
	}
	return append([]byte(nil), g.key...)
}

// SignedIn reports whether a request carries a live session.
func (g *Gate) SignedIn(r *http.Request) bool {
	if !privateTransport(r) {
		return false
	}
	c, err := r.Cookie(CookieName)
	if err != nil {
		return false
	}
	return g.valid(c.Value)
}

// Wrap puts the gate in front of next. The session endpoints are answered
// here; a public path passes; anything else needs a live session. A page is
// sent to the sign-in page, and anything else is told to sign in.
func (g *Gate) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/session":
			g.serveSession(w, r)
			return
		case "/api/v1/password":
			g.servePassword(w, r)
			return
		}
		if g.public[r.URL.Path] || g.SignedIn(r) {
			next.ServeHTTP(w, r)
			return
		}
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && !strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		refuse(w, http.StatusUnauthorized, "sign_in", "Sign in to use this installation.")
	})
}

type passwordRequest struct {
	Password string `json:"password"`
	Next     string `json:"next,omitempty"`
}

// serveSession signs in on POST and out on DELETE.
func (g *Gate) serveSession(w http.ResponseWriter, r *http.Request) {
	secure(w)
	switch r.Method {
	case http.MethodPost:
	case http.MethodDelete:
		if !fromThisPage(r) {
			refuse(w, http.StatusForbidden, "cross_site", "Sign out from this installation's own pages.")
			return
		}
		if c, err := r.Cookie(CookieName); err == nil {
			g.forget(c.Value)
		}
		http.SetCookie(w, expired())
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		w.Header().Set("Allow", "POST, DELETE")
		refuse(w, http.StatusMethodNotAllowed, "method", "Sign in with POST, and out with DELETE.")
		return
	}

	body, ok := readPassword(w, r)
	if !ok {
		return
	}
	if !g.allow(clientKey(r)) {
		w.Header().Set("Retry-After", strconv.Itoa(int(attemptInterval/time.Second)))
		refuse(w, http.StatusTooManyRequests, "rate_limited",
			"Too many attempts from this address. Wait a minute and try again.")
		return
	}
	token, err := g.signIn(body.Password)
	switch {
	case err == nil:
	case errors.Is(err, errBusy):
		w.Header().Set("Retry-After", "2")
		refuse(w, http.StatusServiceUnavailable, "busy", "Another sign-in is being checked. Try again in a moment.")
		return
	case errors.Is(err, ErrWrongPassword):
		refuse(w, http.StatusUnauthorized, "wrong_password", "That is not this installation's password.")
		return
	default:
		// The file could not be read. Its path and the system's words stay in
		// this process; the person at the page is told what to do.
		refuse(w, http.StatusInternalServerError, "unavailable",
			"The password could not be checked. The operator should look at the installation's log.")
		return
	}
	// Secure always, not only over TLS. A browser treats http://localhost as a
	// secure origin, so the SSH tunnel the guide uses works; what stops working
	// is signing in over plain HTTP to any other address, which is a password
	// sent in the clear and exactly what should not work.
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(SessionLife / time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// servePassword changes the password, for somebody already signed in who
// also knows the current one. Every other session ends, so a password
// changed because it leaked stops working everywhere it leaked to.
func (g *Gate) servePassword(w http.ResponseWriter, r *http.Request) {
	secure(w)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		refuse(w, http.StatusMethodNotAllowed, "method", "Change the password with POST.")
		return
	}
	c, err := r.Cookie(CookieName)
	if err != nil || !g.valid(c.Value) {
		refuse(w, http.StatusUnauthorized, "sign_in", "Sign in to use this installation.")
		return
	}
	body, ok := readPassword(w, r)
	if !ok {
		return
	}
	if !g.allow(clientKey(r)) {
		w.Header().Set("Retry-After", strconv.Itoa(int(attemptInterval/time.Second)))
		refuse(w, http.StatusTooManyRequests, "rate_limited",
			"Too many attempts from this address. Wait a minute and try again.")
		return
	}
	select {
	case g.derive <- struct{}{}:
		defer func() { <-g.derive }()
	case <-time.After(3 * time.Second):
		w.Header().Set("Retry-After", "2")
		refuse(w, http.StatusServiceUnavailable, "busy", "Another sign-in is being checked. Try again in a moment.")
		return
	}
	switch err := Change(g.path, body.Password, body.Next); {
	case err == nil:
	case errors.Is(err, ErrWrongPassword):
		refuse(w, http.StatusUnauthorized, "wrong_password", "The current password is not right.")
		return
	case errors.Is(err, ErrWeakPassword):
		refuse(w, http.StatusBadRequest, "weak_password",
			"A new password has to be at least "+strconv.Itoa(MinPassword)+" characters.")
		return
	default:
		refuse(w, http.StatusInternalServerError, "unavailable",
			"The new password could not be saved. The operator should look at the installation's log.")
		return
	}
	g.keepOnly(c.Value)
	w.WriteHeader(http.StatusNoContent)
}

var errBusy = errors.New("another derivation is running")

// signIn checks a password and opens a session for it.
func (g *Gate) signIn(password string) (string, error) {
	select {
	case g.derive <- struct{}{}:
		defer func() { <-g.derive }()
	case <-time.After(3 * time.Second):
		return "", errBusy
	}
	key, err := Unlock(g.path, password)
	if err != nil {
		return "", err
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.key == nil {
		g.key = key
	}
	now := g.now()
	for id, until := range g.sessions {
		if !now.Before(until) {
			delete(g.sessions, id)
		}
	}
	for len(g.sessions) >= maxSessions {
		var oldest [32]byte
		var first time.Time
		for id, until := range g.sessions {
			if first.IsZero() || until.Before(first) {
				oldest, first = id, until
			}
		}
		delete(g.sessions, oldest)
	}
	g.sessions[sha256.Sum256([]byte(token))] = now.Add(SessionLife)
	return token, nil
}

// valid reports whether token names a live session. Sessions are held by
// the hash of their token, so the table is no list of working cookies.
func (g *Gate) valid(token string) bool {
	if token == "" || len(token) > 128 {
		return false
	}
	id := sha256.Sum256([]byte(token))
	g.mu.Lock()
	defer g.mu.Unlock()
	until, ok := g.sessions[id]
	if !ok {
		return false
	}
	if !g.now().Before(until) {
		delete(g.sessions, id)
		return false
	}
	return true
}

func (g *Gate) forget(token string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.sessions, sha256.Sum256([]byte(token)))
}

// keepOnly ends every session but token's.
func (g *Gate) keepOnly(token string) {
	keep := sha256.Sum256([]byte(token))
	g.mu.Lock()
	defer g.mu.Unlock()
	for id := range g.sessions {
		if subtle.ConstantTimeCompare(id[:], keep[:]) != 1 {
			delete(g.sessions, id)
		}
	}
}

// allow spends one attempt for key.
func (g *Gate) allow(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	b, ok := g.attempts[key]
	if !ok {
		if len(g.attempts) >= maxTracked {
			// Forgetting everyone is the cheap bound. It hands a guesser
			// who can spread over a thousand addresses a fresh burst, and
			// the single derivation slot still holds them to one guess at
			// a time.
			g.attempts = map[string]*bucket{}
		}
		b = &bucket{tokens: attemptBurst, last: now}
		g.attempts[key] = b
	}
	b.tokens = min(attemptBurst, b.tokens+now.Sub(b.last).Seconds()/attemptInterval.Seconds())
	b.last = now
	g.sweepLocked()
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops every address idle for attemptsForgotten. The timer runs it.
func (g *Gate) sweep() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweeper = nil
	g.sweepLocked()
}

// sweepLocked drops idle addresses, and keeps a timer armed for as long as
// any are left, so the last of them goes on time too.
func (g *Gate) sweepLocked() {
	now := g.now()
	for key, b := range g.attempts {
		if now.Sub(b.last) >= attemptsForgotten {
			delete(g.attempts, key)
		}
	}
	if len(g.attempts) > 0 && g.sweeper == nil {
		g.sweeper = time.AfterFunc(attemptInterval, g.sweep)
	}
}

// clientKey is the address a request came from, held in memory to count
// attempts and never written down.
//
// The connection's address and never a forwarded header, which is the rule
// porchd applies to scans too: it trusts no proxy, and has no setting that
// would make it (see cmd/porchd). Behind a proxy every sign-in then shares
// one allowance, which is the side to err on — a header any client can write
// would hand each guess a fresh one.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// fromThisPage refuses a request a page on another site made the browser
// send. Sec-Fetch-Site cannot be set by script; a client that sends none is
// not a browser another site can steer.
func fromThisPage(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "none", "same-origin":
		return true
	}
	return false
}

// readPassword reads the one JSON body the session endpoints take. JSON only,
// so a form on another site cannot post it without a preflight, and from this
// installation's pages only.
func readPassword(w http.ResponseWriter, r *http.Request) (passwordRequest, bool) {
	if !privateTransport(r) {
		refuse(w, http.StatusForbidden, "insecure_transport",
			"This installation takes a password only over HTTPS, or through an SSH tunnel to localhost. "+
				"Sent here it would cross the network in the clear.")
		return passwordRequest{}, false
	}
	if !fromThisPage(r) {
		refuse(w, http.StatusForbidden, "cross_site", "Sign in from this installation's own page.")
		return passwordRequest{}, false
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		refuse(w, http.StatusUnsupportedMediaType, "unsupported_media", "Send application/json.")
		return passwordRequest{}, false
	}
	var body passwordRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		refuse(w, http.StatusBadRequest, "invalid_body", "Send a password.")
		return passwordRequest{}, false
	}
	return body, true
}

func expired() *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

// secure sets the headers the API sets: these answers are JSON and need no
// resource of any kind.
func secure(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
}

func refuse(w http.ResponseWriter, status int, code, message string) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	// The shape the API answers with, so a page reads either the same way.
	_ = json.NewEncoder(w).Encode(map[string]map[string]string{"error": {"code": code, "message": message}})
}

// privateTransport reports whether a password or a session may travel on this
// request: over TLS, or addressed to this machine's own name, which is what a
// browser at the near end of an SSH tunnel sends (audit 2026-09-18, D06).
//
// Plain HTTP to any other name is refused, both to sign in and to use a
// session. A browser already keeps the Secure cookie off such a request; this
// makes the server refuse the password before it has been read and refuse a
// cookie somebody sets by hand.
//
// The Host header is the client's to write, and that is acceptable here
// because this is not a check against the client: a browser sends the name the
// person typed, so the person who would send their password in the clear is
// the one refused. Somebody who forges "localhost" is sending their own guess
// over their own plaintext connection. No proxy header is read, because this
// service runs with no proxy in front of it; one that did would terminate TLS
// before this and need a rule of its own.
func privateTransport(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
