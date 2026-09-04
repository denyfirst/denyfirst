package webprobe

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/safedial"
)

// local returns a prober that may reach the loopback addresses httptest uses.
//
// The default dialler refuses them, which is the property the production path
// wants and the one thing a test cannot have. Every test below that needs a
// server therefore supplies its own dialler, and the tests that check the
// default dialler is the safe one call client() directly.
func local() *Prober {
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &Prober{Dial: d.DialContext, RequestTimeout: 5 * time.Second}
}

func TestOnlyTheRootIsRequestedUnlessTheServerSaysOtherwise(t *testing.T) {
	var mu sync.Mutex
	var paths []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := local()
	p.chain(context.Background(), p.client(), srv.URL+"/")

	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 || paths[0] != "/" {
		t.Fatalf("requested %v, want exactly [/]", paths)
	}
}

func TestARedirectChainIsRecordedInOrder(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, srv.URL+"/one", http.StatusMovedPermanently)
		case "/one":
			http.Redirect(w, r, srv.URL+"/two", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	p := local()
	c := p.chain(context.Background(), p.client(), srv.URL+"/")

	if len(c.Hops) != 3 {
		t.Fatalf("got %d hops, want 3: %+v", len(c.Hops), c.Hops)
	}
	if c.Truncated {
		t.Error("the chain finished, so it is not truncated")
	}
	want := []int{http.StatusMovedPermanently, http.StatusFound, http.StatusOK}
	for i, status := range want {
		if c.Hops[i].Status != status {
			t.Errorf("hop %d answered %d, want %d", i, c.Hops[i].Status, status)
		}
	}
	if got := c.Final().Status; got != http.StatusOK {
		t.Errorf("the chain ends at %d, want 200", got)
	}
}

func TestTheRedirectLimitStopsTheChainAndSaysSo(t *testing.T) {
	// A server that redirects for ever. Without the limit this test does not
	// finish, which is exactly the failure the limit exists to prevent.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/again", http.StatusFound)
	}))
	defer srv.Close()

	p := local()
	p.MaxRedirects = 3
	c := p.chain(context.Background(), p.client(), srv.URL+"/")

	if !c.Truncated {
		t.Fatal("an endless chain must be reported as truncated")
	}
	if len(c.Hops) != 4 {
		t.Errorf("got %d hops, want 4 (the first request and three redirects)", len(c.Hops))
	}
}

func TestARelativeLocationIsResolvedAgainstTheAddressThatSentIt(t *testing.T) {
	var mu sync.Mutex
	var paths []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/" {
			w.Header().Set("Location", "/somewhere/else")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := local()
	c := p.chain(context.Background(), p.client(), srv.URL+"/")

	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 || paths[1] != "/somewhere/else" {
		t.Fatalf("requested %v, want the relative Location resolved to /somewhere/else", paths)
	}
	if got := c.Hops[1].URL; got != srv.URL+"/somewhere/else" {
		t.Errorf("recorded %q, want %q", got, srv.URL+"/somewhere/else")
	}
}

func TestALocationWithAnotherSchemeIsNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "ftp://example.com/pub")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	p := local()
	c := p.chain(context.Background(), p.client(), srv.URL+"/")

	if len(c.Hops) != 1 {
		t.Fatalf("got %d hops, want 1: an ftp address is not followed", len(c.Hops))
	}
	if !strings.Contains(c.Stopped, "ftp") {
		t.Errorf("Stopped is %q, and it has to name what was refused", c.Stopped)
	}
}

func TestALocationCarryingCredentialsIsStrippedBeforeItIsFollowed(t *testing.T) {
	// Credentials in a redirect target would be sent by this program, into
	// the access log of whatever answered. The hop is followed; the userinfo
	// is not carried.
	next, why := nextURL(
		Hop{Status: http.StatusFound, Headers: map[string][]string{
			"Location": {"https://user:secret@example.com/"},
		}},
		"https://example.com/",
	)
	if why != "" {
		t.Fatalf("the hop should be followed, not refused: %q", why)
	}
	if strings.Contains(next, "secret") || strings.Contains(next, "user") {
		t.Fatalf("credentials survived into %q", next)
	}
	if next != "https://example.com/" {
		t.Errorf("got %q, want https://example.com/", next)
	}
}

func TestAnOverlongLocationIsNotFollowed(t *testing.T) {
	long := "https://example.com/" + strings.Repeat("a", maxLocationLength)
	_, why := nextURL(
		Hop{Status: http.StatusFound, Headers: map[string][]string{"Location": {long}}},
		"https://example.com/",
	)
	if why == "" {
		t.Fatal("an overlong Location must not be followed")
	}
}

func TestOnlyTheGradedHeadersAreRecorded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		w.Header().Set("X-Internal-Backend", "app-07.internal.example")
		w.Header().Set("X-Request-Id", "9f2c1e44")
		w.Header().Set("Server", "something/1.2.3")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := local()
	c := p.chain(context.Background(), p.client(), srv.URL+"/")

	h := c.Final().Headers
	if got := h["Strict-Transport-Security"]; len(got) != 1 || got[0] != "max-age=63072000" {
		t.Fatalf("HSTS not recorded: %v", got)
	}
	for _, unwanted := range []string{"X-Internal-Backend", "X-Request-Id", "Server"} {
		if _, ok := h[unwanted]; ok {
			t.Errorf("%s was recorded; only graded headers may be kept", unwanted)
		}
	}

	// And not merely absent from the map: absent from anything a caller can
	// serialise. A header held somewhere else would reach a report by a route
	// nobody looked at.
	blob, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"app-07.internal.example", "9f2c1e44", "something/1.2.3"} {
		if strings.Contains(string(blob), leak) {
			t.Errorf("%q reached the serialised chain", leak)
		}
	}
}

func TestACookieValueIsNeverRecorded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=SUPERSECRETSESSIONVALUE; Path=/; Secure; HttpOnly; SameSite=Strict")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := local()
	c := p.chain(context.Background(), p.client(), srv.URL+"/")

	blob, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "SUPERSECRETSESSIONVALUE") {
		t.Fatal("a cookie value reached the serialised chain")
	}

	got := c.Final().Cookies
	if len(got) != 1 || got[0].Name != "session" {
		t.Fatalf("cookie not recorded by name: %+v", got)
	}
}

func TestCookieAttributesAreRead(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		want   Cookie
	}{
		{
			name:   "everything set",
			header: "sid=x; Path=/; Secure; HttpOnly; SameSite=Strict",
			want:   Cookie{Name: "sid", Secure: true, HTTPOnly: true, SameSite: "strict"},
		},
		{
			name:   "nothing set",
			header: "sid=x",
			want:   Cookie{Name: "sid"},
		},
		{
			name:   "attributes are case-insensitive on the wire",
			header: "sid=x; secure; HTTPONLY; samesite=None",
			want:   Cookie{Name: "sid", Secure: true, HTTPOnly: true, SameSite: "none"},
		},
		{
			// The prefixes are case-sensitive in the specification and a
			// browser enforces them exactly. Reporting __host- as a host
			// prefix would claim a guarantee no browser is making.
			name:   "the host prefix is case-sensitive",
			header: "__host-sid=x; Secure",
			want:   Cookie{Name: "__host-sid", Secure: true},
		},
		{
			name:   "the host prefix",
			header: "__Host-sid=x; Secure; Path=/",
			want:   Cookie{Name: "__Host-sid", Secure: true, HostPrefix: true},
		},
		{
			name:   "the secure prefix",
			header: "__Secure-sid=x; Secure",
			want:   Cookie{Name: "__Secure-sid", Secure: true, SecurePrefix: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cookies([]string{tc.header})
			if len(got) != 1 {
				t.Fatalf("got %d cookies, want 1", len(got))
			}
			if got[0] != tc.want {
				t.Errorf("got %+v, want %+v", got[0], tc.want)
			}
		})
	}
}

func TestTheBodyIsNotRead(t *testing.T) {
	// The handler sends its headers and then holds the body open. A probe
	// that read the body would wait here; one that closes it unread does not.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=1")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-release
		_, _ = w.Write([]byte("a body nobody asked for"))
	}))
	defer srv.Close()
	defer close(release)

	p := local()
	start := time.Now()
	c := p.chain(context.Background(), p.client(), srv.URL+"/")
	elapsed := time.Since(start)

	if c.Final().Status != http.StatusOK {
		t.Fatalf("no response: %+v", c.Final())
	}
	if elapsed > 2*time.Second {
		t.Errorf("the probe waited %v, so it was reading the body", elapsed)
	}
}

func TestTheUserAgentIdentifiesTheToolAndWhereToReadAboutIt(t *testing.T) {
	var mu sync.Mutex
	var seen string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = r.Header.Get("User-Agent")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := local()
	p.chain(context.Background(), p.client(), srv.URL+"/")

	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(seen, "denyfirst") {
		t.Errorf("the user agent %q does not name the tool", seen)
	}
	if !strings.Contains(seen, "https://") {
		t.Errorf("the user agent %q carries no address a reader can follow", seen)
	}
}

func TestAnEmptyUserAgentIsNotAvailable(t *testing.T) {
	// There is a field for saying who you are and none for saying nothing.
	// A probe that hides is one an administrator cannot make a decision about.
	if (&Prober{UserAgent: ""}).userAgent() != DefaultUserAgent {
		t.Fatal("an empty user agent must fall back to the default, not to nothing")
	}
}

func TestABareHostnameIsRequired(t *testing.T) {
	for _, tc := range []struct{ name, host string }{
		{"empty", ""},
		{"a scheme", "https://example.com"},
		{"a path", "example.com/admin"},
		{"a port", "example.com:8443"},
		{"an address", "192.0.2.1"},
		{"an address in brackets", "[2001:db8::1]"},
		{"a bare name", "localhost"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkHostname(tc.host); !errors.Is(err, ErrNotAHostname) {
				t.Errorf("checkHostname(%q) = %v, want ErrNotAHostname", tc.host, err)
			}
		})
	}

	if err := checkHostname("example.com"); err != nil {
		t.Errorf("checkHostname(example.com) = %v, want nil", err)
	}
}

func TestTheDefaultDiallerRefusesPrivateAddresses(t *testing.T) {
	// The first address in a chain is one the operator chose. Every address
	// after it was chosen by the server that answered, which is why the guard
	// has to sit under the transport rather than in front of the first
	// request.
	tr := (&Prober{}).client().Transport.(*http.Transport)

	for _, addr := range []string{
		"127.0.0.1:443",
		"10.0.0.1:443",
		"169.254.169.254:80",
		"[::1]:443",
	} {
		_, err := tr.DialContext(context.Background(), "tcp", addr)
		if !errors.Is(err, safedial.ErrBlocked) {
			t.Errorf("dialling %s gave %v, want safedial.ErrBlocked", addr, err)
		}
	}
}

func TestTheDefaultDiallerRefusesPortsOtherThanEightyAndFourFourThree(t *testing.T) {
	// A redirect can name any port on any host. Following one to 22 or 6379
	// would be this program being aimed by the server it is measuring.
	//
	// The address is a documentation range and nothing is sent to it: the
	// port is checked before the name is resolved, which is what the second
	// assertion establishes. A test that only checked for ErrBlocked would
	// pass on a documentation address for the wrong reason and go on passing
	// after somebody removed the port list.
	tr := (&Prober{}).client().Transport.(*http.Transport)

	for _, addr := range []string{"203.0.113.1:22", "203.0.113.1:8080", "203.0.113.1:6379"} {
		_, err := tr.DialContext(context.Background(), "tcp", addr)
		if !errors.Is(err, safedial.ErrBlocked) {
			t.Errorf("dialling %s gave %v, want safedial.ErrBlocked", addr, err)
			continue
		}
		if !strings.Contains(err.Error(), "port") {
			t.Errorf("dialling %s was refused for the wrong reason: %v", addr, err)
		}
	}
}

func TestTheClientFollowsNothingByItself(t *testing.T) {
	// Every hop is made by chain(), so that every hop is recorded and counted.
	// A client that followed redirects on its own would take some of them
	// invisibly and none of them would appear in a report.
	c := (&Prober{}).client()
	if c.CheckRedirect == nil {
		t.Fatal("CheckRedirect is nil, so the client follows redirects by itself")
	}
	if err := c.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("CheckRedirect returned %v, want http.ErrUseLastResponse", err)
	}
}

func TestNoProxyStandsBetweenThisAndTheHost(t *testing.T) {
	// http.Transport reads HTTP_PROXY from the environment by default. A
	// proxy would put a third party in the path and the measurement would
	// then describe the proxy.
	tr := (&Prober{}).client().Transport.(*http.Transport)
	if tr.Proxy != nil {
		t.Fatal("a proxy is configured, so the measurement may not be of the host")
	}
}

func TestTheTwoChainsAreIndependent(t *testing.T) {
	// A host whose certificate does not verify still has a plaintext story
	// worth reading, and a host with nothing on port 80 still has a secure
	// one. Neither failure may take the other with it.
	// A dialler that always fails, so this test needs no network and cannot
	// be turned green or red by whatever a resolver on the machine running it
	// decides to answer.
	p := &Prober{
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("nothing is listening")
		},
		RequestTimeout: 2 * time.Second,
		TotalTimeout:   8 * time.Second,
	}

	report, err := p.Probe(context.Background(), "invalid.example")
	if err != nil {
		t.Fatalf("Probe returned %v; a host that does not resolve is a finding, not an error", err)
	}
	if report.Secure == nil || report.Plain == nil {
		t.Fatal("both chains must be present even when both failed")
	}
	if report.Secure.Final().Err == "" {
		t.Error("the secure chain should carry the reason it failed")
	}
	if report.Plain.Final().Err == "" {
		t.Error("the plaintext chain should carry the reason it failed")
	}
	if report.UserAgent == "" {
		t.Error("a report has to say how it was obtained")
	}
}

func TestTheErrorDoesNotRepeatTheAddress(t *testing.T) {
	// url.Error prints the method and the whole address in front of every
	// failure, and the address is already the URL field of the hop it belongs
	// to. Printed as it comes, a report says the same address twice and the
	// reason is at the end of a long line.
	inner := errors.New("connection refused")
	wrapped := &neturl.Error{Op: "Get", URL: "https://example.com:443/", Err: inner}

	if got := unwrapURLError(wrapped); got != "connection refused" {
		t.Errorf("got %q, want %q", got, "connection refused")
	}
	if got := unwrapURLError(inner); got != "connection refused" {
		t.Errorf("an unwrapped error changed: %q", got)
	}
}
