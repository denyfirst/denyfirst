package challenge

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/safedial"
	"github.com/denyfirst/denyfirst/internal/verify"
)

// localFetcher reaches a test server, which the default dialler refuses.
//
// The certificate is still verified — that is the property under test as much
// as anything else here — so the pool the test server signed with is handed to
// the fetcher the way an internal estate hands it its own authority.
func localFetcher(t *testing.T, srv *httptest.Server) *Fetcher {
	t.Helper()

	addr := strings.TrimPrefix(srv.URL, "https://")
	return &Fetcher{
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		Roots:   srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		Timeout: 5 * time.Second,
	}
}

// serverFor answers one path and records what was asked for.
func serverFor(t *testing.T, path, body string, status int) (*httptest.Server, *[]string) {
	t.Helper()

	var asked []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		if r.URL.Path != path {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	return srv, &asked
}

// The file is read from the one path, and from no other.
//
// This is the only path this project ever constructs, and the reason it is not
// a contradiction of N7 is that it is not a check: it is one request for a file
// an operator deliberately placed. A second path would make it one.
func TestOnlyTheChallengePathIsRequested(t *testing.T) {
	srv, asked := serverFor(t, verify.Path, "a-token", http.StatusOK)

	f := localFetcher(t, srv)

	body, err := f.FetchChallenge(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("FetchChallenge: %v", err)
	}
	if body != "a-token" {
		t.Errorf("got %q, want the token", body)
	}

	if len(*asked) != 1 || (*asked)[0] != verify.Path {
		t.Errorf("the fetcher requested %v; it asks for one path and nothing else", *asked)
	}
}

// A host that serves no such file has published nothing, which is a fact about
// the domain rather than a failure.
func TestAMissingFileIsNoChallengeRatherThanAnError(t *testing.T) {
	srv, _ := serverFor(t, "/somewhere-else", "", http.StatusOK)

	f := localFetcher(t, srv)

	_, err := f.FetchChallenge(context.Background(), "example.com")
	if !errors.Is(err, verify.ErrNoChallenge) {
		t.Errorf("FetchChallenge = %v, want ErrNoChallenge", err)
	}
}

// An empty file is nothing published either.
func TestAnEmptyFileIsNoChallenge(t *testing.T) {
	srv, _ := serverFor(t, verify.Path, "", http.StatusOK)

	f := localFetcher(t, srv)

	if _, err := f.FetchChallenge(context.Background(), "example.com"); !errors.Is(err, verify.ErrNoChallenge) {
		t.Errorf("FetchChallenge = %v, want ErrNoChallenge", err)
	}
}

// Nothing is followed.
//
// A redirect is the host choosing where this deployment looks next. Following
// one would let a host prove control of itself by pointing at somewhere the
// file already is — including somewhere it does not control at all.
func TestARedirectIsNotFollowed(t *testing.T) {
	var reached bool
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		_, _ = w.Write([]byte("a-token"))
	}))
	t.Cleanup(elsewhere.Close)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+verify.Path, http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	f := localFetcher(t, srv)

	_, err := f.FetchChallenge(context.Background(), "example.com")
	if !errors.Is(err, verify.ErrNoChallenge) {
		t.Errorf("FetchChallenge = %v; a redirect answered instead of being refused", err)
	}
	if reached {
		t.Error("the fetcher followed a redirect, so a host can prove itself by pointing elsewhere")
	}
}

// The error text names nothing about this machine (I6).
//
// It reaches a caller that may put it in front of somebody, and Go writes
// network failures naming the resolver's address.
func TestAFetchFailureNamesNoInfrastructure(t *testing.T) {
	f := &Fetcher{
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial tcp 192.0.2.7:443: lookup example.test on 10.0.0.1:53: no such host")
		},
		Timeout: time.Second,
	}

	_, err := f.FetchChallenge(context.Background(), "example.com")
	if err == nil {
		t.Fatal("a dial that failed produced no error")
	}
	for _, leak := range []string{"10.0.0.1", "192.0.2.7", "no such host"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the error carries %q: %v", leak, err)
		}
	}
}

// The default dialler refuses what a scan would refuse.
//
// A fetch is a connection this deployment opens to a host somebody named, and
// it happens before the boundary has decided anything — the shape of an SSRF
// into the scanner, which is one of the things verification exists to survive.
//
// Asked of the dialler rather than through FetchChallenge, because the error a
// caller sees is the same phrase whether a destination was refused by policy or
// had nothing listening. That is right for a caller and blind for a test: a
// sabotage that swapped safedial for a plain dialler passed a test written the
// other way, because nothing answers on loopback port 443 either.
func TestTheDefaultDiallerRefusesPrivateAddresses(t *testing.T) {
	dial := (&Fetcher{}).dialFunc()

	for _, address := range []string{
		"127.0.0.1:443",
		"10.0.0.1:443",
		"169.254.169.254:443",
		"[::1]:443",
	} {
		conn, err := dial(context.Background(), "tcp", address)
		if conn != nil {
			_ = conn.Close()
		}
		if !errors.Is(err, safedial.ErrBlocked) {
			t.Errorf("dialling %s gave %v, want the policy refusal; the fetcher is not dialling "+
				"through safedial and is reachable by an SSRF into this service", address, err)
		}
	}

	// And the port list holds: a challenge is fetched over HTTPS or not at all.
	if _, err := dial(context.Background(), "tcp", "93.184.216.34:8443"); !errors.Is(err, safedial.ErrBlocked) {
		t.Errorf("dialling a port other than %s gave %v, want the policy refusal", securePort, err)
	}
}

// A certificate this program would not trust proves nothing.
//
// Whoever can answer for a name can serve any file, so the file is only worth
// reading over a connection whose other end was verified. A fetcher that
// stopped verifying would still pass every test above, because they all supply
// the authority that signed the test server — so this one deliberately does
// not.
func TestAChallengeIsNotReadOverAnUntrustedConnection(t *testing.T) {
	srv, _ := serverFor(t, verify.Path, "a-token", http.StatusOK)

	addr := strings.TrimPrefix(srv.URL, "https://")
	f := &Fetcher{
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		// An empty pool: the test server's own authority is deliberately not
		// in it, which is what an attacker answering for a name looks like.
		Roots:   x509.NewCertPool(),
		Timeout: 5 * time.Second,
	}

	_, err := f.FetchChallenge(context.Background(), "example.com")
	if err == nil {
		t.Fatal("a challenge was read over a connection this program does not trust")
	}
	if errors.Is(err, verify.ErrNoChallenge) {
		t.Error("an untrusted connection was reported as a host that published nothing, which sends " +
			"an operator to publish a file they have already published")
	}
}
