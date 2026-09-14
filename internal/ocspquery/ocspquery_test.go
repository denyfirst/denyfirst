package ocspquery

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/ocsp"
)

// digicert is a real certificate, its real issuer, and the answer DigiCert's
// responder really gave, captured with internal/ocsp's fixtures, with the
// moment it was current.
var digicertAt = time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

func fixture(t *testing.T, host string) (leaf, issuer *x509.Certificate, der []byte) {
	t.Helper()
	read := func(name string) []byte {
		body, err := os.ReadFile(filepath.Join("..", "ocsp", "testdata", host+name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		return body
	}
	var err error
	if leaf, err = x509.ParseCertificate(read(".leaf.der")); err != nil {
		t.Fatal(err)
	}
	if issuer, err = x509.ParseCertificate(read(".issuer.der")); err != nil {
		t.Fatal(err)
	}
	return leaf, issuer, read(".ocsp.der")
}

// answering is a Fetcher whose every connection reaches the handler, and a
// count of the requests it saw.
func answering(t *testing.T, handler http.HandlerFunc) (*Fetcher, *atomic.Int32) {
	t.Helper()
	var seen atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "http://")
	d := &net.Dialer{Timeout: 3 * time.Second}
	return &Fetcher{
		Timeout: 3 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
	}, &seen
}

// withResponders is the leaf with its responder addresses replaced.
func withResponders(leaf *x509.Certificate, servers ...string) *x509.Certificate {
	copied := *leaf
	copied.OCSPServer = servers
	return &copied
}

// The question is the one RFC 6960 describes, posted, and the answer is read
// once it verifies.
func TestARealResponderAnswerIsVerifiedAndRead(t *testing.T) {
	leaf, issuer, der := fixture(t, "www.digicert.com")
	want, _ := ocsp.Request(leaf, issuer)

	f, _ := answering(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.Method != http.MethodPost:
			t.Errorf("asked with %s, want POST", r.Method)
		case r.Header.Get("Content-Type") != "application/ocsp-request":
			t.Errorf("Content-Type %q", r.Header.Get("Content-Type"))
		case !bytes.Equal(body, want):
			t.Error("the body is not the question ocsp.Request writes for this certificate")
		case !strings.HasPrefix(r.Header.Get("User-Agent"), "porch/"):
			t.Errorf("the request does not say what asked: %q", r.Header.Get("User-Agent"))
		}
		_, _ = w.Write(der)
	})

	got := f.Check(context.Background(), leaf, issuer, digicertAt)
	if got.Status != "good" || got.Reason != "" || got.ThisUpdate.IsZero() {
		t.Errorf("got %+v; DigiCert's own answer, verified, says good", got)
	}
}

// An answer that does not verify against this certificate's issuer establishes
// nothing, whatever it says.
func TestAnAnswerThatDoesNotVerifyEstablishesNothing(t *testing.T) {
	leaf, issuer, _ := fixture(t, "sectigo.com")
	_, _, other := fixture(t, "www.digicert.com")

	f, _ := answering(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(other) })
	got := f.Check(context.Background(), leaf, issuer, digicertAt)
	if got.Status != "" || got.Reason == "" {
		t.Errorf("got %+v; an answer about another certificate is not an answer", got)
	}
}

// A redirect is not followed.
func TestARedirectFromAResponderIsNotFollowed(t *testing.T) {
	leaf, issuer, der := fixture(t, "www.digicert.com")
	var followed atomic.Bool
	f, _ := answering(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed.Store(true)
			_, _ = w.Write(der)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})

	got := f.Check(context.Background(), leaf, issuer, digicertAt)
	if followed.Load() || got.Status != "" {
		t.Errorf("followed=%v, got %+v; a redirect is an address the scanned party did not even choose", followed.Load(), got)
	}
}

// An answer over the cap is refused, not cut and read.
func TestAnOversizedAnswerIsRefused(t *testing.T) {
	leaf, issuer, _ := fixture(t, "www.digicert.com")
	f, _ := answering(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxResponse+1))
	})
	got := f.Check(context.Background(), leaf, issuer, digicertAt)
	if got.Status != "" || !strings.Contains(got.Reason, "larger") {
		t.Errorf("got %+v", got)
	}
}

// Only http and https are asked, at most two responders, and nothing is asked
// without the issuer.
func TestWhatIsAskedIsBounded(t *testing.T) {
	leaf, issuer, _ := fixture(t, "www.digicert.com")

	f, seen := answering(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })

	// Refused by this package, not left to net/http to fail on. A sabotage
	// removing the scheme check escaped on 2026-09-14: the client refused ldap
	// on its own, so nothing was sent either way — the refusal is kept here so
	// it does not depend on what a library happens to reject.
	if got := f.Check(context.Background(), withResponders(leaf, "ldap://ocsp.example.test/", "ftp://ocsp.example.test/"), issuer, digicertAt); got.Status != "" || seen.Load() != 0 ||
		got.Reason != "the certificate names a responder at an address this does not ask" {
		t.Errorf("asked %d times of addresses this does not speak to: %+v", seen.Load(), got)
	}

	f.Check(context.Background(), withResponders(leaf,
		"http://a.example.test/", "http://b.example.test/", "http://c.example.test/", "http://d.example.test/"), issuer, digicertAt)
	if n := seen.Load(); n != maxResponders {
		t.Errorf("%d responders were asked, want at most %d", n, maxResponders)
	}

	// Refused before a question is written, and said as that. A sabotage
	// dropping the check escaped on 2026-09-14 because ocsp.Request refuses a
	// nil issuer too; the sentence here is the one a reader is owed.
	before := seen.Load()
	if got := f.Check(context.Background(), leaf, nil, digicertAt); got.Status != "" || seen.Load() != before ||
		!strings.Contains(got.Reason, "issuing certificate was not sent") {
		t.Errorf("a question was asked, or refused for the wrong reason, without the issuer: %+v", got)
	}
}

// Credentials in an address are not sent.
func TestCredentialsInAResponderAddressAreStripped(t *testing.T) {
	address, ok := usable("http://user:secret@ocsp.example.test/path")
	if !ok || strings.Contains(address, "secret") || strings.Contains(address, "user") {
		t.Errorf("usable returned %q, %v", address, ok)
	}
}

// The default dialler refuses a responder on a private address, and the reason
// names nothing about this machine (I6).
//
// Against a listener that is really there. A sabotage swapping safedial for a
// plain dialler escaped on 2026-09-14 when this aimed at a loopback port nothing
// listened on: the connection failed either way. Here it would succeed, so only
// the guard stops it.
func TestTheDefaultDiallerRefusesPrivateResponders(t *testing.T) {
	leaf, issuer, der := fixture(t, "www.digicert.com")

	var reached atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		_, _ = w.Write(der)
	}))
	defer srv.Close()

	got := (&Fetcher{Timeout: 2 * time.Second}).Check(context.Background(), withResponders(leaf, srv.URL+"/"), issuer, digicertAt)
	if reached.Load() || got.Status != "" || got.Reason == "" {
		t.Errorf("reached=%v, got %+v; a loopback responder is not asked", reached.Load(), got)
	}
	if strings.Contains(got.Reason, "127.0.0.1") {
		t.Errorf("the reason names the address: %q", got.Reason)
	}
}

// A failure to connect names nothing about the network either.
func TestNoReasonNamesTheMachine(t *testing.T) {
	leaf, issuer, _ := fixture(t, "www.digicert.com")
	f := &Fetcher{Timeout: time.Second, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial tcp 198.51.100.7:80 via 192.0.2.53: connection refused")
	}}
	got := f.Check(context.Background(), leaf, issuer, digicertAt)
	for _, leak := range []string{"198.51.100.7", "192.0.2.53", "refused"} {
		if strings.Contains(got.Reason, leak) {
			t.Errorf("the reason carries %q: %q", leak, got.Reason)
		}
	}
}
