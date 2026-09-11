package webprobe

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Which store decides the word "trusted" on an HTTPS chain.
//
// This check set no TLSClientConfig at all until 2026-09-11, so a nil RootCAs
// reached x509.Verify as a nil Roots — which on Windows and macOS hands the
// question to the platform verifier, a different store from the one a service
// checked when it started (R7). Here that is worse than a wrong grade: a chain
// the deciding store cannot verify is a handshake that fails, and a failed
// handshake reads as a site that is not served over HTTPS.

// tlsServerFor starts an HTTPS server on loopback and returns a prober that
// reaches it whatever name is dialled, plus a pool holding its authority.
func tlsServerFor(t *testing.T) (*Prober, *x509.CertPool) {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	addr := srv.Listener.Addr().String()
	p := &Prober{
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
		RequestTimeout: 5 * time.Second,
		TotalTimeout:   15 * time.Second,
	}

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return p, pool
}

// The pool a caller passes is the pool that decides.
func TestTheRootsPassedInAreWhatVerifiesAWebChain(t *testing.T) {
	p, pool := tlsServerFor(t)
	p.Roots = pool

	// The name the certificate is for. httptest issues for 127.0.0.1, and the
	// dialler sends every name to that listener, so the address is the name
	// that verifies.
	c := p.chain(context.Background(), p.client(), "https://127.0.0.1/", anywhere())

	hop := c.Final()
	if hop == nil {
		t.Fatal("no hop was recorded")
	}
	if hop.Err != "" {
		t.Fatalf("the handshake failed with the issuing authority in the pool: %q", hop.Err)
	}
	if hop.Status != http.StatusOK {
		t.Errorf("answered %d, want 200", hop.Status)
	}
}

// And a pool without it refuses, rather than the platform deciding.
//
// The direction that matters. If this passed, the store handed in would not be
// the store in play, and a report would be describing a verification this
// program did not perform.
func TestAStoreWithoutTheAuthorityRefusesTheChain(t *testing.T) {
	p, _ := tlsServerFor(t)
	p.Roots = x509.NewCertPool()

	c := p.chain(context.Background(), p.client(), "https://127.0.0.1/", anywhere())

	hop := c.Final()
	if hop == nil {
		t.Fatal("no hop was recorded")
	}
	if hop.Err == "" {
		t.Error("the handshake succeeded against a pool holding no authority, so something " +
			"other than the pool passed in decided that the chain was trusted")
	}
}

// A store that could not be read reaches the report.
//
// Without this the fix introduces the failure it exists to close. truststore
// answers an unreadable store with an empty pool, which is the safe answer and
// not a usable one: every HTTPS hop then fails, and a chain of failed
// handshakes reads as a site that is not served over HTTPS. A fact about the
// machine running the scan, printed as a finding about somebody else's server
// (R4).
func TestAnUnreadableStoreIsCarriedIntoTheReport(t *testing.T) {
	p, _ := tlsServerFor(t)

	// No pool, and no system pool either: the resolution fails and the report
	// has to say so. Driven by replacing the resolver rather than by skipping,
	// because the machine whose store cannot be read is the machine no test
	// runs on.
	original := resolveRoots
	resolveRoots = func(*x509.CertPool) (*x509.CertPool, error) {
		// What truststore answers on failure: an empty pool, never nil.
		return x509.NewCertPool(), errors.New("no store on this machine")
	}
	t.Cleanup(func() { resolveRoots = original })

	report, err := p.Probe(context.Background(), "example.test", nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !report.TrustStoreUnreadable {
		t.Error("the store could not be read and the report does not say so, so every failed " +
			"HTTPS hop reads as a server that does not serve HTTPS")
	}
}

// And when the store reads, nothing claims otherwise.
func TestAReadableStoreIsNotReportedAsUnreadable(t *testing.T) {
	p, pool := tlsServerFor(t)
	p.Roots = pool

	// A name rather than an address: Probe refuses a bare address, and this is
	// about the store rather than about the handshake, which will fail on the
	// name either way.
	report, err := p.Probe(context.Background(), "example.test", nil)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if report.TrustStoreUnreadable {
		t.Error("a pool was passed in and the report claims the store could not be read")
	}
}

// The client is configured with what it needs and nothing that would weaken it.
//
// Setting TLSClientConfig at all moves responsibility for these from crypto/tls
// to this package, so each is asserted rather than assumed.
func TestTheClientCarriesNoWeakeningTLSSetting(t *testing.T) {
	p, pool := tlsServerFor(t)
	p.Roots = pool

	transport, ok := p.client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("the client no longer carries an *http.Transport, so nothing here is checking " +
			"the settings a handshake is made with")
	}

	cfg := transport.TLSClientConfig
	if cfg == nil {
		t.Fatal("no TLSClientConfig, so a nil RootCAs reaches x509.Verify and the platform " +
			"decides what is trusted — the defect this file exists for")
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is set, which turns every certificate finding into fiction")
	}
	if cfg.RootCAs != pool {
		t.Error("RootCAs is not the pool passed in, so the store that decides is not the one " +
			"the caller chose")
	}

	// A name here would be checked against every hop's certificate, including
	// hosts a redirect moved on to — so every redirect off the first name would
	// fail verification and be reported as a broken site.
	if cfg.ServerName != "" {
		t.Errorf("ServerName is %q; one config serves every hop of both chains and each has "+
			"its own name to verify", cfg.ServerName)
	}

	// A cache shared across hosts can resume somebody else's session, and a
	// resumed handshake is not the handshake this check means to measure.
	if cfg.ClientSessionCache != nil {
		t.Error("a ClientSessionCache is shared across every host this probe reaches")
	}

	// Naming a version here would move a measurement rather than a setting: a
	// host reachable only over an older protocol would start being reported as
	// not reachable at all. The package default is what a browser does.
	if cfg.MinVersion != 0 {
		t.Errorf("MinVersion is %d; leaving it at the package default keeps this a measurement "+
			"of how the site is reached rather than of what this config allows", cfg.MinVersion)
	}
	if cfg.MaxVersion != 0 {
		t.Errorf("MaxVersion is %d, which caps what a handshake may negotiate", cfg.MaxVersion)
	}
}

// The sentence a reader is given lives in internal/policy, which this package
// deliberately does not import — measurement here, rules there. It is asserted
// in internal/webscan, where the two meet.
