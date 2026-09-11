package webscan

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/policy"
	"github.com/denyfirst/denyfirst/internal/webprobe"
)

// The store a caller configures has to reach the prober, and a store that could
// not be read has to reach the reader.

// A store set on the scanner is the store the handshake is judged against.
//
// Asserted by what the handshake does rather than by reading a field back,
// because reading the field back is what the first version of this test did and
// a sabotage that stopped passing the store to the prober walked straight past
// it. The httptest certificate is issued for example.com and signed by an
// authority in no system store, so the two outcomes are distinguishable: the
// chain verifies only if this pool reached the prober, and falls back to the
// system store — where that authority is not — if it did not.
func TestTheScannersTrustStoreDecidesTheHandshake(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build refuses this name before the prober is built")
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	mine := x509.NewCertPool()
	mine.AddCert(srv.Certificate())

	addr := srv.Listener.Addr().String()
	p := &webprobe.Prober{
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
		RequestTimeout: 5 * time.Second,
		TotalTimeout:   15 * time.Second,
	}

	s := &Scanner{Prober: p, Roots: mine}
	out, err := s.Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	hop := out.Observed.Secure.Final()
	if hop == nil {
		t.Fatal("no secure hop was recorded")
	}
	if hop.Err != "" {
		t.Fatalf("the handshake failed with the issuing authority in the scanner's pool (%q), "+
			"so the store the caller configured is not the store that decided", hop.Err)
	}

	// And the prober the caller owns is left alone: the scanner works on a
	// copy, so a Prober reused elsewhere does not silently acquire this store.
	if p.Roots != nil {
		t.Error("the scanner wrote a trust store into the prober the caller passed in")
	}
}

// A store already on the prober is not replaced.
//
// The caller said something by setting it, and a scanner that overwrote it
// would widen or narrow what decides "trusted" without anybody asking — the
// same argument UseWebScanner makes about carrying a boundary over rather than
// replacing it.
//
// Asserted through the handshake for the reason the test above is: the scanner
// works on a copy, so reading the caller's prober back proves only that the copy
// exists. A sabotage that overwrote the copy's store passed a version of this
// test that did exactly that.
func TestAProberWithItsOwnTrustStoreKeepsIt(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build refuses this name before the prober is built")
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// The prober's own store can verify this server. The scanner's cannot.
	theirs := x509.NewCertPool()
	theirs.AddCert(srv.Certificate())

	addr := srv.Listener.Addr().String()
	p := &webprobe.Prober{
		Roots: theirs,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
		RequestTimeout: 5 * time.Second,
		TotalTimeout:   15 * time.Second,
	}

	s := &Scanner{Prober: p, Roots: x509.NewCertPool()}
	out, err := s.Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	hop := out.Observed.Secure.Final()
	if hop == nil {
		t.Fatal("no secure hop was recorded")
	}
	if hop.Err != "" {
		t.Errorf("the handshake failed (%q), so the scanner replaced the store the prober was "+
			"given with its own", hop.Err)
	}
	if p.Roots != theirs {
		t.Error("the prober the caller owns had its store rewritten")
	}
}

// A store that could not be read is said in words, not as an unreachable site.
//
// This is the half that makes the fix safe to ship. truststore answers an
// unreadable store with an empty pool, so every HTTPS hop fails — and a chain of
// failed handshakes reads as a site that is not served over HTTPS. Without the
// note, closing one R4 defect would open another.
func TestAnUnreadableStoreIsSaidInWordsRatherThanAsAnUnreachableSite(t *testing.T) {
	observed := &webprobe.Report{
		Host:                 "example.test",
		TrustStoreUnreadable: true,
	}

	var found string
	for _, n := range Grade(observed).Notes {
		if strings.Contains(n.Text, "trust store on this machine could not be read") {
			if n.Kind != policy.KindUnsettled {
				t.Errorf("the note is of kind %q, want unsettled: nothing judged the chain, so "+
					"this is not a finding about the server", n.Kind)
			}
			found = n.Text
		}
	}

	if found == "" {
		t.Fatal("a report built from an unreadable store says nothing about it, so a reader " +
			"is handed a site that appears not to serve HTTPS with no way to tell why")
	}
	if !strings.Contains(found, "machine running this scan") {
		t.Errorf("the note does not say whose machine the fault is on: %s", found)
	}
	if strings.Contains(strings.ToLower(found), "untrusted") {
		t.Errorf("the note calls something untrusted, which is a finding about a certificate "+
			"produced by this machine's failure (R4): %s", found)
	}
}

// And a report from a readable store does not carry the note.
func TestAReadableStoreAddsNoNote(t *testing.T) {
	observed := &webprobe.Report{Host: "example.test"}

	for _, n := range Grade(observed).Notes {
		if strings.Contains(n.Text, "trust store on this machine could not be read") {
			t.Error("a report says the trust store could not be read when it was read")
		}
	}
}

// Both checks read one sentence.
//
// It was written inline in internal/certinfo while one check verified a chain.
// Two copies of a claim about whose store decided the word "trusted" are two
// copies that drift, and a reader comparing a TLS report with a web report would
// be the one to find out (R16).
func TestOneSentenceSaysTheStoreCouldNotBeRead(t *testing.T) {
	if policy.TrustStoreUnreadable().Kind != policy.KindUnsettled {
		t.Error("the shared sentence is not unsettled, so a local failure is being presented " +
			"as something established about a server")
	}
}
