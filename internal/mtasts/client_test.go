package mtasts

import (
	"net/http"
	"testing"
)

// The connection is judged against a resolved store and is not kept.
//
// A nil RootCAs — and on Windows and macOS a system pool as well — hands the
// certificate to the platform verifier, which fetches what the certificate names
// outside safedial (audit A25). And a kept-alive connection on a transport
// nobody holds stays open until the peer closes it, one per fetch (audit A28).
func TestTheClientResolvesItsStoreAndKeepsNothingOpen(t *testing.T) {
	transport, ok := (&Fetcher{}).client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("the client has no *http.Transport to inspect")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Error("the client passes a nil store, which hands verification to the platform")
	}
	if !transport.DisableKeepAlives {
		t.Error("the one-request client keeps its connection alive with nobody left to close it")
	}
}
