// Package truststore decides which certificate store a check judges a chain
// against.
//
// It holds one decision, and it exists because that decision was about to be
// written a second time. A nil pool is not "the system store": handed to
// crypto/x509 or crypto/tls it means *decide for yourself*, and on Windows and
// macOS deciding means calling the platform verifier — which consults neither
// the pool a service checked when it started nor SSL_CERT_FILE. So a program
// can satisfy itself that its trust store is not empty and then judge every
// chain against something else, on the two platforms self-hosting is most
// likely to run on (R7).
//
// And the machine's own store is not the answer on every platform either: on
// Windows and macOS a pool from x509.SystemCertPool sends verification to the
// platform just as nil does. defaultStore says why that matters and what is
// used instead.
//
// The TLS check was fixed on 2026-09-10 and the web check had the same hole:
// internal/webprobe set no TLSClientConfig at all. Two copies of a rule about
// which store decides the word "trusted" are two copies that drift, and this
// project has been caught twice in one day by exactly that shape — so the rule
// is here and both checks ask it.
package truststore

import (
	"crypto/x509"
	"runtime"

	"github.com/denyfirst/denyfirst/internal/rootstores"
)

// systemCertPool is a variable so that the failure branch below can be reached
// by a test.
//
// It could not be otherwise. That branch matters most on a machine whose store
// cannot be read, which is the machine no test runs on — and a test that skips
// itself everywhere is the same silence A7 is about, arriving in a test file
// instead of in a counter.
var systemCertPool = defaultStore

// platform is runtime.GOOS, replaceable by a test.
var platform = runtime.GOOS

// defaultStore is the pool a nil store becomes.
//
// # Why not SystemCertPool on Windows and macOS
//
// A pool from x509.SystemCertPool carries a mark, and on Windows and macOS
// crypto/x509 reads that mark as "ask the platform verifier first" — the Go
// source says so in Certificate.Verify. On Windows the platform verifier is
// CertGetCertificateChain, called without the flag that keeps it off the
// network, so it fetches the intermediates a certificate's own AIA extension
// names. That certificate was sent by the server being scanned. A scanned
// server could therefore make this machine fetch an address of its choosing,
// private ones included, through a connection safedial never saw — and a chain
// the platform completed that way would be reported as trusted though the
// server never sent it. Found by the 2026-09-16 audit (A25); this file had said
// the opposite since 2026-09-10.
//
// So on those two platforms the pool is the copy this build carries of the
// platform's own programme — Microsoft's store on Windows, Apple's on macOS —
// built as an ordinary pool, which crypto/x509 verifies by itself and which
// fetches nothing. Reports date that copy. Elsewhere the machine's store is
// read as before: on Linux and the BSDs SystemCertPool is a pool loaded from
// files, and there is no platform verifier behind it.
func defaultStore() (*x509.CertPool, error) {
	store, ok := platformStore(platform)
	if !ok {
		return x509.SystemCertPool()
	}
	set, err := rootstores.Carried()
	if err != nil {
		return nil, err
	}
	return set.Pool(store), nil
}

// platformStore names the carried programme that stands in for a platform's
// own verifier, and whether the platform has one.
func platformStore(goos string) (rootstores.Store, bool) {
	switch goos {
	case "windows":
		return rootstores.Microsoft, true
	case "darwin", "ios":
		return rootstores.Apple, true
	}
	return "", false
}

// Resolve turns a caller's store into one that will be used on every platform.
//
// An error is returned rather than swallowed, and a caller says so in words
// rather than reporting a chain as untrusted: a store that could not be read is
// a fact about this machine, not about the server (R4).
func Resolve(roots *x509.CertPool) (*x509.CertPool, error) {
	if roots != nil {
		return roots, nil
	}

	pool, err := systemCertPool()
	if err != nil {
		// An empty pool rather than nil. Nil would send the verification back
		// to the platform, which is the behaviour this package exists to
		// remove — and it would report a trusted chain on the two platforms
		// where the store could not be read, which is the worst of the answers
		// available.
		return x509.NewCertPool(), err
	}
	return pool, nil
}
