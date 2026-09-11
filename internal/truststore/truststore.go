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
// The TLS check was fixed on 2026-09-10 and the web check had the same hole:
// internal/webprobe set no TLSClientConfig at all. Two copies of a rule about
// which store decides the word "trusted" are two copies that drift, and this
// project has been caught twice in one day by exactly that shape — so the rule
// is here and both checks ask it.
package truststore

import "crypto/x509"

// systemCertPool is a variable so that the failure branch below can be reached
// by a test.
//
// It could not be otherwise. That branch matters most on a machine whose store
// cannot be read, which is the machine no test runs on — and a test that skips
// itself everywhere is the same silence A7 is about, arriving in a test file
// instead of in a counter.
var systemCertPool = x509.SystemCertPool

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
