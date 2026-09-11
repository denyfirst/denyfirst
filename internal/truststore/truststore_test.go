package truststore

import (
	"crypto/x509"
	"errors"
	"testing"
)

// A nil pool is resolved here rather than left for a verifier to interpret.
//
// Nil is still accepted, because a caller with nothing to say should get the
// machine's own store. What must not happen is nil reaching VerifyOptions or a
// tls.Config, which is the branch that hands the whole question to the platform.
func TestANilPoolBecomesTheSystemPoolRatherThanThePlatformVerifier(t *testing.T) {
	got, err := Resolve(nil)
	if err != nil {
		t.Skipf("this machine has no readable system store: %v", err)
	}
	if got == nil {
		t.Fatal("Resolve returned nil, which is the value that sends verification to the platform")
	}

	system, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("this machine has no readable system store: %v", err)
	}
	if !got.Equal(system) {
		t.Error("a nil pool resolved to something other than the system store")
	}
}

// A pool a caller passes is returned unchanged.
func TestAPoolPassedInIsNotReplaced(t *testing.T) {
	mine := x509.NewCertPool()

	got, err := Resolve(mine)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !got.Equal(mine) {
		t.Error("the pool passed in was replaced, so a caller cannot decide what its chains " +
			"are judged against")
	}
}

// A store that cannot be read resolves to an empty pool, never to nil.
//
// The pool returned on failure matters as much as the error. Nil would send
// verification back to the platform — the behaviour this package exists to
// remove — and on the two platforms where the store could not be read it would
// then report chains as trusted, which is the worst of the available answers
// arrived at by the exact path this closes.
//
// Driven by replacing the loader rather than by skipping. The branch matters
// most on a machine whose store cannot be read, which is the machine no test
// runs on, and a test that skips itself everywhere says nothing at all.
func TestAnUnreadableStoreResolvesToAnEmptyPoolRatherThanNil(t *testing.T) {
	original := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) {
		return nil, errors.New("no store on this machine")
	}
	t.Cleanup(func() { systemCertPool = original })

	pool, err := Resolve(nil)
	if err == nil {
		t.Fatal("a store that could not be read was reported as readable")
	}
	if pool == nil {
		t.Fatal("a failure returned a nil pool, which is the value that sends verification " +
			"to the platform")
	}
	if !pool.Equal(x509.NewCertPool()) {
		t.Error("a failure returned a pool with something in it")
	}
}
