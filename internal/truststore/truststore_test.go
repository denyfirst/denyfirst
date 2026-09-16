package truststore

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/denyfirst/denyfirst/internal/rootstores"
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

	want, err := defaultStore()
	if err != nil {
		t.Skipf("this machine has no readable store: %v", err)
	}
	if !got.Equal(want) {
		t.Error("a nil pool resolved to something other than this platform's default store")
	}
}

// On Windows and macOS a nil pool becomes the carried copy of the platform's
// programme, and never a pool from SystemCertPool — which crypto/x509 hands to
// the platform verifier, and which on Windows fetches whatever a scanned
// server's certificate names (audit A25). Everywhere else it is the machine's
// store, which is only a pool there.
//
// Every platform is asked, whichever this test runs on, by replacing the name
// of the platform: CI runs on Linux, and the platforms this guards are the two
// it does not run on. Pool.Equal compares the mark crypto/x509 reads as well as
// the certificates, so a system pool can never pass for the carried one.
func TestEachPlatformResolvesToAPoolThatIsOnlyAPool(t *testing.T) {
	carried, err := rootstores.Carried()
	if err != nil {
		t.Fatalf("the carried stores: %v", err)
	}
	original := platform
	t.Cleanup(func() { platform = original })

	for goos, store := range map[string]rootstores.Store{
		"windows": rootstores.Microsoft,
		"darwin":  rootstores.Apple,
		"ios":     rootstores.Apple,
	} {
		platform = goos
		got, err := Resolve(nil)
		if err != nil {
			t.Fatalf("%s: %v", goos, err)
		}
		if !got.Equal(carried.Pool(store)) {
			t.Errorf("%s: a nil pool did not become the carried %s store", goos, store.Name())
		}
		if system, err := x509.SystemCertPool(); err == nil && got.Equal(system) {
			t.Errorf("%s: a nil pool became the system pool, which the platform verifier answers for", goos)
		}
	}

	platform = "linux"
	if _, ok := platformStore(platform); ok {
		t.Error("Linux was given a carried store; its system pool has no platform verifier behind it")
	}
}

// The carried pool is a copy: a caller adding to it changes nothing for the next.
func TestTheCarriedPoolIsACopy(t *testing.T) {
	carried, err := rootstores.Carried()
	if err != nil {
		t.Fatalf("the carried stores: %v", err)
	}
	first := carried.Pool(rootstores.Microsoft)
	first.AddCert(&x509.Certificate{Raw: []byte("not a certificate"), RawSubject: []byte("x")})
	if first.Equal(carried.Pool(rootstores.Microsoft)) {
		t.Error("adding to one caller's pool changed the carried store")
	}
	if carried.Pool(rootstores.Microsoft).Equal(x509.NewCertPool()) {
		t.Error("the carried Microsoft pool is empty")
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
