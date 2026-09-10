package certinfo

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

// The store a caller passes is the store that decides, on every platform.
//
// This is the defect the parameter exists to close. x509.Verify with a nil
// Roots does not mean "the system pool": it means "decide for yourself", and
// on Windows and macOS deciding means calling the platform verifier, which
// consults a different store and reads neither SSL_CERT_FILE nor anything this
// program checked when it started. denyfirstd satisfied itself at startup that
// its trust store was not empty and then judged every chain against something
// else, on the two platforms self-hosting is most likely to run on.
//
// Two tests in this package failed there from the day they were written, which
// was the symptom, and it was read as a fixture problem rather than as the
// program measuring against a store it had never looked at.
func TestTheRootsPassedInAreTheOnesThatDecide(t *testing.T) {
	root := newUntrustedRoot(t)
	leaf := newLeaf(t, root, leafOpts{})
	chain := []*x509.Certificate{leaf, root.cert}

	// Against a pool that holds this root, the chain is trusted — even though
	// no machine anywhere has this authority installed. If the platform
	// verifier were deciding, no pool could make this true.
	mine := x509.NewCertPool()
	mine.AddCert(root.cert)

	report, err := Analyse(chain, "example.test", refNow, mine)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if !report.Trusted {
		t.Errorf("a chain to the root in the pool passed is untrusted (%s); the pool a caller "+
			"gives is not what the verification uses", report.VerifyError)
	}

	// And against a pool that does not hold it, the same chain is untrusted.
	// Both directions, because a function that ignored its argument and
	// answered "trusted" to everything would satisfy the half above.
	empty := x509.NewCertPool()
	report, err = Analyse(chain, "example.test", refNow, empty)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if report.Trusted {
		t.Error("a chain whose root is in no pool was reported trusted; the pool a caller gives " +
			"is not what the verification uses")
	}
}

// A nil pool is resolved here rather than left for Verify to interpret.
//
// Nil is still accepted, because a caller with nothing to say should get the
// machine's own store. What must not happen is nil reaching VerifyOptions,
// which is the branch that hands the whole question to the platform.
func TestANilPoolBecomesTheSystemPoolRatherThanThePlatformVerifier(t *testing.T) {
	got, err := resolveRoots(nil)
	if err != nil {
		t.Skipf("this machine has no readable system store: %v", err)
	}
	if got == nil {
		t.Fatal("resolveRoots returned nil, which is the value that sends Verify to the platform")
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
	mine.AddCert(sharedRoot.cert)

	got, err := resolveRoots(mine)
	if err != nil {
		t.Fatalf("resolveRoots: %v", err)
	}
	if !got.Equal(mine) {
		t.Error("the pool passed in was replaced, so a caller cannot decide what its chains are judged against")
	}
}

// A store that cannot be read is a fact about this machine, not about the
// server (R4).
//
// The pool returned on failure matters as much as the note. Nil would send
// Verify back to the platform verifier — the behaviour being removed — and on
// the two platforms where the store could not be read it would then report
// chains as trusted, which is the worst of the available answers arrived at by
// the exact path this change closes.
//
// Driven by replacing the loader rather than by skipping. The branch matters
// most on a machine whose store cannot be read, which is the machine no test
// runs on, and a test that skips itself everywhere says nothing at all.
func TestAnUnreadableStoreIsNotReportedAsAnUntrustedServer(t *testing.T) {
	original := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) {
		return nil, errors.New("no store on this machine")
	}
	t.Cleanup(func() { systemCertPool = original })

	pool, err := resolveRoots(nil)
	if err == nil {
		t.Fatal("a store that could not be read was reported as readable")
	}
	if pool == nil {
		t.Fatal("a failure returned a nil pool, which is the value that sends Verify to the platform")
	}
	if !pool.Equal(x509.NewCertPool()) {
		t.Error("a failure returned a pool with something in it")
	}

	// And the report says so in words rather than calling the server
	// untrusted, which would be a finding about somebody else's certificate
	// produced by this machine's problem.
	leaf := newLeaf(t, sharedRoot, leafOpts{})
	report, err := Analyse([]*x509.Certificate{leaf, sharedRoot.cert}, "example.test", refNow, nil)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}

	var said bool
	for _, n := range report.Notes {
		if strings.Contains(n.Text, "trust store on this machine could not be read") {
			said = true
		}
	}
	if !said {
		t.Error("the report does not say the trust store could not be read, so a reader takes " +
			"untrusted as a fact about the server")
	}
}
