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

// What Resolve does with a nil pool, and with one a caller passed, is tested in
// internal/truststore — the package that decides it, since the web check asks
// the same question. What this package still has to answer is what it says when
// the answer came back as a failure.

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
	original := resolveRoots
	resolveRoots = func(*x509.CertPool) (*x509.CertPool, error) {
		// What truststore returns when the store cannot be read: an empty pool
		// rather than nil, because nil is the value that sends Verify to the
		// platform — and on the machine whose store could not be read, that
		// path reports chains as trusted.
		return x509.NewCertPool(), errors.New("no store on this machine")
	}
	t.Cleanup(func() { resolveRoots = original })

	// The report says so in words rather than calling the server untrusted,
	// which would be a finding about somebody else's certificate produced by
	// this machine's problem.
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
