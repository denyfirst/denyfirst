package certinfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// A root this package's tests can actually reach.
//
// Every chain these tests built used to fail verification, because a root
// generated in a test is not in the machine's store. Nothing was wrong with
// that until it started hiding things: every report came out `insecure` from
// cert.chain-untrusted whatever else was true, so a rule that only shows up on
// an otherwise sound chain could not be seen at all. The chain verdict landed
// in that blind spot on 2026-09-02 — the fold over the issuers could be
// deleted and no test noticed, because the leaf was already insecure.
//
// Go's verifier reads SSL_CERT_FILE, so one root written to a PEM before
// anything verifies gives these tests a store of their own. The catch is that
// the system pool is built once per process: setting the variable inside a
// test works when that test runs alone and does nothing in a full package
// run, because something has verified already. TestMain is the only place
// early enough.
//
// The store holds exactly one certificate, and no public authority. Nothing
// here should ever depend on a real root, and a test that started to would
// now fail rather than pass for a reason nobody chose.
var (
	// sharedRoot is trusted. newRoot returns it, so a chain built the ordinary
	// way in a test verifies the way a real one does.
	sharedRoot issuer
)

func TestMain(m *testing.M) {
	code, err := run(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "certinfo tests: %v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

// run does the work so that deferred cleanup happens before os.Exit.
func run(m *testing.M) (int, error) {
	dir, err := os.MkdirTemp("", "denyfirst-roots")
	if err != nil {
		return 0, fmt.Errorf("making a directory for the test root: %w", err)
	}
	defer os.RemoveAll(dir)

	root, err := makeRoot("denyfirst test root")
	if err != nil {
		return 0, err
	}
	sharedRoot = root

	path := filepath.Join(dir, "roots.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: root.cert.Raw}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return 0, fmt.Errorf("writing the test root: %w", err)
	}

	// Both, because Go consults them separately and a directory left pointing
	// at the machine's own store would put real authorities back in.
	if err := os.Setenv("SSL_CERT_FILE", path); err != nil {
		return 0, err
	}
	if err := os.Setenv("SSL_CERT_DIR", dir); err != nil {
		return 0, err
	}

	return m.Run(), nil
}

// makeRoot builds a self-signed authority. Shared by TestMain, which has no
// *testing.T, and by newUntrustedRoot, which has one.
func makeRoot(commonName string) (issuer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return issuer{}, fmt.Errorf("generating a root key: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             refNow.AddDate(-1, 0, 0),
		NotAfter:              refNow.AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return issuer{}, fmt.Errorf("creating a root: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return issuer{}, fmt.Errorf("parsing a root: %w", err)
	}
	return issuer{cert: cert, key: key}, nil
}

// newUntrustedRoot builds an authority that is deliberately in no store.
//
// For the tests whose subject is what happens when a chain does not verify.
// They used to get that for free from every root; now they have to ask, which
// is the right way round — an assertion about untrusted chains should say so.
func newUntrustedRoot(t *testing.T) issuer {
	t.Helper()
	root, err := makeRoot("denyfirst untrusted test root")
	if err != nil {
		t.Fatalf("%v", err)
	}
	return root
}

// The store TestMain installs is really installed.
//
// Everything this package now measures about trusted chains rests on it, and
// a setup that quietly stops working does not announce itself: the tests go
// back to reporting every chain untrusted and keep passing, which is the blind
// spot they were arranged to leave.
//
// Both variables are set because Go consults them separately, and removing
// either one alone leaves the other doing the work — so this asserts the
// outcome rather than the mechanism.
func TestTheTestRootIsInTheStore(t *testing.T) {
	if sharedRoot.cert == nil {
		t.Fatal("TestMain built no shared root")
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		t.Fatalf("reading the system pool: %v", err)
	}

	leaf := newLeaf(t, sharedRoot, leafOpts{})
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		DNSName:     "example.test",
		CurrentTime: refNow,
	}); err != nil {
		t.Fatalf(`a chain to the test root does not verify against the system pool: %v

TestMain writes that root to a PEM and points SSL_CERT_FILE and SSL_CERT_DIR
at it before anything else runs. If that has stopped working, every test in
this package is back to measuring untrusted chains and passing anyway.`, err)
	}

	// And nothing else is in there. A public authority in the pool would mean
	// a test could pass for a reason nobody chose, and would make this suite
	// depend on the machine it runs on: setting only one of the two variables
	// leaves the other loading the system store, and that is not a failure
	// that announces itself.
	//
	// Compared as a whole rather than counted through Subjects, which is
	// deprecated precisely because it does not describe a system pool
	// faithfully — reaching for it here would be using a broken measure to
	// check that a measurement is sound.
	want := x509.NewCertPool()
	want.AddCert(sharedRoot.cert)
	if !pool.Equal(want) {
		t.Error(`the system pool is not exactly the test root.

TestMain sets SSL_CERT_FILE and SSL_CERT_DIR, and Go consults them separately:
leaving either one unset lets the machine's own authorities back in, and every
test here would then depend on which machine it ran on.`)
	}
}
