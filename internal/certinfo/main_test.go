package certinfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
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
// One root, built here and handed to every Analyse call as its Roots. It used
// to be installed through SSL_CERT_FILE instead, which worked on Linux and on
// nothing else: only Go's unix root loader reads that variable, so on Windows
// and macOS the PEM was written and never consulted, and two tests failed there
// from the day they were written. Passing the pool is what the program does
// now, so the tests take the same path it does.
//
// The store holds exactly one certificate, and no public authority. Nothing
// here should ever depend on a real root, and a test that started to would
// now fail rather than pass for a reason nobody chose.
var (
	// sharedRoot is trusted. newRoot returns it, so a chain built the ordinary
	// way in a test verifies the way a real one does.
	sharedRoot issuer

	// testRoots is the store every Analyse call in this package is given.
	//
	// Passed rather than installed through the environment. SSL_CERT_FILE is
	// read by Go's unix root loader and by nothing else, so on Windows and
	// macOS the fixture below wrote a PEM that nothing consulted and two tests
	// failed there from the day they were written. Handing the pool to the
	// function under test works the same way on every platform — and it is
	// also what the program now does, so the tests exercise the real path
	// rather than a second one.
	testRoots *x509.CertPool
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
	root, err := makeRoot("denyfirst test root")
	if err != nil {
		return 0, err
	}
	sharedRoot = root

	testRoots = x509.NewCertPool()
	testRoots.AddCert(root.cert)

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

// The store the tests hand to Analyse is really the store it verifies against.
//
// Everything this package measures about trusted chains rests on it, and a
// setup that quietly stops working does not announce itself: the tests go back
// to reporting every chain untrusted and keep passing, which is the blind spot
// they were arranged to leave.
//
// It used to rest on SSL_CERT_FILE and SSL_CERT_DIR, and that is why this test
// existed in the first place — the mechanism was fragile enough to need
// watching. It was also fragile in a way the watching could not catch, because
// only Go's unix root loader reads those variables: on Windows and macOS the
// fixture wrote a PEM that nothing consulted, and two tests in this package
// failed there from the day they were written. Passing the pool to the
// function under test works identically on every platform, and it is what the
// program itself now does, so these tests exercise the real path rather than a
// second one arranged for them.
func TestTheTestRootIsTheStoreAnalyseUses(t *testing.T) {
	if sharedRoot.cert == nil {
		t.Fatal("TestMain built no shared root")
	}
	if testRoots == nil {
		t.Fatal("TestMain built no pool for the tests to pass")
	}

	// The outcome rather than the mechanism: a chain to the test root is
	// trusted when Analyse is given that pool.
	leaf := newLeaf(t, sharedRoot, leafOpts{})
	report, err := Analyse([]*x509.Certificate{leaf, sharedRoot.cert}, "example.test", refNow, testRoots)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if !report.Trusted {
		t.Fatalf(`a chain to the test root is not trusted: %s

The pool TestMain builds is what every Analyse call here passes. If that has
stopped working, every test in this package is back to measuring untrusted
chains and passing anyway.`, report.VerifyError)
	}

	// And nothing else is in there. A public authority in the pool would mean
	// a test could pass for a reason nobody chose, and would make this suite
	// depend on the machine it runs on.
	//
	// Compared as a whole rather than counted through Subjects, which is
	// deprecated precisely because it does not describe a pool faithfully —
	// reaching for it here would be using a broken measure to check that a
	// measurement is sound.
	want := x509.NewCertPool()
	want.AddCert(sharedRoot.cert)
	if !testRoots.Equal(want) {
		t.Error("the pool the tests pass is not exactly the test root, so a result here could " +
			"depend on which machine it ran on")
	}

	// The machine's own store is not it. Were the two the same, this suite
	// would be measuring whatever authorities happen to be installed, and the
	// separation the fixture exists for would be gone without a symptom.
	if system, err := x509.SystemCertPool(); err == nil && system.Equal(want) {
		t.Error("the system pool and the test pool are identical, which means the fixture is not " +
			"isolating anything")
	}
}
