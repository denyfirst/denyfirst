package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

// privateChain builds an authority nobody has installed and leaves under it.
func privateChain(t *testing.T, leaves int) (root *x509.Certificate, served []*tls.Certificate) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a root key: %v", err)
	}
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "denyfirst scan test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatalf("creating the root: %v", err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parsing the root: %v", err)
	}

	for i := range leaves {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating a leaf key: %v", err)
		}
		leafTpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(2 + i)),
			Subject:      pkix.Name{CommonName: "localhost"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			DNSNames:     []string{"localhost"},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, root, leafKey.Public(), rootKey)
		if err != nil {
			t.Fatalf("creating the leaf: %v", err)
		}

		served = append(served, &tls.Certificate{
			Certificate: [][]byte{leafDER, rootDER},
			PrivateKey:  leafKey,
		})
	}

	return root, served
}

// The scanner's trust store is the one the chain is judged against.
//
// Scanner.Roots exists because it did not, and the absence was invisible: a
// nil Roots reaching x509.Verify means "decide for yourself", and on Windows
// and macOS deciding means the platform verifier — a different store from the
// one denyfirstd checks when it starts. The service satisfied itself that its
// trust store was not empty and then judged every chain against something
// else, on the two platforms self-hosting is most likely to run on.
//
// A sabotage that dropped the field on the way to certinfo.Analyse broke
// nothing, because nothing here asked whether the store a caller set had any
// effect. This asks, in both directions: an authority nobody has installed
// makes a chain trusted when the scanner is given it, and does not when the
// scanner is given an empty pool.
func TestTheScannersTrustStoreIsWhatJudgesTheChain(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build does not scan this host")
	}

	// Two leaves under one authority, served by protocol version, so the
	// report carries an alternate chain as well as the one described. Both are
	// graded and both verdicts join the aggregate, so a pool that reached one
	// and not the other would put two different trust answers in one report.
	root, leaves := privateChain(t, 2)
	host, port := serverByVersion(t, leaves[0], leaves[1])
	target := net.JoinHostPort(host, port)

	scanWith := func(roots *x509.CertPool) (described bool, alternates []bool) {
		t.Helper()

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		s := &Scanner{
			Prober:         &tlsprobe.Prober{Dial: (&net.Dialer{}).DialContext},
			AllowAnyPort:   true,
			AllowIPTargets: true,
			Roots:          roots,
		}
		result, err := s.Scan(ctx, target)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if result.Certificate == nil {
			t.Fatal("the scan produced no certificate report")
		}
		for _, alt := range result.AlternateCertificates {
			alternates = append(alternates, alt.Trusted)
		}
		return result.Certificate.Trusted, alternates
	}

	mine := x509.NewCertPool()
	mine.AddCert(root)

	described, alternates := scanWith(mine)
	if !described {
		t.Error("a chain to the authority the scanner was given is untrusted; Roots decides nothing, " +
			"so the store this program checks is not the store it verifies against")
	}
	if len(alternates) == 0 {
		t.Fatal("no alternate chain was graded, so this test cannot say whether the pool reached one")
	}
	for i, trusted := range alternates {
		if !trusted {
			t.Errorf("alternate chain %d is untrusted while the described chain is trusted; the "+
				"pool reached one call site and not the other, so one report carries two trust answers", i)
		}
	}

	// The other direction. A scanner that reported everything trusted would
	// satisfy the half above without the field doing any work.
	described, alternates = scanWith(x509.NewCertPool())
	if described {
		t.Error("a chain to an authority in no pool was reported trusted")
	}
	for i, trusted := range alternates {
		if trusted {
			t.Errorf("alternate chain %d was reported trusted against an empty pool", i)
		}
	}
}
