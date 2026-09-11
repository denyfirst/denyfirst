package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/crl"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

// Whether this deployment asks a certificate authority anything.
//
// The demonstration's privacy page says it asks none. That is a published
// promise, and until this file it had no test: a sabotage removing the guard in
// Scan changed nothing anybody could see. These drive both answers, because a
// guard that refuses everywhere is as wrong as one that refuses nowhere.

// revocationServer starts a TLS server whose certificate names a distribution
// point, and returns the host and port to scan.
func revocationServer(t *testing.T, point string) (host, port string) {
	t.Helper()

	// A real chain, not a self-signed leaf. A list is verified against the
	// certificate that issued the leaf, so without an issuer in the chain the
	// check stops before it reaches the network — correctly, and it would make
	// these tests pass for a reason that has nothing to do with what they are
	// about.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Revocation Test CA"},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating an authority: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing an authority: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}

	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(20260911),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"localhost", "denyfirst.dev"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CRLDistributionPoints: []string{point},
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}

	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
	})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
			}()
		}
	}()

	host, port, _ = net.SplitHostPort(l.Addr().String())
	return host, port
}

// watchingFetcher is a revocation fetcher that records whether anything asked
// it to open a connection, and refuses when it does.
//
// atomic because the prober handshakes several versions in parallel and the
// fetch happens on the path they feed; a plain bool written from there and read
// here is a race only the -race build on CI would find.
func watchingFetcher(asked *atomic.Bool) *crl.Fetcher {
	return &crl.Fetcher{
		Timeout: 2 * time.Second,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			asked.Store(true)
			return nil, errors.New("no network in tests")
		},
	}
}

// scanTo scans a name and sends every connection to a local listener.
//
// The name and the address are separate because the demonstration build refuses
// any host outside the list compiled into it, so a test under that tag has to
// scan a name that list allows while still reaching a server this test started.
// The certificate the listener serves carries that name.
func scanTo(t *testing.T, target, dialTo string, fetcher *crl.Fetcher) *Result {
	t.Helper()

	d := &net.Dialer{Timeout: 5 * time.Second}
	s := &Scanner{
		Prober: &tlsprobe.Prober{
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, dialTo)
			},
			TotalTimeout: 20 * time.Second,
		},
		AllowAnyPort:   true,
		AllowIPTargets: true,
		Revocation:     fetcher,
	}

	out, err := s.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return out
}

// A list that established nothing never becomes "not revoked".
//
// The most dangerous answer this check can give. crl reports Unknown for a list
// that could not be fetched, parsed, verified against the issuer, or trusted for
// being inside its own window — and every one of those has to reach a report as
// "not checked" (R4). A sabotage that filled the status in regardless passed
// every test here until this one existed, because the tests watched whether the
// fetch happened and not what was made of it.
func TestAnUnknownListStatusIsNotAnAnswer(t *testing.T) {
	for _, tc := range []struct {
		in   crl.Status
		want string
	}{
		{crl.Unknown, ""},
		{crl.Good, "good"},
		{crl.Revoked, "revoked"},
	} {
		if got := listStatus(tc.in); got != tc.want {
			t.Errorf("listStatus(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
