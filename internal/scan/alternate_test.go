package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

// A weakness reachable only by an old client is a weakness.
//
// A server chooses its certificate from what the client offered, so the chain
// an old client is handed can be a different one — and the one kept for old
// clients is the one most likely to be weak. This report described the newest
// handshake alone, so a small-key or SHA-1 certificate sitting behind TLS 1.0
// went entirely unreported beside a clean modern chain.
//
// R5 settles it. An attacker chooses which version to negotiate, so a chain
// reachable at any version is a chain reachable, and the worse of the two has
// to set the verdict.
func TestAWeakCertificateBehindAnOldVersionIsGraded(t *testing.T) {
	// A demonstration build reaches only the hosts this project owns, and
	// this test scans one it does not. What is under test here is the tool,
	// and the demonstration build is the tool with a list — the list is
	// covered by its own tests under the same tag.
	if Demo {
		t.Skip("a demonstration build does not scan this host")
	}

	modern := selfSignedECDSA(t)
	legacy := selfSignedSmallRSA(t)

	host, port := serverByVersion(t, modern, legacy)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	s := &Scanner{
		Prober:         &tlsprobe.Prober{Dial: (&net.Dialer{}).DialContext},
		AllowAnyPort:   true,
		AllowIPTargets: true,
	}

	result, err := s.Scan(ctx, net.JoinHostPort(host, port))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(result.AlternateCertificates) != 1 {
		t.Fatalf("%d alternate certificates, want 1; the chain an old client is given was not graded",
			len(result.AlternateCertificates))
	}

	var ids []string
	for _, f := range result.Findings() {
		ids = append(ids, f.RuleID)
	}
	if !slices.Contains(ids, "cert.rsa-key-too-small") {
		t.Errorf("findings are %v; the 1024-bit key served to old clients is not among them", ids)
	}

	// The modern chain has no such key, so the finding can only have come
	// from the alternate. Its own findings must be there too.
	if result.Certificate == nil || result.Certificate.Chain[0].KeyBits != 256 {
		t.Fatal("the certificate section no longer describes the newest handshake's chain")
	}
}

func selfSignedECDSA(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	return certificateFor(t, 11, &key.PublicKey, key)
}

func selfSignedSmallRSA(t *testing.T) *tls.Certificate {
	t.Helper()
	// 1024 bits: below every current minimum, and the point of the fixture.
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	return certificateFor(t, 12, &key.PublicKey, key)
}

func certificateFor(t *testing.T, serial int64, pub, signer any) *tls.Certificate {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, signer)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: signer}
}

// serverByVersion answers TLS 1.2 with one certificate and anything older
// with another, which is what selection by offered signature algorithms does.
func serverByVersion(t *testing.T, modern, legacy *tls.Certificate) (host, port string) {
	t.Helper()

	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			for _, v := range hello.SupportedVersions {
				if v >= tls.VersionTLS12 {
					return modern, nil
				}
			}
			return legacy, nil
		},
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

// The issuer is found by signature, not by position.
//
// This used to be chain[1], on the reasoning that a server sends its chain
// leaf first. Most do, and RFC 8446 dropped the requirement: a TLS 1.3 sender
// SHOULD order the chain and a receiver MAY accept any order.
//
// Getting it wrong does not fail quietly. Every OCSP check is against the
// issuer, so a response about a perfectly good certificate would fail to match
// and be reported as cert.staple-unverifiable — a Weak finding against a
// server doing everything right, which a reader cannot tell from a real one.
func TestTheIssuerIsFoundWhereverItSitsInTheChain(t *testing.T) {
	root := newTestCA(t, "Root CA")
	other := newTestCA(t, "Unrelated CA")
	leaf := root.sign(t, 5150)

	cases := map[string][]*x509.Certificate{
		"the usual order":         {leaf, root.cert},
		"an unrelated cert first": {leaf, other.cert, root.cert},
		"the issuer last":         {leaf, other.cert, other.cert, root.cert},
	}

	for name, chain := range cases {
		got := issuerOf(leaf, chain)
		if got == nil {
			t.Errorf("%s: no issuer found; a stapled response would be called unverifiable", name)
			continue
		}
		if !got.Equal(root.cert) {
			t.Errorf("%s: found %q, want %q", name, got.Subject.CommonName, root.cert.Subject.CommonName)
		}
	}

	// A chain that really does not carry the issuer has to say so rather than
	// return whatever was nearby.
	if got := issuerOf(leaf, []*x509.Certificate{leaf, other.cert}); got != nil {
		t.Errorf("an unrelated certificate was returned as the issuer: %q", got.Subject.CommonName)
	}
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating %s: %v", name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return testCA{cert: cert, key: key}
}

func (c testCA) sign(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "leaf.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"leaf.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the leaf: %v", err)
	}
	return cert
}
