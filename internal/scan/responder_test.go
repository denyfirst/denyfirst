package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- building the CertID RFC 6960 specifies.
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/denyfirst/internal/demo"
	"github.com/denyfirst/denyfirst/internal/ocspquery"
	"github.com/denyfirst/denyfirst/internal/tlsprobe"
)

// responderChain is an authority, a leaf it issued naming a responder, and a
// TLS listener serving the pair.
type responderChain struct {
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	leaf   *x509.Certificate
	listen string
}

func newResponderChain(t *testing.T, responder string) responderChain {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Responder Test CA"},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(20260914), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames:    []string{"localhost", "denyfirst.dev"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		OCSPServer: []string{responder},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)

	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der, caDER}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	return responderChain{ca: ca, caKey: caKey, leaf: leaf, listen: l.Addr().String()}
}

// revokedResponse is the answer the authority's responder gives about the leaf:
// revoked, signed by the authority, current. Written here with the RFC 6960
// shapes rather than borrowed, because internal/ocsp's builder is its own.
func (c responderChain) revokedResponse(t *testing.T) []byte {
	t.Helper()
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.ca.RawSubjectPublicKeyInfo, &spki); err != nil {
		t.Fatal(err)
	}
	nameHash := sha1.Sum(c.ca.RawSubject)            // #nosec G401
	keyHash := sha1.Sum(spki.PublicKey.RightAlign()) // #nosec G401

	type certID struct {
		HashAlgorithm  pkix.AlgorithmIdentifier
		IssuerNameHash []byte
		IssuerKeyHash  []byte
		SerialNumber   *big.Int
	}
	type revokedInfo struct {
		RevocationTime time.Time `asn1:"generalized"`
	}
	type single struct {
		CertID     certID
		Status     asn1.RawValue
		ThisUpdate time.Time `asn1:"generalized"`
		NextUpdate time.Time `asn1:"generalized,optional,explicit,tag:0"`
	}
	type data struct {
		ResponderID asn1.RawValue
		ProducedAt  time.Time `asn1:"generalized"`
		Responses   []single
	}

	now := time.Now().UTC().Truncate(time.Second)
	info, err := asn1.Marshal(revokedInfo{RevocationTime: now.Add(-48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := asn1.Marshal(data{
		ResponderID: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: c.ca.RawSubject},
		ProducedAt:  now.Add(-time.Hour),
		Responses: []single{{
			CertID: certID{
				HashAlgorithm:  pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}},
				IssuerNameHash: nameHash[:], IssuerKeyHash: keyHash[:], SerialNumber: c.leaf.SerialNumber,
			},
			Status:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: info[2:]},
			ThisUpdate: now.Add(-time.Hour),
			NextUpdate: now.Add(72 * time.Hour),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, c.caKey, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	basic, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{
		TBS:       asn1.RawValue{FullBytes: tbs},
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		Signature: asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	type responseBytes struct {
		ResponseType asn1.ObjectIdentifier
		Response     []byte
	}
	out, err := asn1.Marshal(struct {
		Status   asn1.Enumerated
		Response responseBytes `asn1:"explicit,tag:0"`
	}{Response: responseBytes{ResponseType: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}, Response: basic}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A scan given a responder asks it, and what it verifies reaches the report.
//
// Two sabotages escaped every test on 2026-09-14 before this: Scan never asking,
// and Scan asking and dropping the status. The fetcher and the rule were each
// tested alone, and nothing ran a whole scan with a responder that answered.
func TestAScanGivenAResponderAsksItAndReportsWhatItVerified(t *testing.T) {
	if demo.Enabled {
		t.Skip("the demonstration build compiles the question out")
	}

	var asked atomic.Bool
	var chain responderChain
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Store(true)
		_, _ = w.Write(chain.revokedResponse(t))
	}))
	defer srv.Close()
	chain = newResponderChain(t, "http://ocsp.responder.test/")

	responderAddr := strings.TrimPrefix(srv.URL, "http://")
	d := &net.Dialer{Timeout: 5 * time.Second}
	var listAsked atomic.Bool
	s := &Scanner{
		Prober: &tlsprobe.Prober{
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, chain.listen)
			},
			TotalTimeout: 20 * time.Second,
		},
		AllowAnyPort:   true,
		AllowIPTargets: true,
		Revocation:     watchingFetcher(&listAsked),
		Responder: &ocspquery.Fetcher{
			Timeout: 3 * time.Second,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, responderAddr)
			},
		},
	}

	out, err := s.Scan(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !asked.Load() {
		t.Fatal("a scan given a responder never asked it")
	}
	if out.Stapling == nil {
		t.Fatal("the report carries no revocation grading")
	}
	revoked := false
	for _, f := range out.Stapling.Findings {
		revoked = revoked || f.RuleID == "cert.revoked"
	}
	if !revoked {
		t.Errorf("the responder verifiably said revoked and the report raises no cert.revoked: %+v", out.Stapling.Findings)
	}
	if !strings.Contains(out.RevocationLine, "asked directly") {
		t.Errorf("the revocation line does not say the responder answered: %q", out.RevocationLine)
	}
}

// A scan given no responder asks none — the other direction, and the one every
// deployment but a flagged command line depends on.
func TestAScanGivenNoResponderAsksNone(t *testing.T) {
	if demo.Enabled {
		t.Skip("the demonstration build compiles the question out")
	}
	chain := newResponderChain(t, "http://ocsp.responder.test/")
	d := &net.Dialer{Timeout: 5 * time.Second}
	var listAsked atomic.Bool
	s := &Scanner{
		Prober: &tlsprobe.Prober{
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, chain.listen)
			},
			TotalTimeout: 20 * time.Second,
		},
		AllowAnyPort: true, AllowIPTargets: true,
		Revocation: watchingFetcher(&listAsked),
	}
	out, err := s.Scan(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if strings.Contains(out.RevocationLine, "asked directly") {
		t.Errorf("a scan that was given no responder says it asked one: %q", out.RevocationLine)
	}
}
