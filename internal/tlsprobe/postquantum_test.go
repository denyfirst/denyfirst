package tlsprobe

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
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A server whose key exchange this test controls, and a count of every
// connection it received.
func groupServer(t *testing.T, curves []tls.CurveID, max uint16, count *atomic.Int64) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}

	cfg := &tls.Config{
		Certificates:     []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       max,
		CurvePreferences: curves,
	}

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })

	go func() {
		for {
			c, err := raw.Accept()
			if err != nil {
				return
			}
			if count != nil {
				count.Add(1)
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck // a test server
				server := tls.Server(c, cfg)
				_ = server.HandshakeContext(context.Background())
			}(c)
		}
	}()

	_, port, err := net.SplitHostPort(raw.Addr().String())
	if err != nil {
		t.Fatalf("reading the listener address: %v", err)
	}
	return port
}

func proberFor(port string) *Prober {
	var d net.Dialer
	return &Prober{
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		},
		HandshakeTimeout: 3 * time.Second,
		TotalTimeout:     30 * time.Second,
	}
}

// Three answers, and the third is the one that is usually got wrong.
//
// A server that says no and a question that could not be asked are different
// results. Reporting the second as the first would read in the server's
// favour or against it depending on the day, and either way it would be a
// measurement that never happened drawn as one that did.
func TestThePostQuantumQuestionHasThreeAnswers(t *testing.T) {
	cases := []struct {
		name     string
		curves   []tls.CurveID
		max      uint16
		measured bool
		offered  bool
		reason   string
	}{
		{
			name:     "a server that takes the hybrid",
			curves:   []tls.CurveID{tls.X25519MLKEM768},
			max:      tls.VersionTLS13,
			measured: true,
			offered:  true,
		},
		{
			name:     "a server with classical groups only",
			curves:   []tls.CurveID{tls.X25519, tls.CurveP256},
			max:      tls.VersionTLS13,
			measured: true,
			offered:  false,
		},
		{
			name:     "a server with no TLS 1.3, where the question does not exist",
			curves:   nil,
			max:      tls.VersionTLS12,
			measured: false,
			offered:  false,
			reason:   "TLS 1.3",
		},
	}

	for _, c := range cases {
		port := groupServer(t, c.curves, c.max, nil)
		report, err := proberFor(port).Probe(context.Background(), "localhost", port)
		if err != nil {
			t.Fatalf("%s: probing: %v", c.name, err)
		}

		got := report.PostQuantum
		if got.Measured != c.measured || got.Offered != c.offered {
			t.Errorf("%s: measured=%v offered=%v, want measured=%v offered=%v (reason %q)",
				c.name, got.Measured, got.Offered, c.measured, c.offered, got.Reason)
		}
		if c.reason != "" && !strings.Contains(got.Reason, c.reason) {
			t.Errorf("%s: the reason does not mention %q: %q", c.name, c.reason, got.Reason)
		}
		if got.Measured && got.Reason != "" {
			t.Errorf("%s: something was measured and a reason for not measuring was given anyway: %q",
				c.name, got.Reason)
		}
		if c.measured && got.Group != "X25519MLKEM768" {
			t.Errorf("%s: the group is not named: %q", c.name, got.Group)
		}
	}
}

// What the answer costs the server it is asked of.
//
// One handshake, and only where the question exists. A server with no TLS 1.3
// is not asked at all, which is the difference between a measurement that is
// cheap and one that is free.
func TestThePostQuantumQuestionCostsOneHandshake(t *testing.T) {
	var with, without atomic.Int64

	port := groupServer(t, nil, tls.VersionTLS13, &with)
	if _, err := proberFor(port).Probe(context.Background(), "localhost", port); err != nil {
		t.Fatalf("probing: %v", err)
	}

	old := groupServer(t, nil, tls.VersionTLS12, &without)
	if _, err := proberFor(old).Probe(context.Background(), "localhost", old); err != nil {
		t.Fatalf("probing: %v", err)
	}

	t.Logf("a TLS 1.3 server received %d connections; a TLS 1.2 server received %d",
		with.Load(), without.Load())

	// Exactly one, and the comparison is clean: both servers get the same
	// four version probes, the same TLS 1.2 enumeration and the same two
	// ordering probes, so everything except the question cancels. Asserting
	// the difference rather than the total, because the total moves whenever
	// Go changes which suites it offers and that is not a change in what
	// this costs anybody.
	if got := with.Load() - without.Load(); got != 1 {
		t.Errorf("the question cost %d connections; it is meant to cost one (%d against %d)",
			got, with.Load(), without.Load())
	}
}
