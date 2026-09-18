package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/demo"
	"github.com/denyfirst/porch/internal/policy"
	"github.com/denyfirst/porch/internal/tlsprobe"
)

// oneSuiteUnanswered closes a connection whose hello offers exactly the one
// suite given — a server that goes silent for one question in the middle of an
// enumeration, the way a rate limit or a middlebox does.
type oneSuiteUnanswered struct {
	net.Conn
	suite   uint16
	checked bool
}

func (c *oneSuiteUnanswered) Write(b []byte) (int, error) {
	if !c.checked {
		c.checked = true
		if len(b) > 5+4+35 {
			body := b[9:]
			sid := int(body[34])
			rest := body[35+sid:]
			if len(rest) >= 4 && binary.BigEndian.Uint16(rest) == 2 && binary.BigEndian.Uint16(rest[2:]) == c.suite {
				_ = c.Conn.Close()
				return 0, net.ErrClosed
			}
		}
	}
	return c.Conn.Write(b)
}

// tls13Server serves a TLS 1.3-only listener with the certificate given.
func tls13Server(t *testing.T, cert *tls.Certificate) string {
	t.Helper()
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
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
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
			}()
		}
	}()
	return l.Addr().String()
}

// A scan whose suite list did not finish is not strong, however sound the
// certificate is.
//
// tlsprobe returns Ungraded for the transport, and policy.Worst passes over
// Ungraded, so joining it with a strong certificate made the whole report
// strong — the claim an unfinished list cannot support (R11). The audit of
// 2026-09-16 (A10) showed the join; this shows the whole scan, both ways.
func TestAnUnfinishedTransportDoesNotEndStrong(t *testing.T) {
	if demo.Enabled {
		t.Skip("a demonstration build does not scan this host")
	}
	root, leaf := soundChain(t)
	addr := tls13Server(t, leaf)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	scan := func(silent bool) *Result {
		t.Helper()
		d := &net.Dialer{Timeout: 3 * time.Second}
		s := &Scanner{
			Prober: &tlsprobe.Prober{
				HandshakeTimeout: 3 * time.Second,
				TotalTimeout:     30 * time.Second,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					conn, err := d.DialContext(ctx, network, addr)
					if err != nil || !silent {
						return conn, err
					}
					// TLS_AES_128_CCM_8_SHA256, which Go's server does not
					// offer and a real one might: asked and never answered.
					return &oneSuiteUnanswered{Conn: conn, suite: 0x1305}, nil
				},
			},
			AllowAnyPort:   true,
			AllowIPTargets: true,
			Roots:          roots,
			Revocation:     watchingFetcher(new(atomic.Bool)),
		}
		out, err := s.Scan(context.Background(), addr)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		return out
	}

	if got := scan(false); got.Verdict != policy.Strong {
		t.Fatalf("an undisturbed scan of a sound TLS 1.3 server is %q; this test needs it strong (findings %v)",
			got.Verdict, got.Findings())
	}

	got := scan(true)
	if got.Certificate == nil || got.Certificate.Verdict != policy.Strong {
		t.Fatalf("the certificate is not strong in the interrupted scan; this test needs it to be")
	}
	if got.Verdict == policy.Strong {
		t.Error("a scan whose TLS 1.3 suite list did not finish was reported strong")
	}
	if got.Verdict != policy.Ungraded {
		t.Errorf("verdict %q, want ungraded: nothing was shown to be wrong, and the measurement did not finish", got.Verdict)
	}
}

// Only strong is withdrawn: a finding that was seen stays seen.
func TestAnUnfinishedTransportKeepsWhatItFound(t *testing.T) {
	unfinished := &tlsprobe.Report{Versions: []tlsprobe.VersionResult{{Supported: true}}}
	finished := &tlsprobe.Report{Versions: []tlsprobe.VersionResult{{Supported: true, CipherListComplete: true}}}
	refused := &tlsprobe.Report{Versions: []tlsprobe.VersionResult{{Refused: true}}}

	if !transportUnfinished(unfinished) {
		t.Error("an accepted version with an unfinished list is not unfinished")
	}
	if transportUnfinished(finished) || transportUnfinished(refused) || transportUnfinished(nil) {
		t.Error("a finished, refused or absent transport was called unfinished")
	}
}

// soundChain is a root and one leaf under it that nothing in the certificate
// rules marks down: a random serial, a lifetime well inside the limit and well
// clear of expiry.
func soundChain(t *testing.T) (*x509.Certificate, *tls.Certificate) {
	t.Helper()
	serial := func() *big.Int {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
		if err != nil {
			t.Fatal(err)
		}
		return n.Add(n, new(big.Int).Lsh(big.NewInt(1), 100))
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "denyfirst scan sound root"},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().AddDate(5, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, 60),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, root, leafKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return root, &tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}
}

// Settling an unfinished scan withdraws strong and nothing else. A sabotage
// withdrawing every verdict escaped on 2026-09-16: the whole-scan test above
// only ever sees strong.
func TestSettlingWithdrawsOnlyStrong(t *testing.T) {
	unfinished := &tlsprobe.Report{Versions: []tlsprobe.VersionResult{{Supported: true}}}
	finished := &tlsprobe.Report{Versions: []tlsprobe.VersionResult{{Supported: true, CipherListComplete: true}}}

	for v, want := range map[policy.Verdict]policy.Verdict{
		policy.Strong:   policy.Ungraded,
		policy.Weak:     policy.Weak,
		policy.Insecure: policy.Insecure,
		policy.Ungraded: policy.Ungraded,
	} {
		if got := settle(v, unfinished); got != want {
			t.Errorf("an unfinished scan at %q settled to %q, want %q", v, got, want)
		}
		if got := settle(v, finished); got != v {
			t.Errorf("a finished scan at %q settled to %q", v, got)
		}
	}
}
