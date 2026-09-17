package tlsprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

// One leaf with another intermediate is another chain.
//
// A server keeping a SHA-1 cross-sign for old clients hands them the same leaf
// over a different path. Compared by the leaf alone, that chain was never seen
// (audit A19).
func TestTheSameLeafOverAnotherPathIsAnotherChain(t *testing.T) {
	modern, other := twoCertificates(t)
	legacy := *modern
	legacy.Certificate = append([][]byte{modern.Certificate[0]}, other.Certificate[0])

	host, port := serverServingByVersion(t, modern, &legacy)
	report, err := (&Prober{Dial: (&net.Dialer{}).DialContext}).Probe(context.Background(), host, port)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(report.AlternateChains) != 1 {
		t.Fatalf("%d alternate chains, want the one with the other path", len(report.AlternateChains))
	}
	if got := len(report.AlternateChains[0].Certificates); got != 2 {
		t.Errorf("the alternate chain holds %d certificates, want 2", got)
	}
}

// chainSum tells chains apart by every certificate and where each ends.
func TestAChainDigestCoversEveryCertificateInOrder(t *testing.T) {
	a, b := twoCertificates(t)
	ca := parsed(t, a)
	cb := parsed(t, b)

	if chainSum(ca) == chainSum(append(ca, cb...)) {
		t.Error("adding an intermediate does not change the digest")
	}
	if chainSum(append(ca, cb...)) == chainSum(append(cb, ca...)) {
		t.Error("the order of a chain does not change the digest")
	}
	if chainSum(ca) != chainSum(parsed(t, a)) {
		t.Error("the same chain gives two digests")
	}
}

// No report claims an application protocol it never asked about.
func TestNoApplicationProtocolIsReported(t *testing.T) {
	only, _ := twoCertificates(t)
	host, port := serverServingByVersion(t, only, only)
	report, err := (&Prober{Dial: (&net.Dialer{}).DialContext}).Probe(context.Background(), host, port)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(body)), `"alpn"`) {
		t.Errorf("the report names an application protocol no handshake offered: %s", body)
	}
}

func parsed(t *testing.T, c *tls.Certificate) []*x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return []*x509.Certificate{cert}
}

// A whole chain served the same at every version is one chain, not two.
func TestTheSameWholeChainEverywhereIsNoAlternate(t *testing.T) {
	leaf, other := twoCertificates(t)
	chain := *leaf
	chain.Certificate = append([][]byte{leaf.Certificate[0]}, other.Certificate[0])

	host, port := serverServingByVersion(t, &chain, &chain)
	report, err := (&Prober{Dial: (&net.Dialer{}).DialContext}).Probe(context.Background(), host, port)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(report.AlternateChains) != 0 {
		t.Errorf("%d alternate chains for a server with one chain", len(report.AlternateChains))
	}
}

// Two certificates are not the one certificate their bytes would make joined.
func TestAChainDigestKnowsWhereEachCertificateEnds(t *testing.T) {
	a := &x509.Certificate{Raw: []byte("first-")}
	b := &x509.Certificate{Raw: []byte("second")}
	joined := &x509.Certificate{Raw: []byte("first-second")}
	if chainSum([]*x509.Certificate{a, b}) == chainSum([]*x509.Certificate{joined}) {
		t.Error("two certificates and their concatenation share a digest")
	}
}
