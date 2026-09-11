package crl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Everything this package reads was chosen by somebody else: the address by the
// scanned server's certificate, the bytes by whoever answered that address. The
// tests are written from that direction.

var refNow = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

// authority is a signing certificate and its key.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newAuthority(t *testing.T, name string) authority {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             refNow.Add(-24 * time.Hour),
		NotAfter:              refNow.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating an authority: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing an authority: %v", err)
	}
	return authority{cert: cert, key: key}
}

// newLeaf issues a certificate naming the given distribution points.
func newLeaf(t *testing.T, by authority, serial *big.Int, points ...string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "leaf.example"},
		NotBefore:             refNow.Add(-time.Hour),
		NotAfter:              refNow.Add(time.Hour),
		CRLDistributionPoints: points,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, by.cert, &key.PublicKey, by.key)
	if err != nil {
		t.Fatalf("issuing a leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing a leaf: %v", err)
	}
	return cert
}

// listOpts describes the revocation list a test wants served.
type listOpts struct {
	revoked    []*big.Int
	thisUpdate time.Time
	nextUpdate time.Time
	pad        int
}

// signedList builds a revocation list signed by an authority.
func signedList(t *testing.T, by authority, opts listOpts) []byte {
	t.Helper()

	if opts.thisUpdate.IsZero() {
		opts.thisUpdate = refNow.Add(-time.Hour)
	}
	if opts.nextUpdate.IsZero() {
		opts.nextUpdate = refNow.Add(time.Hour)
	}

	entries := make([]x509.RevocationListEntry, 0, len(opts.revoked)+opts.pad)
	for _, serial := range opts.revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: refNow.Add(-2 * time.Hour),
			ReasonCode:     1, // keyCompromise
		})
	}
	// Padding, so a test can make a list larger than the cap.
	for i := 0; i < opts.pad; i++ {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(int64(1_000_000 + i)),
			RevocationTime: refNow.Add(-2 * time.Hour),
		})
	}

	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                opts.thisUpdate,
		NextUpdate:                opts.nextUpdate,
		RevokedCertificateEntries: entries,
	}, by.cert, by.key)
	if err != nil {
		t.Fatalf("creating a revocation list: %v", err)
	}
	return der
}

// serving starts a server handing out one body, and a fetcher that reaches it
// whatever address is dialled.
func serving(t *testing.T, body []byte, status int) (*Fetcher, string) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	addr := srv.Listener.Addr().String()
	f := &Fetcher{
		Timeout: 5 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
	}
	return f, "http://lists.example/one.crl"
}

// A certificate named on a list its issuer signed is revoked.
func TestACertificateOnTheListIsRevoked(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	serial := big.NewInt(4242)
	leaf := newLeaf(t, ca, serial, "http://lists.example/one.crl")

	f, point := serving(t, signedList(t, ca, listOpts{revoked: []*big.Int{serial}}), http.StatusOK)
	leaf.CRLDistributionPoints = []string{point}

	got := f.Check(context.Background(), leaf, ca.cert, refNow)
	if got.Status != Revoked {
		t.Fatalf("status is %s (%s), want revoked", got.Status, got.Reason)
	}
	if got.RevokedAt.IsZero() {
		t.Error("no revocation time was reported")
	}
	if got.ReasonCode != 1 {
		t.Errorf("reason code is %d, want 1", got.ReasonCode)
	}
}

// And one that is not named is good, with the window it was judged in.
func TestACertificateNotOnTheListIsGood(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := newLeaf(t, ca, big.NewInt(4242), "http://lists.example/one.crl")

	f, point := serving(t, signedList(t, ca, listOpts{revoked: []*big.Int{big.NewInt(7)}}), http.StatusOK)
	leaf.CRLDistributionPoints = []string{point}

	got := f.Check(context.Background(), leaf, ca.cert, refNow)
	if got.Status != Good {
		t.Fatalf("status is %s (%s), want good", got.Status, got.Reason)
	}
	if got.ThisUpdate.IsZero() || got.NextUpdate.IsZero() {
		t.Error("the window the list claims for itself was not reported, so a report cannot " +
			"say how old the answer is")
	}
}

// A list nobody trustworthy signed decides nothing.
//
// The test this package exists for. A distribution point is fetched over plain
// HTTP from an address the scanned server's certificate named, so whoever can
// answer that request can hand back any bytes they like. Without the signature
// check they could report a sound certificate as revoked — or, far worse, a
// revoked one as sound.
func TestAListTheIssuerDidNotSignIsRefused(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	impostor := newAuthority(t, "Somebody Else")

	serial := big.NewInt(4242)
	leaf := newLeaf(t, ca, serial, "http://lists.example/one.crl")

	// The impostor says this certificate is revoked. It is not their list to
	// make.
	f, point := serving(t, signedList(t, impostor, listOpts{revoked: []*big.Int{serial}}), http.StatusOK)
	leaf.CRLDistributionPoints = []string{point}

	got := f.Check(context.Background(), leaf, ca.cert, refNow)
	if got.Status != Unknown {
		t.Fatalf("status is %s, want unknown: a list signed by somebody other than the issuer "+
			"was believed", got.Status)
	}
	if !strings.Contains(got.Reason, "not signed by the issuing authority") {
		t.Errorf("reason is %q, and it has to say the signature was the problem", got.Reason)
	}
}

// A list past its own window is not an answer.
func TestAStaleListIsNotAnAnswer(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := newLeaf(t, ca, big.NewInt(4242), "http://lists.example/one.crl")

	stale := signedList(t, ca, listOpts{
		thisUpdate: refNow.Add(-72 * time.Hour),
		nextUpdate: refNow.Add(-48 * time.Hour),
	})
	f, point := serving(t, stale, http.StatusOK)
	leaf.CRLDistributionPoints = []string{point}

	got := f.Check(context.Background(), leaf, ca.cert, refNow)
	if got.Status != Unknown {
		t.Fatalf("status is %s, want unknown: absence from a list the authority has already "+
			"replaced says nothing about now", got.Status)
	}
	if !strings.Contains(got.Reason, "older than the authority said") {
		t.Errorf("reason is %q", got.Reason)
	}
}

// And one that has not taken effect yet is not one either.
func TestAListNotYetInEffectIsNotAnAnswer(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := newLeaf(t, ca, big.NewInt(4242), "http://lists.example/one.crl")

	future := signedList(t, ca, listOpts{
		thisUpdate: refNow.Add(24 * time.Hour),
		nextUpdate: refNow.Add(48 * time.Hour),
	})
	f, point := serving(t, future, http.StatusOK)
	leaf.CRLDistributionPoints = []string{point}

	if got := f.Check(context.Background(), leaf, ca.cert, refNow); got.Status != Unknown {
		t.Fatalf("status is %s, want unknown", got.Status)
	}
}

// A list larger than the cap is refused rather than cut and read.
//
// The direction of this failure is what makes the cap matter. Every serial is
// absent from a truncated list, and absence is exactly what "not revoked" is
// read from — so a list cut at the cap answers "good" about a revoked
// certificate, which is the one wrong answer this check must never give.
func TestAnOversizedListIsRefusedRatherThanTruncated(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	serial := big.NewInt(4242)
	leaf := newLeaf(t, ca, serial, "http://lists.example/one.crl")

	// Served bytes beyond the cap. Not a real list: what is asserted is that
	// nothing past the cap is parsed at all.
	huge := make([]byte, maxList+1024)
	f, point := serving(t, huge, http.StatusOK)
	leaf.CRLDistributionPoints = []string{point}

	got := f.Check(context.Background(), leaf, ca.cert, refNow)
	if got.Status != Unknown {
		t.Fatalf("status is %s, want unknown", got.Status)
	}
	if !strings.Contains(got.Reason, "larger than this fetches") {
		t.Errorf("reason is %q", got.Reason)
	}
}

// A serial is compared as a number, not as bytes.
//
// The same integer is encoded with or without a leading zero byte depending on
// whether its top bit is set. Comparing encodings reports a revoked certificate
// as sound for every serial above 0x7f, which is most of them — and it would
// pass every test written with small numbers.
func TestASerialIsComparedAsANumber(t *testing.T) {
	// 0x80 needs a leading zero byte to encode as positive, so its DER form
	// differs from the raw big-endian bytes.
	serial := big.NewInt(0x80)

	ca := newAuthority(t, "Test CA")
	leaf := newLeaf(t, ca, serial, "http://lists.example/one.crl")

	f, point := serving(t, signedList(t, ca, listOpts{revoked: []*big.Int{big.NewInt(0x80)}}), http.StatusOK)
	leaf.CRLDistributionPoints = []string{point}

	if got := f.Check(context.Background(), leaf, ca.cert, refNow); got.Status != Revoked {
		t.Fatalf("status is %s (%s), want revoked: a high-bit serial was not matched", got.Status, got.Reason)
	}
}

// An address this does not fetch is refused rather than dialled.
func TestOnlyHTTPAddressesAreFetched(t *testing.T) {
	for _, point := range []string{
		"ldap://directory.example/cn=CRL",
		"ftp://files.example/one.crl",
		"file:///etc/passwd",
		"gopher://example",
		"",
		"http://",
	} {
		if _, ok := usable(point); ok {
			t.Errorf("usable(%q) said yes; a certificate names this address and following one "+
				"means speaking a protocol the scanned party chose", point)
		}
	}

	for _, point := range []string{
		"http://lists.example/one.crl",
		"https://lists.example/one.crl",
	} {
		if _, ok := usable(point); !ok {
			t.Errorf("usable(%q) said no", point)
		}
	}
}

// Credentials in a distribution point are not sent.
func TestCredentialsInADistributionPointAreStripped(t *testing.T) {
	got, ok := usable("http://user:secret@lists.example/one.crl")
	if !ok {
		t.Fatal("the address was refused outright")
	}
	if strings.Contains(got, "secret") || strings.Contains(got, "user") {
		t.Errorf("credentials survived into %q, and would reach the access log of whatever "+
			"answered", got)
	}
}

// A certificate naming nothing is answered in words.
func TestACertificateNamingNoListSaysSo(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := newLeaf(t, ca, big.NewInt(4242))

	got := (&Fetcher{}).Check(context.Background(), leaf, ca.cert, refNow)
	if got.Status != Unknown {
		t.Fatalf("status is %s, want unknown", got.Status)
	}
	if !strings.Contains(got.Reason, "names no revocation list") {
		t.Errorf("reason is %q", got.Reason)
	}
}

// Without the issuer there is nothing to verify against, so there is no answer.
func TestWithoutTheIssuerThereIsNoAnswer(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := newLeaf(t, ca, big.NewInt(4242), "http://lists.example/one.crl")

	got := (&Fetcher{}).Check(context.Background(), leaf, nil, refNow)
	if got.Status != Unknown {
		t.Fatalf("status is %s, want unknown", got.Status)
	}
	if !strings.Contains(got.Reason, "issuing certificate was not sent") {
		t.Errorf("reason is %q", got.Reason)
	}
}

// A server that answers with something other than 200 establishes nothing.
func TestAListThatWasNotServedEstablishesNothing(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := newLeaf(t, ca, big.NewInt(4242), "http://lists.example/one.crl")

	f, point := serving(t, nil, http.StatusNotFound)
	leaf.CRLDistributionPoints = []string{point}

	if got := f.Check(context.Background(), leaf, ca.cert, refNow); got.Status != Unknown {
		t.Fatalf("status is %s, want unknown", got.Status)
	}
}

// Bytes that are not a list are not read as one.
func TestSomethingThatIsNotAListIsNotParsedAsOne(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	leaf := newLeaf(t, ca, big.NewInt(4242), "http://lists.example/one.crl")

	f, point := serving(t, []byte("<html>not a revocation list</html>"), http.StatusOK)
	leaf.CRLDistributionPoints = []string{point}

	got := f.Check(context.Background(), leaf, ca.cert, refNow)
	if got.Status != Unknown {
		t.Fatalf("status is %s, want unknown", got.Status)
	}
	if !strings.Contains(got.Reason, "could not be parsed") {
		t.Errorf("reason is %q", got.Reason)
	}
}

// No reason names a resolver, an address or a Go type.
//
// These strings reach a report, and a report is read by whoever asked for the
// scan (I6).
func TestNoReasonDescribesTheMachine(t *testing.T) {
	ca := newAuthority(t, "Test CA")

	reasons := []string{
		(&Fetcher{}).Check(context.Background(), nil, nil, refNow).Reason,
		(&Fetcher{}).Check(context.Background(), newLeaf(t, ca, big.NewInt(1)), ca.cert, refNow).Reason,
	}

	// A point that cannot be dialled: the address is refused before any
	// connection, and the reason must not repeat it.
	leaf := newLeaf(t, ca, big.NewInt(1), "ldap://directory.internal/cn=CRL")
	reasons = append(reasons, (&Fetcher{}).Check(context.Background(), leaf, ca.cert, refNow).Reason)

	for _, reason := range reasons {
		if reason == "" {
			t.Error("a status of unknown came back with no reason, so a report can only say " +
				"that nothing was established and not why")
			continue
		}
		for _, leak := range []string{"directory.internal", "dial ", "tcp ", "x509:", "0x", "*x509."} {
			if strings.Contains(reason, leak) {
				t.Errorf("the reason contains %q: %s", leak, reason)
			}
		}
	}
}

// The default dialler is the one that refuses the network this runs in.
//
// The address comes from the scanned server's certificate. A distribution point
// reading http://10.0.0.1/ is that server aiming this scanner at the operator's
// own network, and the guard against it must not be something a caller has to
// remember to pass.
func TestTheDefaultDiallerRefusesPrivateAddresses(t *testing.T) {
	ca := newAuthority(t, "Test CA")
	serial := big.NewInt(4242)

	// A server on loopback that would answer, serving a list this issuer
	// really signed. The first version of this test pointed at a port nothing
	// was listening on, so "safedial refused" and "nothing answered" were the
	// same Unknown — and a sabotage replacing safedial with a plain dialler
	// passed it. Something has to be there for the refusal to mean anything.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(signedList(t, ca, listOpts{revoked: []*big.Int{serial}}))
	}))
	defer srv.Close()

	leaf := newLeaf(t, ca, serial, "http://"+srv.Listener.Addr().String()+"/one.crl")

	// No Dial, so the default is the one that decides.
	got := (&Fetcher{Timeout: 2 * time.Second}).Check(context.Background(), leaf, ca.cert, refNow)

	if got.Status == Revoked {
		t.Fatal("the default dialler reached a loopback distribution point. The address comes " +
			"from the scanned server's certificate, so that server can aim this scanner at the " +
			"network it runs in")
	}
	if got.Status != Unknown {
		t.Fatalf("status is %s, want unknown", got.Status)
	}
}
