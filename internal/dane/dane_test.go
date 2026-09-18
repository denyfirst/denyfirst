package dane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/dnsclient"
)

const exchanger = "mx.example.test"

var now = time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

// pki is an anchor and a leaf it issued.
type pki struct {
	anchor, leaf *x509.Certificate
}

type dates struct {
	anchorFrom, anchorUntil, leafFrom, leafUntil time.Time
}

func current() dates {
	return dates{now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0), now.AddDate(0, -1, 0), now.AddDate(0, 2, 0)}
}

func issue(t *testing.T, leafName string, d dates) pki {
	t.Helper()
	return issueFor(t, leafName, d, nil)
}

// issueFor is issue with the leaf's extended key usages named.
func issueFor(t *testing.T, leafName string, d dates, eku []x509.ExtKeyUsage) pki {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating a key: %v", err)
		}
		return k
	}
	anchorKey, leafKey := key(), key()

	anchorTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Mail Anchor"},
		NotBefore: d.anchorFrom, NotAfter: d.anchorUntil,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	anchorDER, err := x509.CreateCertificate(rand.Reader, anchorTpl, anchorTpl, &anchorKey.PublicKey, anchorKey)
	if err != nil {
		t.Fatalf("creating the anchor: %v", err)
	}
	anchor, _ := x509.ParseCertificate(anchorDER)

	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: leafName},
		DNSNames:  []string{leafName},
		NotBefore: d.leafFrom, NotAfter: d.leafUntil,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, anchor, &leafKey.PublicKey, anchorKey)
	if err != nil {
		t.Fatalf("creating the leaf: %v", err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	return pki{anchor: anchor, leaf: leaf}
}

// record publishes a binding to one certificate.
func record(usage, selector, matching uint8, c *x509.Certificate) dnsclient.TLSA {
	content := c.Raw
	if selector == SelectorPublicKey {
		content = c.RawSubjectPublicKeyInfo
	}
	data := content
	switch matching {
	case MatchingSHA256:
		sum := sha256.Sum256(content)
		data = sum[:]
	case MatchingSHA512:
		sum := sha512.Sum512(content)
		data = sum[:]
	}
	return dnsclient.TLSA{Usage: usage, Selector: selector, Matching: matching, Data: data}
}

// "3 1 1", the record almost every DANE deployment publishes, matches the leaf
// — and RFC 7672 §3.1.1 says the leaf's name and dates are not checked, because
// the record is the binding. A check that applied them would report a working
// deployment as refused.
func TestAnEndEntityRecordMatchesTheLeafWhateverItsNameAndDates(t *testing.T) {
	d := current()
	d.leafUntil = now.AddDate(0, 0, -1)
	p := issue(t, "another.example.test", d)

	got := Check([]dnsclient.TLSA{record(3, 1, 1, p.leaf)}, []*x509.Certificate{p.leaf}, exchanger, now)
	if got.Outcome != Matched || got.Usage != UsageDANEEE {
		t.Errorf("got %+v; a DANE-EE record matching the leaf is a match whatever the leaf names or when it expires", got)
	}
}

func TestAnEndEntityRecordForAnotherKeyDoesNotMatch(t *testing.T) {
	presented, other := issue(t, exchanger, current()), issue(t, exchanger, current())

	got := Check([]dnsclient.TLSA{record(3, 1, 1, other.leaf)}, []*x509.Certificate{presented.leaf}, exchanger, now)
	if got.Outcome != Mismatched || got.Usable != 1 || got.Reason == "" {
		t.Errorf("got %+v; the record binds a key the exchanger did not present", got)
	}
}

// DANE-TA matches a presented certificate, and the leaf must chain to it and
// name the exchanger (RFC 7672 §3.1.2, §3.2.3).
func TestATrustAnchorRecordNeedsTheLeafToChainAndNameTheExchanger(t *testing.T) {
	p := issue(t, exchanger, current())
	chain := []*x509.Certificate{p.leaf, p.anchor}
	records := []dnsclient.TLSA{record(2, 0, 1, p.anchor)}

	if got := Check(records, chain, exchanger, now); got.Outcome != Matched || got.Usage != UsageDANETA {
		t.Errorf("got %+v; the leaf chains to the anchor the record names and names the exchanger", got)
	}

	got := Check(records, chain, "mx2.example.test", now)
	if got.Outcome != Mismatched || !strings.Contains(got.Reason, "does not name the exchanger") {
		t.Errorf("got %+v; under DANE-TA the leaf has to name the exchanger", got)
	}
}

// RFC 7672 asks a DANE-TA chain for its path and its name, not for the
// server-authentication usage. A leaf limited to another usage still matches:
// a check demanding one would report a working deployment as refused on a rule
// the RFC does not state. A sabotage demanding it escaped on 2026-09-14,
// because every other leaf here names no usage at all, which Go reads as any.
func TestATrustAnchorChainIsNotHeldToAKeyUsageTheRFCDoesNotAsk(t *testing.T) {
	p := issueFor(t, exchanger, current(), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	got := Check([]dnsclient.TLSA{record(2, 0, 1, p.anchor)}, []*x509.Certificate{p.leaf, p.anchor}, exchanger, now)
	if got.Outcome != Matched {
		t.Errorf("got %+v; the leaf chains to the anchor and names the exchanger", got)
	}
}

// An anchor the exchanger did not send is not found, and the record then
// matches nothing presented.
func TestATrustAnchorThatWasNotPresentedIsNotFound(t *testing.T) {
	p := issue(t, exchanger, current())

	got := Check([]dnsclient.TLSA{record(2, 0, 1, p.anchor)}, []*x509.Certificate{p.leaf}, exchanger, now)
	if got.Outcome != Mismatched {
		t.Errorf("got %+v; the anchor the record names was not among the certificates presented", got)
	}
}

// A DANE-TA record can publish a bare key. Where no presented certificate
// carries it, which certificate it signed is not worked out here, so the answer
// is not given — rather than reported as a mail server refusing mail.
func TestABareAnchorKeyNobodyPresentedIsUndetermined(t *testing.T) {
	p, elsewhere := issue(t, exchanger, current()), issue(t, exchanger, current())

	got := Check([]dnsclient.TLSA{record(2, 1, 0, elsewhere.anchor)}, []*x509.Certificate{p.leaf, p.anchor}, exchanger, now)
	if got.Outcome != Undetermined || got.Reason == "" {
		t.Errorf("got %+v; a bare key the chain does not carry is not established either way", got)
	}
}

// An anchor past its own dates fails Go's verifier, and whether a sender holds a
// DNS-named anchor to them is not settled here.
func TestAnExpiredAnchorIsUndetermined(t *testing.T) {
	d := dates{now.AddDate(-2, 0, 0), now.AddDate(0, 0, -1), now.AddDate(0, -2, 0), now.AddDate(0, 2, 0)}
	p := issue(t, exchanger, d)

	got := Check([]dnsclient.TLSA{record(2, 0, 1, p.anchor)}, []*x509.Certificate{p.leaf, p.anchor}, exchanger, now)
	if got.Outcome != Undetermined {
		t.Errorf("got %+v; an expired anchor is not established as a refusal", got)
	}
}

// A leaf past its dates under a DANE-TA anchor is a failure: only DANE-EE
// waives them.
func TestAnExpiredLeafUnderAnAnchorDoesNotMatch(t *testing.T) {
	d := current()
	d.leafFrom, d.leafUntil = now.AddDate(0, -3, 0), now.AddDate(0, 0, -1)
	p := issue(t, exchanger, d)

	got := Check([]dnsclient.TLSA{record(2, 0, 1, p.anchor)}, []*x509.Certificate{p.leaf, p.anchor}, exchanger, now)
	if got.Outcome != Mismatched {
		t.Errorf("got %+v; under DANE-TA the leaf's dates are checked", got)
	}
}

// Records a sender does not use for SMTP authenticate nothing: the PKIX usages
// (RFC 7672 §3.1.3), undefined selectors and matching types, and digests of the
// wrong length.
func TestRecordsASenderDoesNotUseForSMTPAreNotUsable(t *testing.T) {
	p := issue(t, exchanger, current())
	chain := []*x509.Certificate{p.leaf, p.anchor}

	short := record(3, 1, 1, p.leaf)
	short.Data = short.Data[:20]
	undefinedSelector := record(3, 1, 1, p.leaf)
	undefinedSelector.Selector = 2
	undefinedMatching := record(3, 1, 1, p.leaf)
	undefinedMatching.Matching = 3

	unusable := []dnsclient.TLSA{
		record(0, 0, 1, p.anchor),
		record(1, 1, 1, p.leaf),
		short, undefinedSelector, undefinedMatching,
		{Usage: 3, Selector: 1, Matching: 0},
	}
	got := Check(unusable, chain, exchanger, now)
	if got.Outcome != NoUsableRecords || got.Usable != 0 {
		t.Errorf("got %+v; none of these is a record a sender uses for SMTP", got)
	}
}

func TestEveryMatchingTypeMatches(t *testing.T) {
	p := issue(t, exchanger, current())
	for _, r := range []dnsclient.TLSA{
		record(3, 0, 0, p.leaf), record(3, 1, 0, p.leaf),
		record(3, 0, 1, p.leaf), record(3, 1, 1, p.leaf),
		record(3, 0, 2, p.leaf), record(3, 1, 2, p.leaf),
	} {
		if got := Check([]dnsclient.TLSA{r}, []*x509.Certificate{p.leaf}, exchanger, now); got.Outcome != Matched {
			t.Errorf("%d %d %d: got %+v", r.Usage, r.Selector, r.Matching, got)
		}
	}
}

// A sender accepts the connection if any usable record matches, so a record
// that does not — a key rotated out, say — beside one that does is a match,
// in whichever order they come.
func TestOneMatchingRecordAmongSeveralIsEnough(t *testing.T) {
	p, old := issue(t, exchanger, current()), issue(t, exchanger, current())
	chain := []*x509.Certificate{p.leaf, p.anchor}

	for _, records := range [][]dnsclient.TLSA{
		{record(3, 1, 1, old.leaf), record(2, 0, 1, p.anchor)},
		{record(2, 0, 1, old.anchor), record(3, 1, 1, p.leaf)},
	} {
		if got := Check(records, chain, exchanger, now); got.Outcome != Matched || got.Usable != 2 {
			t.Errorf("got %+v; one of the two records matches", got)
		}
	}
}

func TestWithoutACertificateNothingIsEstablished(t *testing.T) {
	p := issue(t, exchanger, current())
	if got := Check([]dnsclient.TLSA{record(3, 1, 1, p.leaf)}, nil, exchanger, now); got.Outcome != Undetermined {
		t.Errorf("got %+v; with no certificate there is nothing to compare", got)
	}
}
