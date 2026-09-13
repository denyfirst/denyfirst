package rootstores

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// realChain is denyfirst.dev's chain as served on 2026-09-13: the leaf, Let's
// Encrypt's YE2, Root YE, and ISRG Root X2 cross-signed by ISRG Root X1.
func realChain(t *testing.T) []*x509.Certificate {
	t.Helper()
	var chain []*x509.Certificate
	for _, name := range []string{"denyfirst.dev.der", "YE2.der", "RootYE.der", "ISRGRootX2-cross.der"} {
		der, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		chain = append(chain, cert)
	}
	return chain
}

// minted is a test root and a leaf it issued on a chosen day.
type minted struct {
	root, leaf *x509.Certificate
}

func mint(t *testing.T, issued time.Time) minted {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating: %v", err)
	}
	rootTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: issued.AddDate(-1, 0, 0), NotAfter: issued.AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("creating the root: %v", err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf.example.test"},
		DNSNames:  []string{"leaf.example.test"},
		NotBefore: issued, NotAfter: issued.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("creating the leaf: %v", err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	return minted{root: root, leaf: leaf}
}

func entryFor(cert *x509.Certificate, stores map[string]string) Root {
	sum := sha256.Sum256(cert.Raw)
	return Root{
		SHA256: hex.EncodeToString(sum[:]), Name: cert.Subject.CommonName,
		DER: base64.StdEncoding.EncodeToString(cert.Raw), Stores: stores,
	}
}

func parseRoots(t *testing.T, roots ...Root) (*Set, error) {
	t.Helper()
	raw, err := json.Marshal(File{Retrieved: "2026-09-14", Roots: roots})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	return Parse(raw)
}

// A carried root whose bytes do not hash to its recorded fingerprint is refused.
//
// The carried file has no publisher signature. What stops a certificate being
// swapped in it is that every one must match the fingerprint its publisher
// listed, and this is where that holds on every build.
func TestARootThatDoesNotMatchItsFingerprintIsRefused(t *testing.T) {
	m := mint(t, time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC))
	r := entryFor(m.root, map[string]string{"mozilla": "trusted"})
	r.SHA256 = hex.EncodeToString(make([]byte, 32))

	if _, err := parseRoots(t, r); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a root with the wrong fingerprint gave %v, want ErrCorrupt", err)
	}
}

// A store this package does not know, or a status it cannot read, is refused.
func TestAnUnknownStoreOrStatusIsRefused(t *testing.T) {
	m := mint(t, time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC))
	for name, stores := range map[string]map[string]string{
		"unknown store":   {"opera": "trusted"},
		"unknown status":  {"mozilla": "maybe"},
		"unreadable date": {"mozilla": "distrust-after:soon"},
	} {
		if _, err := parseRoots(t, entryFor(m.root, stores)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Each store answers for itself, in each of the four ways it can.
func TestEachStoreAnswersForItself(t *testing.T) {
	issued := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	m := mint(t, issued)

	set, err := parseRoots(t, entryFor(m.root, map[string]string{
		"mozilla":   "trusted",
		"chrome":    "conditional",
		"microsoft": "distrust-after:2026-01-09",
	}))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}

	got := map[Store]Judgement{}
	for _, j := range set.Judge([]*x509.Certificate{m.leaf}, issued.AddDate(0, 3, 0)) {
		got[j.Store] = j
	}

	want := map[Store]Verdict{Mozilla: Trusted, Chrome: Conditional, Microsoft: Distrusted, Apple: NotTrusted}
	for store, verdict := range want {
		if got[store].Verdict != verdict {
			t.Errorf("%s says %s, want %s", store.Name(), got[store].Verdict, verdict)
		}
	}
	if got[Mozilla].Root != "Test Root" {
		t.Errorf("the root reached is named %q", got[Mozilla].Root)
	}
	if got[Microsoft].After != "2026-01-09" {
		t.Errorf("the distrust date is %q", got[Microsoft].After)
	}
	if got[Apple].Root != "" {
		t.Errorf("a store that trusts nothing here names a root: %q", got[Apple].Root)
	}
}

// A distrust date is the last day a certificate is trusted, from both sides.
func TestTheDistrustDateIsTheLastDayTrusted(t *testing.T) {
	issued := time.Date(2026, 1, 10, 9, 30, 0, 0, time.UTC)
	m := mint(t, issued)

	for after, want := range map[string]Verdict{
		"2026-01-09": Distrusted, // issued the day after
		"2026-01-10": Trusted,    // issued on the day itself
		"2026-01-11": Trusted,    // issued before
	} {
		set, err := parseRoots(t, entryFor(m.root, map[string]string{"mozilla": "distrust-after:" + after}))
		if err != nil {
			t.Fatalf("parsing: %v", err)
		}
		if got := set.Judge([]*x509.Certificate{m.leaf}, issued.AddDate(0, 1, 0))[0]; got.Verdict != want {
			t.Errorf("distrust after %s, issued %s: %s, want %s", after, issued.Format(time.DateOnly), got.Verdict, want)
		}
	}
}

// The stores this build carries read, and all four trust a real, ordinary chain.
//
// denyfirst.dev's chain reaches ISRG Root X1, which every one of the four
// includes. A carried file that failed this would be missing Let's Encrypt from
// a store, which is news worth reading rather than a test to loosen.
func TestTheCarriedStoresTrustARealChain(t *testing.T) {
	set, err := Carried()
	if err != nil {
		t.Fatalf("the carried stores do not read: %v", err)
	}
	if set.Retrieved == "" {
		t.Fatal("the carried stores name no retrieval date, so a report cannot say how old they are")
	}

	chain := realChain(t)
	leaf := chain[0]
	at := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	for _, j := range set.Judge(chain, at) {
		if j.Verdict != Trusted {
			t.Errorf("%s says %s for denyfirst.dev's chain, want trusted", j.Store.Name(), j.Verdict)
		}
	}
}

// Two files saying the same of the same roots summarise the same, whenever they
// were fetched.
func TestTheSummaryIgnoresWhenAFileWasFetched(t *testing.T) {
	m := mint(t, time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC))
	root := entryFor(m.root, map[string]string{"mozilla": "trusted"})

	a := Summary(File{Retrieved: "2026-01-01", Roots: []Root{root}})
	b := Summary(File{Retrieved: "2026-09-14", Roots: []Root{root}})
	if len(a) != 1 || len(b) != 1 || a[0] != b[0] {
		t.Errorf("summaries differ by retrieval date: %v %v", a, b)
	}
}

// A file naming more roots than a file should is refused, and one naming exactly
// that many is read.
//
// The file is carried and checked, so the bound is not reachable by a stranger.
// A sabotage removing it escaped every test on 2026-09-14, so it is measured from
// both sides here: the same root repeated to the bound reads, and once more does
// not.
func TestAFileNamingTooManyRootsIsRefused(t *testing.T) {
	m := mint(t, time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC))
	root := entryFor(m.root, map[string]string{"mozilla": "trusted"})

	many := func(n int) []Root {
		out := make([]Root, n)
		for i := range out {
			out[i] = root
		}
		return out
	}

	if _, err := parseRoots(t, many(maxRoots)...); err != nil {
		t.Fatalf("a file naming exactly %d roots gave %v; the bound refuses more than it should", maxRoots, err)
	}
	if _, err := parseRoots(t, many(maxRoots+1)...); err == nil {
		t.Errorf("a file naming %d roots was read; the bound is %d", maxRoots+1, maxRoots)
	}
}

// The summary names the store, so a root moving from one store to another is a
// change.
//
// Checked here and not only through refresh/: a sabotage dropping the store from
// the line escaped this package's tests on 2026-09-14, because the only test
// that would notice lived in another one.
func TestTheSummaryNamesTheStore(t *testing.T) {
	m := mint(t, time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC))
	lines := Summary(File{Roots: []Root{entryFor(m.root, map[string]string{"mozilla": "trusted", "chrome": "trusted"})}})

	if len(lines) != 2 || lines[0] == lines[1] {
		t.Fatalf("one root trusted by two stores summarises as %v; the stores are indistinguishable", lines)
	}
	joined := strings.Join(lines, "\n")
	for _, store := range []string{" mozilla ", " chrome "} {
		if !strings.Contains(joined, store) {
			t.Errorf("the summary does not name%s:\n%s", store, joined)
		}
	}
}

// crossSigned is one intermediate key certified by two roots, and a leaf it
// issued: two paths from one leaf to two different roots.
type crossSigned struct {
	leaf, viaA, viaB, rootA, rootB *x509.Certificate
}

func crossSign(t *testing.T) crossSigned {
	t.Helper()
	now := time.Now()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating: %v", err)
		}
		return k
	}
	create := func(tpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
		if err != nil {
			t.Fatalf("creating %s: %v", tpl.Subject.CommonName, err)
		}
		cert, _ := x509.ParseCertificate(der)
		return cert
	}
	ca := func(serial int64, name string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
	}

	keyA, keyB, keyI, keyL := key(), key(), key(), key()
	rootA := create(ca(1, "Root A"), ca(1, "Root A"), &keyA.PublicKey, keyA)
	rootB := create(ca(2, "Root B"), ca(2, "Root B"), &keyB.PublicKey, keyB)
	viaA := create(ca(3, "Shared Intermediate"), rootA, &keyI.PublicKey, keyA)
	viaB := create(ca(4, "Shared Intermediate"), rootB, &keyI.PublicKey, keyB)

	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "leaf.example.test"},
		DNSNames:  []string{"leaf.example.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leaf := create(leafTpl, viaA, &keyL.PublicKey, keyI)
	return crossSigned{leaf: leaf, viaA: viaA, viaB: viaB, rootA: rootA, rootB: rootB}
}

// Where a chain reaches two roots, the better answer decides.
//
// A client accepts a chain if any path works. Asked both ways round — the
// trusted root first, then the conditional one — so the answer cannot depend on
// which path the verifier happens to return first; a sabotage taking the first
// path escaped every test built on one real chain, whose paths all agree.
func TestTheBestPathToARootDecides(t *testing.T) {
	c := crossSign(t)
	chain := []*x509.Certificate{c.leaf, c.viaA, c.viaB}

	both := x509.NewCertPool()
	both.AddCert(c.rootA)
	both.AddCert(c.rootB)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(c.viaA)
	intermediates.AddCert(c.viaB)
	paths, err := c.leaf.Verify(x509.VerifyOptions{Roots: both, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil || len(paths) < 2 {
		t.Fatalf("the fixture gives %d paths (%v); it needs two for this test to assert anything", len(paths), err)
	}

	for name, statuses := range map[string][2]string{
		"A conditional, B trusted": {"conditional", "trusted"},
		"A trusted, B conditional": {"trusted", "conditional"},
	} {
		set, err := parseRoots(t,
			entryFor(c.rootA, map[string]string{"chrome": statuses[0]}),
			entryFor(c.rootB, map[string]string{"chrome": statuses[1]}))
		if err != nil {
			t.Fatalf("%s: parsing: %v", name, err)
		}
		for _, j := range set.Judge(chain, time.Now()) {
			if j.Store == Chrome && j.Verdict != Trusted {
				t.Errorf("%s: Chrome says %s; a trusted path exists and a client takes it", name, j.Verdict)
			}
		}
	}
}
