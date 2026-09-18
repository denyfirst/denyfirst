package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/porch/internal/rootstores"
)

// Chrome's anchors are read with whether they carry constraints, and nothing
// outside a trust_anchors block is taken for one.
func TestChromeAnchorsAreReadWithTheirConstraints(t *testing.T) {
	text := []byte(`# a comment
trust_anchors {
  sha256_hex: "AAAA"
  crs_root_id: 1
}

trust_anchors {
  sha256_hex: "bbbb"
  constraints: {
    sct_not_after_sec: 1
    min_version: "153.0.0.0"
  }
}

additional_certs {
  sha256_hex: "cccc"
  tls_trust_anchor: true
}
`)
	got := trustAnchors(text)
	if len(got) != 2 {
		t.Fatalf("read %v; want the two trust anchors and not the additional certificate", got)
	}
	if constrained, ok := got["aaaa"]; !ok || constrained {
		t.Errorf("an unconstrained anchor read as %v (present %v)", constrained, ok)
	}
	if constrained, ok := got["bbbb"]; !ok || !constrained {
		t.Errorf("a constrained anchor read as %v (present %v)", constrained, ok)
	}
}

func pemRow(t *testing.T) (field, fingerprint string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Row Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating: %v", err)
	}
	sum := sha256.Sum256(der)
	return "'" + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + "'",
		strings.ToUpper(hex.EncodeToString(sum[:]))
}

// A certificate that does not hash to the fingerprint its row lists is refused.
//
// These sources carry no signature. A certificate matching the fingerprint its
// own publisher lists beside it is the one check they make possible, and a source
// failing it is refused whole.
func TestACertificateNotMatchingItsListedFingerprintIsRefused(t *testing.T) {
	field, fingerprint := pemRow(t)

	if _, sum, err := pemMatching([]string{fingerprint, field}, 0); err != nil || sum != strings.ToLower(fingerprint) {
		t.Errorf("a matching row gave %q, %v", sum, err)
	}
	if _, _, err := pemMatching([]string{strings.Repeat("0", 64), field}, 0); err == nil {
		t.Error("a certificate listed under another fingerprint was accepted")
	}
}

// -check exits 1 when a store says something new of a root, and 0 when only the
// retrieval date differs.
func TestCheckExitsOneWhenAStoreChanged(t *testing.T) {
	root := rootstores.Root{SHA256: "aa", Stores: map[string]string{"mozilla": "trusted"}}
	current := rootstores.File{Retrieved: "2026-09-01", Roots: []rootstores.Root{root}}

	same := rootstores.File{Retrieved: "2026-09-14", Roots: []rootstores.Root{root}}
	if code, lines := checkOutcome(current, same); code != 0 {
		t.Errorf("a file differing only in its date exited %d: %v", code, lines)
	}

	changed := rootstores.File{Retrieved: "2026-09-14", Roots: []rootstores.Root{
		{SHA256: "aa", Stores: map[string]string{"mozilla": "trusted", "chrome": "conditional"}},
	}}
	code, lines := checkOutcome(current, changed)
	if code != 1 {
		t.Errorf("a store adding a root exited %d", code)
	}
	if text := strings.Join(lines, "\n"); !strings.Contains(text, "+ aa chrome conditional") {
		t.Errorf("the change is not named:\n%s", text)
	}
}

// A root that matches its fingerprint and that Go cannot parse is left out, not
// taken as a source disagreeing with itself.
//
// Microsoft's store includes EC-ACC, whose serial number is negative. Go refuses
// to parse such a certificate, so its verifier could never use the root — and
// refusing all of Microsoft's store for it would have carried none of the other
// five hundred. The fingerprint is still checked: this is the case where it
// matches.
func TestAnUnparseableRootMatchingItsFingerprintIsLeftOut(t *testing.T) {
	field, _ := pemRow(t)
	block, _ := pem.Decode([]byte(strings.Trim(field, "'")))
	der := append([]byte(nil), block.Bytes...)

	// The serial is the INTEGER 1; make it -1.
	at := bytes.Index(der, []byte{0x02, 0x01, 0x01})
	if at < 0 {
		t.Fatal("the serial number was not found in the certificate")
	}
	der[at+2] = 0xff
	if _, err := x509.ParseCertificate(der); err == nil {
		t.Fatal("Go parsed a certificate with a negative serial, so this test asserts nothing")
	}

	sum := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(sum[:])
	unparseable := "'" + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + "'"

	_, got, err := pemMatching([]string{fingerprint, unparseable}, 0)
	if !errors.Is(err, errUnparseable) {
		t.Errorf("an unparseable root matching its fingerprint gave %v, want it left out", err)
	}
	if got != fingerprint {
		t.Errorf("the left-out root is named %q, want its fingerprint", got)
	}

	// And the same certificate under another fingerprint is still a source
	// disagreeing with itself.
	if _, _, err := pemMatching([]string{strings.Repeat("0", 64), unparseable}, 0); !errors.Is(err, errSource) {
		t.Errorf("an unparseable certificate under the wrong fingerprint gave %v, want the source refused", err)
	}
}

// namedRoot is a self-signed root with a name, as a CCADB row would carry it.
func namedRoot(t *testing.T, name string, serial int64) (der []byte, field, fingerprint string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating %s: %v", name, err)
	}
	sum := sha256.Sum256(der)
	return der, "'" + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + "'",
		strings.ToUpper(hex.EncodeToString(sum[:]))
}

func csvOf(t *testing.T, rows [][]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.WriteAll(rows); err != nil {
		t.Fatalf("writing csv: %v", err)
	}
	return buf.Bytes()
}

// The carried file holds what each store trusts for TLS, and nothing else.
//
// The whole of the refresh, from five sources to one file, on sources small
// enough to read: a Mozilla root trusted only for email is not carried as trusted
// for websites; a Microsoft root enabled only for email is left out; a Microsoft
// NotBefore root and a constrained Chrome anchor are conditional; Mozilla's
// distrust date travels in the date format the file uses; and an Apple root
// resolves to a certificate another source published. A sabotage reading every
// Mozilla root as trusted for websites escaped every test on 2026-09-14, because
// nothing drove this function before.
func TestBuildCarriesWhatEachStoreTrustsForTLS(t *testing.T) {
	derA, pemA, fpA := namedRoot(t, "Root A", 1)
	derB, pemB, fpB := namedRoot(t, "Root B", 2)
	_, pemC, fpC := namedRoot(t, "Root C", 3)

	mozilla := csvOf(t, [][]string{
		{"Common Name or Certificate Name", "SHA-256 Fingerprint", "Trust Bits", "Distrust for TLS After Date", "PEM Info"},
		{"Root A", fpA, "Websites;Email", "", pemA},
		{"Root B", fpB, "Email", "", pemB},
		{"Root C", fpC, "Websites", "2026.04.15", pemC},
	})
	microsoft := csvOf(t, [][]string{
		{"Microsoft Status", "CA Common Name or Certificate Name", "SHA-256 Fingerprint", "Microsoft EKUs", "PEM Info"},
		{"Included", "Root A", fpA, "Server Authentication;Secure Email", pemA},
		{"NotBefore", "Root B", fpB, "Server Authentication", pemB},
		{"Included", "Root C", fpC, "Secure Email", pemC},
	})
	certs := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derA})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derB}))
	proto := "trust_anchors {\n  sha256_hex: \"" + strings.ToLower(fpA) + "\"\n}\n\n" +
		"trust_anchors {\n  sha256_hex: \"" + strings.ToLower(fpB) + "\"\n  constraints: {\n    sct_not_after_sec: 1\n  }\n}\n"
	apple := csvOf(t, [][]string{
		{"Apple Status", "SHA-256 Fingerprint", "Certificate Name"},
		{"Included", fpA, "Root A"},
		{"Included", strings.Repeat("AB", 32), "A Verified Mark root nobody publishes"},
		{"Not Included", fpC, "Root C"},
	})

	file, skipped, err := build(map[string][]byte{
		"mozilla":      mozilla,
		"microsoft":    microsoft,
		"chrome-certs": []byte(base64.StdEncoding.EncodeToString([]byte(certs))),
		"chrome-proto": []byte(base64.StdEncoding.EncodeToString([]byte(proto))),
		"apple":        apple,
	}, time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("skipped %v; every certificate here parses", skipped)
	}
	if file.Retrieved != "2026-09-13" {
		t.Errorf("retrieved %q", file.Retrieved)
	}

	stores := map[string]map[string]string{}
	for _, r := range file.Roots {
		stores[r.Name] = r.Stores
	}
	want := map[string]map[string]string{
		"Root A": {"mozilla": "trusted", "microsoft": "trusted", "chrome": "trusted", "apple": "trusted"},
		"Root B": {"microsoft": "conditional", "chrome": "conditional"},
		"Root C": {"mozilla": "distrust-after:2026-04-15"},
	}
	for name, wantStores := range want {
		got := stores[name]
		if len(got) != len(wantStores) {
			t.Errorf("%s is carried as %v, want %v", name, got, wantStores)
			continue
		}
		for store, status := range wantStores {
			if got[store] != status {
				t.Errorf("%s in %s is %q, want %q (carried as %v)", name, store, got[store], status, got)
			}
		}
	}
}
