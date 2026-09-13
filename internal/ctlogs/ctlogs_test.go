package ctlogs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"
)

// fixture is denyfirst.dev's certificate and the authority that issued it, as
// served on 2026-09-13. Public certificates, carried so the check can be run
// against receipts real logs signed rather than only against receipts this
// file signed for itself.
func fixture(t *testing.T) (leaf, issuer *x509.Certificate) {
	t.Helper()
	read := func(name string) *x509.Certificate {
		der, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		return cert
	}
	return read("denyfirst.dev.der"), read("YE2.der")
}

func carriedList(t *testing.T) *List {
	t.Helper()
	list, err := Embedded()
	if err != nil {
		t.Fatalf("the carried list does not verify: %v", err)
	}
	return list
}

// The list this build carries is Google's, and says so with Google's signature.
//
// Run on every build, so a list edited by hand in this repository — a log added,
// a key swapped — fails here before it can make a receipt look genuine.
func TestTheCarriedListIsGooglesSigned(t *testing.T) {
	list := carriedList(t)
	if list.Len() == 0 {
		t.Error("the carried list names no logs")
	}
	if list.Version == "" || list.Timestamp.IsZero() {
		t.Errorf("version %q, timestamp %v; a report cannot say how old the list is", list.Version, list.Timestamp)
	}

	// And each log's state is read rather than assumed. The weekly comparison
	// is of identifiers and states, so a reader that called every log usable
	// would never notice a log being retired — and a sabotage doing exactly
	// that escaped on 2026-09-14. Google's list has always carried retired
	// logs beside usable ones.
	states := map[string]bool{}
	for _, line := range list.Summary() {
		states[line[strings.LastIndex(line, " ")+1:]] = true
	}
	if !states["usable"] || len(states) < 2 {
		t.Errorf("the carried list reads as states %v; a list of live logs has more than one", states)
	}
}

// One byte changed, in the list or in the signature, and nothing is believed.
func TestAListGoogleDidNotSignIsRefused(t *testing.T) {
	list := append([]byte(nil), listJSON...)
	list[len(list)/2] ^= 1
	if _, err := Parse(list, listSignature); !errors.Is(err, ErrSignature) {
		t.Errorf("a list with one byte changed gave %v, want the signature refusal", err)
	}

	signature := append([]byte(nil), listSignature...)
	signature[0] ^= 1
	if _, err := Parse(listJSON, signature); !errors.Is(err, ErrSignature) {
		t.Errorf("a changed signature gave %v, want the signature refusal", err)
	}
}

// A log whose identifier is not the hash of its key is refused.
//
// RFC 6962 defines the identifier as that hash. A list pairing an identifier with
// another key would let a receipt be checked against a key its log never held.
func TestALogWhoseIdentifierIsNotItsKeyIsRefused(t *testing.T) {
	var someKey string
	for _, log := range carriedList(t).logs {
		der, err := x509.MarshalPKIXPublicKey(log.Key)
		if err != nil {
			t.Fatalf("marshalling a key: %v", err)
		}
		someKey = base64.StdEncoding.EncodeToString(der)
		break
	}

	forged := `{"version":"1","log_list_timestamp":"2026-01-01T00:00:00Z","operators":[{"name":"x","logs":[` +
		`{"description":"forged","log_id":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) +
		`","key":"` + someKey + `","state":{"usable":{}}}]}]}`

	if _, err := read([]byte(forged)); err == nil {
		t.Error("a log whose identifier is not the hash of its key was accepted")
	}
}

// The receipts a real log signed for a real certificate verify.
//
// The case the package exists for, checked against data it did not produce:
// denyfirst.dev's certificate carries two receipts, one from a classic log and
// one from a tiled one, and both are checked against keys from Google's list.
func TestTheReceiptsInARealCertificateVerify(t *testing.T) {
	leaf, issuer := fixture(t)
	receipts := CheckEmbedded(carriedList(t), leaf, issuer)

	if len(receipts) != 2 {
		t.Fatalf("%d receipts, want the two the certificate carries: %+v", len(receipts), receipts)
	}
	var logs []string
	for _, r := range receipts {
		if r.Status != Verified {
			// A log dropped from a refreshed list would land here as
			// UnknownLog. Retired logs stay in Google's list, so that would
			// be news worth reading rather than a test to loosen.
			t.Errorf("the receipt from %s (%s) is %s, want verified", r.Log, r.LogID, r.Status)
		}
		logs = append(logs, r.Log)
	}
	joined := strings.Join(logs, "; ")
	for _, want := range []string{"Sphinx2026h2", "Gouda2026h2"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the receipts name %q, and not %s", joined, want)
		}
	}
}

// Checked against the wrong authority, genuine receipts do not verify.
//
// The other direction of the test above, and the one that proves the check
// checks: a verifier that returned true for anything would pass that one.
func TestReceiptsCheckedAgainstTheWrongIssuerDoNotVerify(t *testing.T) {
	leaf, _ := fixture(t)
	for _, r := range CheckEmbedded(carriedList(t), leaf, leaf) {
		if r.Status != BadSignature {
			t.Errorf("a receipt checked against the certificate's own key as issuer is %s, want bad-signature", r.Status)
		}
	}
}

// Without the issuer, nothing is verified and nothing is called false.
func TestWithoutTheIssuerNothingIsVerified(t *testing.T) {
	leaf, _ := fixture(t)
	for _, r := range CheckEmbedded(carriedList(t), leaf, nil) {
		if r.Status != Unreadable {
			t.Errorf("a receipt with no issuer to check against is %s, want unreadable", r.Status)
		}
	}
}

// A log the list does not name is unknown, not false.
//
// A log newer than the carried list, or one another browser trusts, looks
// exactly like this — and "bad signature" would accuse a certificate of carrying
// a forged receipt on the strength of an old list.
func TestAReceiptFromALogNotInTheListIsUnknownRatherThanFalse(t *testing.T) {
	leaf, issuer := fixture(t)
	for _, r := range CheckEmbedded(&List{}, leaf, issuer) {
		if r.Status != UnknownLog {
			t.Errorf("a receipt from a log the list does not name is %s, want unknown-log", r.Status)
		}
	}
}

// What a log signs for an embedded receipt has the receipts taken out.
func TestThePrecertificateHasNoReceiptList(t *testing.T) {
	leaf, _ := fixture(t)
	oid, err := asn1.Marshal(sctListOID)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if !bytes.Contains(leaf.RawTBSCertificate, oid) {
		t.Fatal("the fixture carries no receipt list, so this test asserts nothing")
	}

	tbs, err := precertificateTBS(leaf.RawTBSCertificate)
	if err != nil {
		t.Fatalf("rebuilding: %v", err)
	}
	if bytes.Contains(tbs, oid) {
		t.Error("the rebuilt certificate still carries the receipt list")
	}
	if len(tbs) >= len(leaf.RawTBSCertificate) {
		t.Errorf("the rebuilt certificate is %d bytes, the original %d; nothing was removed", len(tbs), len(leaf.RawTBSCertificate))
	}
}

// signedHandshakeReceipt is a receipt for the certificate itself, signed by a key
// this test holds, and a list naming that key.
func signedHandshakeReceipt(t *testing.T, cert *x509.Certificate) ([]byte, *List) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	id := sha256.Sum256(spki)
	timestamp := []byte{0, 0, 1, 0x92, 0, 0, 0, 0}

	signed := []byte{0, 0}
	signed = append(signed, timestamp...)
	signed = binary.BigEndian.AppendUint16(signed, entryX509)
	signed = appendOpaque24(signed, cert.Raw)
	signed = binary.BigEndian.AppendUint16(signed, 0)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	sct := []byte{0}
	sct = append(sct, id[:]...)
	sct = append(sct, timestamp...)
	sct = binary.BigEndian.AppendUint16(sct, 0)
	sct = append(sct, hashSHA256, sigECDSA)
	sct = binary.BigEndian.AppendUint16(sct, uint16(len(signature)))
	sct = append(sct, signature...)

	return sct, &List{logs: map[[32]byte]Log{id: {ID: id, Key: &key.PublicKey, Description: "test log", State: "usable"}}}
}

// A handshake receipt signs the certificate as sent, and only that certificate.
func TestAHandshakeReceiptSignsTheCertificateItself(t *testing.T) {
	leaf, issuer := fixture(t)
	sct, list := signedHandshakeReceipt(t, leaf)

	if got := CheckHandshake(list, [][]byte{sct}, leaf); len(got) != 1 || got[0].Status != Verified {
		t.Errorf("a receipt signed over the certificate is %+v, want verified", got)
	}
	if got := CheckHandshake(list, [][]byte{sct}, issuer); len(got) != 1 || got[0].Status != BadSignature {
		t.Errorf("the same receipt checked against another certificate is %+v, want bad-signature", got)
	}
}

// A malformed receipt is unreadable, and nothing in it is believed.
func TestAMalformedReceiptIsUnreadable(t *testing.T) {
	leaf, _ := fixture(t)
	good, list := signedHandshakeReceipt(t, leaf)

	for name, bad := range map[string][]byte{
		"empty":                 {},
		"short":                 good[:minSCT-1],
		"version 1":             append([]byte{1}, good[1:]...),
		"extensions overflow":   append(append(append([]byte(nil), good[:41]...), 0xFF, 0xFF), good[43:]...),
		"signature length lies": append(append([]byte(nil), good...), 0),
	} {
		if got := CheckHandshake(list, [][]byte{bad}, leaf); len(got) != 1 || got[0].Status != Unreadable {
			t.Errorf("%s: %+v, want unreadable", name, got)
		}
	}
}

// A change of state shows as a change, and an unchanged list shows nothing.
func TestDifferenceSeesWhatChanged(t *testing.T) {
	var a, b [32]byte
	a[0], b[0] = 1, 2
	current := &List{logs: map[[32]byte]Log{a: {State: "usable"}, b: {State: "usable"}}}

	if added, removed := Difference(current, current); len(added) != 0 || len(removed) != 0 {
		t.Errorf("a list compared with itself changed: +%v -%v", added, removed)
	}

	next := &List{logs: map[[32]byte]Log{a: {State: "retired"}}}
	added, removed := Difference(current, next)
	if len(added) != 1 || !strings.HasSuffix(added[0], " retired") {
		t.Errorf("added = %v, want the log that became retired", added)
	}
	if len(removed) != 2 {
		t.Errorf("removed = %v, want the old state of one log and the other log", removed)
	}
}
