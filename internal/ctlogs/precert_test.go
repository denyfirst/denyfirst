package ctlogs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// The poison extension is removed with the receipt list.
//
// A precertificate carries it and the final certificate does not, so the log
// signed a TBSCertificate without it. No certificate a server presents normally
// carries it, which is why a sabotage leaving it in escaped every test built on
// denyfirst.dev's certificate on 2026-09-14. This certificate carries both.
func TestThePoisonExtensionIsRemovedToo(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating: %v", err)
	}
	poison := pkix.Extension{Id: poisonOID, Critical: true, Value: []byte{0x05, 0x00}}
	receipts := pkix.Extension{Id: sctListOID, Value: []byte{0x04, 0x00}}

	tpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "precert.example.test"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{poison, receipts},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}

	poisonDER, _ := asn1.Marshal(poisonOID)
	receiptsDER, _ := asn1.Marshal(sctListOID)
	if !bytes.Contains(cert.RawTBSCertificate, poisonDER) {
		t.Fatal("the certificate carries no poison extension, so this test asserts nothing")
	}

	tbs, err := precertificateTBS(cert.RawTBSCertificate)
	if err != nil {
		t.Fatalf("rebuilding: %v", err)
	}
	if bytes.Contains(tbs, poisonDER) {
		t.Error("the rebuilt TBSCertificate still carries the poison extension")
	}
	if bytes.Contains(tbs, receiptsDER) {
		t.Error("the rebuilt TBSCertificate still carries the receipt list")
	}
}

// A receipt naming a hash other than SHA-256 is unsupported, even if its
// signature would verify.
//
// RFC 6962 allows SHA-256 alone. A checker that ignored the byte naming the hash
// would call a receipt verified that says it was made some other way — and the
// helper below signs with SHA-256 whatever the byte says, which is exactly the
// case that would slip through.
func TestAReceiptNamingAnotherHashIsUnsupported(t *testing.T) {
	leaf, _ := fixture(t)
	sct, list := signedHandshakeReceipt(t, leaf)

	// Version, log id, timestamp and a zero extension length come first.
	hashAt := 1 + logIDLen + 8 + 2
	if sct[hashAt] != hashSHA256 {
		t.Fatalf("byte %d is %d, not the hash algorithm; the layout assumption is wrong", hashAt, sct[hashAt])
	}
	sha1Named := append([]byte(nil), sct...)
	sha1Named[hashAt] = 2

	if got := CheckHandshake(list, [][]byte{sha1Named}, leaf); len(got) != 1 || got[0].Status != Unsupported {
		t.Errorf("a receipt naming SHA-1 is %+v, want unsupported", got)
	}
}
